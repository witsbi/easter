//! The ratatui application: tabs, lists, lineage tree, detail panes.

use crate::db::{
    Db, EvidenceRow, ExceptionRow, GrantRow, ReceiptRow, RevocationRow, StateRow, TransitionRow,
};
use crate::mcp::{self, McpConfig};
use crate::model::{
    build_lineage, flatten_tree, grant_status, pretty_json, short_id, summarize_evidence,
    summarize_state, summarize_transition, GrantStatus, LineageNode, TreeRow,
};
use crate::snapshot::refresh_snapshot;
use anyhow::Result;
use serde_json::{json, Value};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Frame,
};
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

const TABS: [&str; 6] = [
    "Lineage",
    "States",
    "Transitions",
    "Receipts",
    "Evidence",
    "Grants",
];

// ---------------------------------------------------------------------------
// Row item (one display row in a list pane)
// ---------------------------------------------------------------------------

struct RowItem {
    id: String,
    title: String,
    subtitle: String,
    haystack: String,
}

// ---------------------------------------------------------------------------
// Write configuration + forms
//
// Writes never touch SQLite directly: the form collects arguments, one
// MCP server is spawned for the submit, and it is killed before the
// call returns (see crate::mcp). Afterwards the snapshot is refreshed
// from the live DB and the TUI reloads from the snapshot.
// ---------------------------------------------------------------------------

/// How the console reaches the live kernel DB for writes.
pub struct AppConfig {
    /// Snapshot DB the TUI browses (read-only). Also `--db` / `EASTER_DB`.
    pub db_path: String,
    /// Live kernel DB for MCP writes. `None` disables the write keys.
    pub live_db: Option<String>,
    /// Path to `mcp_server.py`.
    pub mcp_server_py: String,
    /// Python interpreter for the MCP server.
    pub python: String,
}

#[derive(Clone, Copy, PartialEq)]
enum FormKind {
    RecordEvidence,
    RecordDecision,
    ProposeTransition,
}

impl FormKind {
    fn title(self) -> &'static str {
        match self {
            FormKind::RecordEvidence => "Record Evidence",
            FormKind::RecordDecision => "Record Human Decision",
            FormKind::ProposeTransition => "Propose Transition",
        }
    }
}

enum FieldKind {
    /// Plain text; `required` rejects blank.
    Text { required: bool },
    /// Must parse as a JSON object when non-blank; `required` rejects
    /// blank. Note: `{}` is valid -- blank means "absent", not "empty".
    Json { required: bool },
}

struct FormField {
    label: &'static str,
    value: String,
    kind: FieldKind,
}

struct WriteForm {
    kind: FormKind,
    fields: Vec<FormField>,
    focus: usize,
    error: Option<String>,
}

impl WriteForm {
    fn new(kind: FormKind, identity: &str, grant: &str, from_state: Option<&str>) -> Self {
        let id = FormField {
            label: "requester_identity_id",
            value: identity.to_string(),
            kind: FieldKind::Text { required: true },
        };
        let gr = FormField {
            label: "authority_grant_id",
            value: grant.to_string(),
            kind: FieldKind::Text { required: true },
        };
        let fields = match kind {
            FormKind::RecordEvidence => vec![
                id,
                gr,
                FormField {
                    label: "payload (JSON object)",
                    value: String::new(),
                    kind: FieldKind::Json { required: true },
                },
            ],
            FormKind::RecordDecision => vec![
                id,
                gr,
                FormField {
                    label: "subject",
                    value: String::new(),
                    kind: FieldKind::Text { required: true },
                },
                FormField {
                    label: "decision",
                    value: String::new(),
                    kind: FieldKind::Text { required: true },
                },
                FormField {
                    label: "rationale (optional)",
                    value: String::new(),
                    kind: FieldKind::Text { required: false },
                },
            ],
            FormKind::ProposeTransition => vec![
                id,
                gr,
                FormField {
                    label: "from_state_id",
                    value: from_state.unwrap_or("").to_string(),
                    kind: FieldKind::Text { required: true },
                },
                FormField {
                    label: "new_state_payload (JSON object)",
                    value: String::new(),
                    kind: FieldKind::Json { required: true },
                },
                FormField {
                    label: "transition_payload (JSON object, optional)",
                    value: String::new(),
                    kind: FieldKind::Json { required: false },
                },
                FormField {
                    label: "evidence_ids (comma-separated, optional)",
                    value: String::new(),
                    kind: FieldKind::Text { required: false },
                },
            ],
        };
        Self {
            kind,
            fields,
            focus: 0,
            error: None,
        }
    }

    fn field(&self, label: &str) -> anyhow::Result<&FormField> {
        self.fields
            .iter()
            .find(|f| f.label == label)
            .ok_or_else(|| anyhow::anyhow!("unknown form field: {label}"))
    }

    fn text(&self, label: &str) -> &str {
        self.field(label).map(|f| f.value.trim()).unwrap_or("")
    }

    /// Required text field: blank is an error.
    fn req_text(&self, label: &str) -> anyhow::Result<&str> {
        let f = self.field(label)?;
        match f.kind {
            FieldKind::Text { required: true } if f.value.trim().is_empty() => {
                anyhow::bail!("{label} is required -- nothing was sent to MCP")
            }
            FieldKind::Text { .. } => Ok(f.value.trim()),
            _ => anyhow::bail!("{label} is not a text field"),
        }
    }

    /// Returns `None` for blank+optional, `Some(obj)` otherwise.
    /// A present-but-empty `{}` is valid -- only *missing or malformed*
    /// input is an error.
    fn json_obj(&self, label: &str) -> anyhow::Result<Option<Value>> {
        let f = self.field(label)?;
        let required = match f.kind {
            FieldKind::Json { required } => required,
            _ => anyhow::bail!("{label} is not a JSON field"),
        };
        let raw = f.value.trim();
        if raw.is_empty() {
            if required {
                anyhow::bail!("{label} is required -- nothing was sent to MCP");
            }
            return Ok(None);
        }
        let v: Value = serde_json::from_str(raw)
            .map_err(|e| anyhow::anyhow!("{label} is not valid JSON: {e}"))?;
        if !v.is_object() {
            anyhow::bail!("{label} must be a JSON object");
        }
        Ok(Some(v))
    }

    /// Validate the form and build the `(tool_name, arguments)` pair.
    /// Matches the Python console's `/evidence/record`,
    /// `/evidence/decision`, and `/transition/propose` conventions.
    fn validated_args(&self) -> anyhow::Result<(String, Value)> {
        let requester = self.req_text("requester_identity_id")?;
        let grant = self.req_text("authority_grant_id")?;
        match self.kind {
            FormKind::RecordEvidence => {
                let payload = self.json_obj("payload (JSON object)")?.expect("required");
                Ok((
                    "record_evidence".to_string(),
                    json!({
                        "requester_identity_id": requester,
                        "authority_grant_id": grant,
                        "payload": payload,
                    }),
                ))
            }
            FormKind::RecordDecision => {
                let subject = self.req_text("subject")?;
                let decision = self.req_text("decision")?;
                let mut payload = json!({
                    "kind": "human_decision",
                    "subject": subject,
                    "decision": decision,
                });
                let rationale = self.text("rationale (optional)");
                if !rationale.is_empty() {
                    payload["rationale"] = json!(rationale);
                }
                Ok((
                    "record_evidence".to_string(),
                    json!({
                        "requester_identity_id": requester,
                        "authority_grant_id": grant,
                        "payload": payload,
                    }),
                ))
            }
            FormKind::ProposeTransition => {
                let from_state = self.req_text("from_state_id")?;
                let new_state = self
                    .json_obj("new_state_payload (JSON object)")?
                    .expect("required");
                let mut args = json!({
                    "requester_identity_id": requester,
                    "from_state_id": from_state,
                    "authority_grant_id": grant,
                    "new_state_payload": new_state,
                });
                if let Some(tp) = self.json_obj("transition_payload (JSON object, optional)")? {
                    args["transition_payload"] = tp;
                }
                let ev: Vec<String> = self
                    .text("evidence_ids (comma-separated, optional)")
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                if !ev.is_empty() {
                    args["evidence_ids"] = json!(ev);
                }
                Ok(("transition".to_string(), args))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct App {
    db_path: String,
    states: Vec<StateRow>,
    states_by_id: HashMap<String, usize>,
    transitions: Vec<TransitionRow>,
    transition_by_id: HashMap<String, usize>,
    transition_into: HashMap<String, usize>, // to_state_id -> transition idx
    receipts: Vec<ReceiptRow>,
    evidence: Vec<EvidenceRow>,
    evidence_by_id: HashMap<String, usize>,
    grants: Vec<GrantRow>,
    grant_by_id: HashMap<String, usize>,
    revocations: Vec<RevocationRow>,
    exceptions_by_receipt: HashMap<String, ExceptionRow>,

    roots: Vec<LineageNode>,
    expanded: HashSet<String>,
    tree_rows: Vec<TreeRow>,

    tab: usize,
    list_state: ListState,
    query: String,
    searching: bool,
    detail_scroll: u16,
    show_help: bool,
    status_msg: String,

    // Write path: live DB for MCP writes (None disables the write
    // keys), plus how to spawn the MCP server. Browsing always uses
    // db_path, the read-only snapshot.
    live_db: Option<String>,
    mcp_server_py: String,
    python: String,
    write_form: Option<WriteForm>,
    // In-session memory of the last-used identity/grant, prefilled into
    // new forms. Never persisted; the operator still names them.
    last_identity: String,
    last_grant: String,
}

impl App {
    pub fn load(cfg: &AppConfig) -> Result<Self> {
        let db = Db::open_read_only(&cfg.db_path)?;
        let states = db.states()?;
        let transitions = db.transitions()?;
        let receipts = db.receipts()?;
        let evidence = db.evidence()?;
        let grants = db.grants()?;
        let revocations = db.revocations()?;
        let exceptions = db.exceptions()?;

        let states_by_id = states
            .iter()
            .enumerate()
            .map(|(i, s)| (s.state_id.clone(), i))
            .collect();
        let transition_by_id = transitions
            .iter()
            .enumerate()
            .map(|(i, t)| (t.transition_id.clone(), i))
            .collect();
        let transition_into = transitions
            .iter()
            .enumerate()
            .map(|(i, t)| (t.to_state_id.clone(), i))
            .collect();
        let evidence_by_id = evidence
            .iter()
            .enumerate()
            .map(|(i, e)| (e.evidence_id.clone(), i))
            .collect();
        let grant_by_id = grants
            .iter()
            .enumerate()
            .map(|(i, g)| (g.grant_id.clone(), i))
            .collect();
        let exceptions_by_receipt = exceptions
            .into_iter()
            .map(|e| (e.receipt_id.clone(), e))
            .collect();

        let roots = build_lineage(&states, &transitions);
        // Start with the first level expanded so the tree isn't just roots.
        let mut expanded: HashSet<String> = roots
            .iter()
            .map(|r| r.state.state_id.clone())
            .collect();
        // Also expand genesis children one level if there's a single root.
        if roots.len() == 1 {
            for (t, _) in &roots[0].children {
                let _ = t;
            }
            for (_, child) in &roots[0].children {
                expanded.insert(child.state.state_id.clone());
            }
        }
        let tree_rows = flatten_tree(&roots, &expanded);

        let mut app = Self {
            db_path: cfg.db_path.clone(),
            states,
            states_by_id,
            transitions,
            transition_by_id,
            transition_into,
            receipts,
            evidence,
            evidence_by_id,
            grants,
            grant_by_id,
            revocations,
            exceptions_by_receipt,
            roots,
            expanded,
            tree_rows,
            tab: 0,
            list_state: ListState::default(),
            query: String::new(),
            searching: false,
            detail_scroll: 0,
            show_help: false,
            status_msg: String::new(),
            live_db: cfg.live_db.clone(),
            mcp_server_py: cfg.mcp_server_py.clone(),
            python: cfg.python.clone(),
            write_form: None,
            last_identity: String::new(),
            last_grant: String::new(),
        };
        app.list_state.select(Some(0));
        Ok(app)
    }

    pub fn reload(&mut self) {
        let cfg = AppConfig {
            db_path: self.db_path.clone(),
            live_db: self.live_db.clone(),
            mcp_server_py: self.mcp_server_py.clone(),
            python: self.python.clone(),
        };
        // Preserve the operator's in-session identity/grant memory and
        // any open form across reloads.
        let (last_identity, last_grant, write_form) =
            (self.last_identity.clone(), self.last_grant.clone(), self.write_form.take());
        self.status_msg = match Self::load(&cfg) {
            Ok(fresh) => {
                *self = fresh;
                self.last_identity = last_identity;
                self.last_grant = last_grant;
                self.write_form = write_form;
                "reloaded from disk".to_string()
            }
            Err(e) => {
                self.write_form = write_form;
                format!("reload failed: {e:#}")
            }
        };
    }

    // -- write forms --------------------------------------------------------

    fn selected_state_id(&self) -> Option<String> {
        match self.tab {
            // Lineage tree rows and States rows are keyed by state_id.
            0 | 1 => self.selected_id(),
            _ => None,
        }
    }

    fn open_write_form(&mut self, kind: FormKind) {
        if self.live_db.is_none() {
            self.status_msg =
                "writes disabled: set EASTER_LIVE_DB (or --live-db) to enable".to_string();
            return;
        }
        let from_state = if kind == FormKind::ProposeTransition {
            self.selected_state_id()
        } else {
            None
        };
        self.write_form = Some(WriteForm::new(
            kind,
            &self.last_identity.clone(),
            &self.last_grant.clone(),
            from_state.as_deref(),
        ));
        self.status_msg.clear();
    }

    fn handle_form_key(&mut self, code: crossterm::event::KeyCode) -> bool {
        use crossterm::event::KeyCode::*;
        match code {
            Esc => {
                self.write_form = None;
                self.status_msg = "write cancelled".to_string();
            }
            Enter => self.submit_write_form(),
            _ => {
                let form = match self.write_form.as_mut() {
                    Some(f) => f,
                    None => return true,
                };
                match code {
                    Tab | Down => {
                        form.focus = (form.focus + 1) % form.fields.len();
                        form.error = None;
                    }
                    BackTab | Up => {
                        form.focus = (form.focus + form.fields.len() - 1) % form.fields.len();
                        form.error = None;
                    }
                    Backspace => {
                        form.fields[form.focus].value.pop();
                        form.error = None;
                    }
                    Char(c) => {
                        form.fields[form.focus].value.push(c);
                        form.error = None;
                    }
                    _ => {}
                }
            }
        }
        true
    }

    fn submit_write_form(&mut self) {
        let Some(form) = self.write_form.take() else {
            return;
        };
        match self.run_submit(&form) {
            Ok(msg) => {
                // In-session memory only: prefill the next form, never
                // persisted. The operator still names identity and grant.
                self.last_identity = form.text("requester_identity_id").to_string();
                self.last_grant = form.text("authority_grant_id").to_string();
                self.status_msg = msg;
            }
            Err(e) => {
                let mut form = form;
                form.error = Some(format!("{e:#}"));
                self.write_form = Some(form);
            }
        }
    }

    /// Validate, run one MCP call in a freshly spawned server (killed
    /// before this returns), refresh the snapshot from the live DB, and
    /// reload the TUI. The live DB is open only for this call.
    fn run_submit(&mut self, form: &WriteForm) -> Result<String> {
        let live_db = self
            .live_db
            .clone()
            .ok_or_else(|| anyhow::anyhow!("writes disabled"))?;
        let (tool, args) = form.validated_args()?;
        let cfg = McpConfig::new(&self.python, &self.mcp_server_py, &live_db);
        // The response is the commit confirmation: the kernel commits
        // atomically before the tool returns.
        let result = mcp::oneshot_call(&cfg, &tool, &args)?;

        let mut note = String::new();
        if let Err(e) = refresh_snapshot(&live_db, &self.db_path) {
            note = format!(" -- snapshot refresh failed: {e:#}");
        }
        // Reload from the (refreshed) snapshot, keeping the in-session
        // identity/grant memory.
        let (li, lg) = (self.last_identity.clone(), self.last_grant.clone());
        self.reload();
        self.last_identity = li;
        self.last_grant = lg;

        let get = |k: &str| result.get(k).and_then(Value::as_str).unwrap_or("?");
        let summary = match tool.as_str() {
            "record_evidence" => format!(
                "evidence {} recorded (receipt {}){}",
                short_id(get("evidence_id")),
                short_id(get("receipt_id")),
                note
            ),
            "transition" => format!(
                "transition {} -> state {} (receipt {}){}",
                short_id(get("transition_id")),
                short_id(get("state_id")),
                short_id(get("receipt_id")),
                note
            ),
            _ => format!("{tool} ok{note}"),
        };
        self.status_msg = summary.clone();
        Ok(summary)
    }

    // -- rows ---------------------------------------------------------------

    fn rows(&self) -> Vec<RowItem> {
        let mut rows: Vec<RowItem> = match self.tab {
            0 => self
                .tree_rows
                .iter()
                .map(|tr| {
                    let idx = self.states_by_id[tr.state_id.as_str()];
                    let s = &self.states[idx];
                    let glyph = if tr.has_children {
                        if tr.expanded { "▾ " } else { "▸ " }
                    } else {
                        "  "
                    };
                    let indent = "  ".repeat(tr.depth);
                    RowItem {
                        id: tr.state_id.clone(),
                        title: format!("{indent}{glyph}{}", summarize_state(&s.payload)),
                        subtitle: format!("{} · {}", short_id(&tr.state_id), s.created_at),
                        haystack: format!(
                            "{} {} {}",
                            tr.state_id,
                            s.payload.to_lowercase(),
                            s.created_at
                        ),
                    }
                })
                .collect(),
            1 => self
                .states
                .iter()
                .map(|s| RowItem {
                    id: s.state_id.clone(),
                    title: summarize_state(&s.payload),
                    subtitle: format!("{} · {}", short_id(&s.state_id), s.created_at),
                    haystack: format!("{} {} {}", s.state_id, s.payload.to_lowercase(), s.created_at),
                })
                .collect(),
            2 => self
                .transitions
                .iter()
                .map(|t| RowItem {
                    id: t.transition_id.clone(),
                    title: summarize_transition(&t.payload),
                    subtitle: format!(
                        "{} → {} · {}",
                        short_id(&t.from_state_id),
                        short_id(&t.to_state_id),
                        t.created_at
                    ),
                    haystack: format!(
                        "{} {} {} {} {}",
                        t.transition_id,
                        t.from_state_id,
                        t.to_state_id,
                        t.payload.to_lowercase(),
                        t.created_at
                    ),
                })
                .collect(),
            3 => self
                .receipts
                .iter()
                .map(|r| RowItem {
                    id: r.receipt_id.clone(),
                    title: format!("{} · {}", r.outcome, short_id(&r.operation_id)),
                    subtitle: format!("{} · {}", short_id(&r.receipt_id), r.created_at),
                    haystack: format!(
                        "{} {} {} {}",
                        r.receipt_id,
                        r.operation_id,
                        r.outcome.to_lowercase(),
                        r.payload.to_lowercase()
                    ),
                })
                .collect(),
            4 => self
                .evidence
                .iter()
                .map(|e| RowItem {
                    id: e.evidence_id.clone(),
                    title: summarize_evidence(&e.payload),
                    subtitle: format!("{} · {}", short_id(&e.evidence_id), e.created_at),
                    haystack: format!(
                        "{} {} {}",
                        e.evidence_id,
                        e.payload.to_lowercase(),
                        e.created_at
                    ),
                })
                .collect(),
            _ => self
                .grants
                .iter()
                .map(|g| {
                    let st = grant_status(g, &self.revocations);
                    RowItem {
                        id: g.grant_id.clone(),
                        title: format!("{} → {}", short_id(&g.identity_id), short_id(&g.authority_id)),
                        subtitle: format!("{} · {}", st.label(), short_id(&g.grant_id)),
                        haystack: format!(
                            "{} {} {} {}",
                            g.grant_id,
                            g.identity_id,
                            g.authority_id,
                            st.label().to_lowercase()
                        ),
                    }
                })
                .collect(),
        };
        if !self.query.is_empty() {
            let q = self.query.to_lowercase();
            rows.retain(|r| r.haystack.contains(&q));
        }
        rows
    }

    fn selected_id(&self) -> Option<String> {
        let rows = self.rows();
        let i = self.list_state.selected()?;
        rows.get(i).map(|r| r.id.clone())
    }

    // -- detail pane --------------------------------------------------------

    fn detail(&self) -> Vec<Line<'static>> {
        let Some(id) = self.selected_id() else {
            return vec![dim("no selection")];
        };
        match self.tab {
            0 | 1 => self.state_detail(&id),
            2 => self.transition_detail(&id),
            3 => self.receipt_detail(&id),
            4 => self.evidence_detail(&id),
            _ => self.grant_detail(&id),
        }
    }

    fn state_detail(&self, state_id: &str) -> Vec<Line<'static>> {
        let mut out = Vec::new();
        let Some(&idx) = self.states_by_id.get(state_id) else {
            return vec![dim("state not found")];
        };
        let s = &self.states[idx];
        out.push(h1(&s.state_id));
        out.push(kv("created", &s.created_at));
        out.push(kv("summary", &summarize_state(&s.payload)));
        out.push(blank());
        out.push(h2("Payload"));
        out.extend(code_block(&pretty_json(&s.payload)));

        if let Some(&ti) = self.transition_into.get(state_id) {
            let t = &self.transitions[ti];
            out.push(blank());
            out.push(h2("Arrived via transition"));
            out.push(kv("transition", &t.transition_id));
            out.push(kv("from", &t.from_state_id));
            out.push(kv("grant", &t.authority_grant_id));
            out.push(kv("task", &summarize_transition(&t.payload)));
            out.push(kv("at", &t.created_at));
            for r in self.receipts.iter().filter(|r| r.transition_id.as_deref() == Some(t.transition_id.as_str())) {
                out.push(kv("receipt", &format!("{} ({})", r.receipt_id, r.outcome)));
            }
        } else {
            out.push(blank());
            out.push(dim("no incoming transition — a lineage root"));
        }

        // Children (branches from here).
        let kids: Vec<&TransitionRow> = self
            .transitions
            .iter()
            .filter(|t| t.from_state_id == state_id)
            .collect();
        out.push(blank());
        out.push(h2(&format!("Branches from here ({})", kids.len())));
        for t in kids.iter().take(20) {
            out.push(Line::from(format!(
                "  → {} · {}",
                short_id(&t.to_state_id),
                summarize_transition(&t.payload)
            )));
        }
        if kids.len() > 20 {
            out.push(dim(&format!("  …and {} more", kids.len() - 20)));
        }
        out
    }

    fn transition_detail(&self, transition_id: &str) -> Vec<Line<'static>> {
        let mut out = Vec::new();
        let Some(&idx) = self.transition_by_id.get(transition_id) else {
            return vec![dim("transition not found")];
        };
        let t = &self.transitions[idx];
        out.push(h1(&t.transition_id));
        out.push(kv("from", &t.from_state_id));
        out.push(kv("to", &t.to_state_id));
        out.push(kv("grant", &t.authority_grant_id));
        out.push(kv("at", &t.created_at));
        out.push(kv("task", &summarize_transition(&t.payload)));
        if let Some(&gi) = self.grant_by_id.get(t.authority_grant_id.as_str()) {
            let g = &self.grants[gi];
            out.push(kv(
                "grant",
                &format!(
                    "{} ({} → {})",
                    grant_status(g, &self.revocations).label(),
                    short_id(&g.identity_id),
                    short_id(&g.authority_id)
                ),
            ));
        }
        out.push(blank());
        out.push(h2("Transition payload (handoff detail)"));
        out.extend(code_block(&pretty_json(&t.payload)));
        out.push(blank());
        out.push(h2("Receipts"));
        let mut any = false;
        for r in self
            .receipts
            .iter()
            .filter(|r| r.transition_id.as_deref() == Some(transition_id))
        {
            any = true;
            out.push(outcome_line(&format!("{} · {}", r.receipt_id, r.operation_id), &r.outcome));
        }
        if !any {
            out.push(dim("none"));
        }
        out
    }

    fn receipt_detail(&self, receipt_id: &str) -> Vec<Line<'static>> {
        let mut out = Vec::new();
        let Some(r) = self.receipts.iter().find(|r| r.receipt_id == receipt_id) else {
            return vec![dim("receipt not found")];
        };
        out.push(outcome_line(&r.receipt_id, &r.outcome));
        out.push(kv("operation", &r.operation_id));
        out.push(kv("seq", &r.receipt_seq.to_string()));
        out.push(kv("at", &r.created_at));
        if let Some(tid) = &r.transition_id {
            out.push(kv("transition", tid));
            if let Some(&ti) = self.transition_by_id.get(tid.as_str()) {
                let t = &self.transitions[ti];
                out.push(kv("handoff", &summarize_transition(&t.payload)));
            }
        }
        out.push(blank());
        out.push(h2("Payload"));
        out.extend(code_block(&pretty_json(&r.payload)));

        // Evidence cited.
        if let Ok(db) = Db::open_read_only(&self.db_path) {
            if let Ok(ev_ids) = db.evidence_for_receipt(receipt_id) {
                if !ev_ids.is_empty() {
                    out.push(blank());
                    out.push(h2(&format!("Evidence cited ({})", ev_ids.len())));
                    for eid in ev_ids {
                        let summary = self
                            .evidence_by_id
                            .get(eid.as_str())
                            .map(|&i| summarize_evidence(&self.evidence[i].payload))
                            .unwrap_or_default();
                        out.push(Line::from(format!("  {eid} · {summary}")));
                    }
                }
            }
        }
        if let Some(exc) = self.exceptions_by_receipt.get(receipt_id) {
            out.push(blank());
            out.push(h2("Exception (why it failed)"));
            out.extend(code_block(&pretty_json(&exc.payload)));
        }
        out
    }

    fn evidence_detail(&self, evidence_id: &str) -> Vec<Line<'static>> {
        let mut out = Vec::new();
        let Some(&idx) = self.evidence_by_id.get(evidence_id) else {
            return vec![dim("evidence not found")];
        };
        let e = &self.evidence[idx];
        out.push(h1(&e.evidence_id));
        out.push(kv("created", &e.created_at));
        out.push(kv("summary", &summarize_evidence(&e.payload)));
        out.push(blank());
        out.push(h2("Payload"));
        out.extend(code_block(&pretty_json(&e.payload)));
        if let Ok(db) = Db::open_read_only(&self.db_path) {
            if let Ok(r_ids) = db.receipts_citing_evidence(evidence_id) {
                if !r_ids.is_empty() {
                    out.push(blank());
                    out.push(h2(&format!("Cited by receipts ({})", r_ids.len())));
                    for rid in r_ids {
                        out.push(Line::from(format!("  {rid}")));
                    }
                }
            }
        }
        out
    }

    fn grant_detail(&self, grant_id: &str) -> Vec<Line<'static>> {
        let mut out = Vec::new();
        let Some(&idx) = self.grant_by_id.get(grant_id) else {
            return vec![dim("grant not found")];
        };
        let g: &GrantRow = &self.grants[idx];
        let st = grant_status(g, &self.revocations);
        out.push(status_line(&g.grant_id, st.label(), status_color(st)));
        out.push(kv("identity", &g.identity_id));
        out.push(kv("authority", &g.authority_id));
        out.push(kv(
            "granted_by",
            g.granted_by.as_deref().unwrap_or("— (genesis)"),
        ));
        out.push(kv("valid_from", &g.valid_from));
        out.push(kv("expires_at", g.expires_at.as_deref().unwrap_or("never")));
        out.push(kv("authority_seq", &g.authority_seq.to_string()));
        out.push(kv("created", &g.created_at));

        for r in self.revocations.iter().filter(|r| {
            (r.kind == "REVOKE" && r.grant_id.as_deref() == Some(grant_id))
                || (r.kind == "REVOKE_ALL"
                    && r.identity_id.as_deref() == Some(g.identity_id.as_str())
                    && r.authority_seq > g.authority_seq)
        }) {
            out.push(blank());
            out.push(h2("Revoked by"));
            out.push(kv("revocation", &r.revocation_id));
            out.push(kv("kind", &r.kind));
            out.push(kv("caused_by", &r.caused_by));
            out.push(kv("at", &r.created_at));
        }

        let used: Vec<&TransitionRow> = self
            .transitions
            .iter()
            .filter(|t| t.authority_grant_id == grant_id)
            .collect();
        out.push(blank());
        out.push(h2(&format!("Transitions exercised ({})", used.len())));
        for t in used.iter().take(20) {
            out.push(Line::from(format!(
                "  {} → {} · {}",
                short_id(&t.from_state_id),
                short_id(&t.to_state_id),
                summarize_transition(&t.payload)
            )));
        }
        if used.len() > 20 {
            out.push(dim(&format!("  …and {} more", used.len() - 20)));
        }
        out.push(blank());
        out.push(h2("Payload"));
        out.extend(code_block(&pretty_json(&g.payload)));
        out
    }

    // -- input --------------------------------------------------------------

    /// Handle a key. Returns false when the app should quit.
    pub fn handle_key(&mut self, code: crossterm::event::KeyCode) -> bool {
        use crossterm::event::KeyCode::*;
        if self.show_help {
            self.show_help = false;
            return true;
        }
        if self.write_form.is_some() {
            return self.handle_form_key(code);
        }
        if self.searching {
            match code {
                Esc | Enter => {
                    self.searching = false;
                    self.list_state.select(Some(0));
                    self.detail_scroll = 0;
                }
                Backspace => {
                    self.query.pop();
                }
                Char(c) => {
                    self.query.push(c);
                    self.list_state.select(Some(0));
                    self.detail_scroll = 0;
                }
                _ => {}
            }
            return true;
        }
        match code {
            Char('q') => return false,
            Esc => {
                if !self.query.is_empty() {
                    self.query.clear();
                    self.list_state.select(Some(0));
                }
            }
            Char('?') => self.show_help = true,
            Char('/') => {
                self.searching = true;
            }
            Char('r') => self.reload(),
            Char('e') => self.open_write_form(FormKind::RecordEvidence),
            Char('d') => self.open_write_form(FormKind::RecordDecision),
            Char('t') => self.open_write_form(FormKind::ProposeTransition),
            Tab => self.switch_tab((self.tab + 1) % TABS.len()),
            BackTab => self.switch_tab((self.tab + TABS.len() - 1) % TABS.len()),
            Char(c @ '1'..='6') => {
                let i = (c as usize) - ('1' as usize);
                if i < TABS.len() {
                    self.switch_tab(i);
                }
            }
            Up | Char('k') => self.move_sel(-1),
            Down | Char('j') => self.move_sel(1),
            Char('K') => {
                self.detail_scroll = self.detail_scroll.saturating_add(3);
            }
            Char('J') => {
                self.detail_scroll = self.detail_scroll.saturating_sub(3);
            }
            Char('g') => {
                self.list_state.select(Some(0));
                self.detail_scroll = 0;
            }
            Char('G') => {
                let n = self.rows().len();
                if n > 0 {
                    self.list_state.select(Some(n - 1));
                    self.detail_scroll = 0;
                }
            }
            Enter => self.activate(),
            _ => {}
        }
        true
    }

    fn switch_tab(&mut self, i: usize) {
        self.tab = i;
        self.query.clear();
        self.detail_scroll = 0;
        self.status_msg.clear();
        self.list_state.select(Some(0));
    }

    fn move_sel(&mut self, delta: i32) {
        let n = self.rows().len() as i32;
        if n == 0 {
            return;
        }
        let cur = self.list_state.selected().unwrap_or(0) as i32;
        let next = (cur + delta).clamp(0, n - 1) as usize;
        self.list_state.select(Some(next));
        self.detail_scroll = 0;
    }

    /// Enter: toggle tree expansion on Lineage; jump to the natural
    /// related record on the other tabs.
    fn activate(&mut self) {
        let Some(id) = self.selected_id() else {
            return;
        };
        match self.tab {
            0 => {
                if self.expanded.remove(&id) {
                    self.status_msg = format!("collapsed {}", short_id(&id));
                } else {
                    // Only expandable if it has children.
                    let has = self.tree_rows.iter().any(|tr| tr.state_id == id && tr.has_children);
                    if has {
                        self.expanded.insert(id.clone());
                        self.status_msg = format!("expanded {}", short_id(&id));
                    } else {
                        self.status_msg = "leaf state — nothing to expand".to_string();
                        return;
                    }
                }
                self.tree_rows = flatten_tree(&self.roots, &self.expanded);
                // Keep selection on the toggled node.
                if let Some(pos) = self.tree_rows.iter().position(|tr| tr.state_id == id) {
                    self.list_state.select(Some(pos));
                }
            }
            2 => {
                // Transition -> its to_state in States.
                if let Some(&ti) = self.transition_by_id.get(id.as_str()) {
                    let to = self.transitions[ti].to_state_id.clone();
                    self.jump_to(1, &to);
                }
            }
            3 => {
                // Receipt -> its transition in Transitions.
                let tid: Option<String> = self
                    .receipts
                    .iter()
                    .find(|r| r.receipt_id == id)
                    .and_then(|r| r.transition_id.clone());
                match tid {
                    Some(tid) => self.jump_to(2, &tid),
                    None => self.status_msg = "receipt has no transition".to_string(),
                }
            }
            4 => {
                // Evidence -> first receipt citing it.
                if let Ok(db) = Db::open_read_only(&self.db_path) {
                    if let Ok(rids) = db.receipts_citing_evidence(&id) {
                        if let Some(rid) = rids.first() {
                            self.jump_to(3, rid);
                        } else {
                            self.status_msg = "no receipts cite this evidence".to_string();
                        }
                    }
                }
            }
            _ => {
                self.status_msg = "Enter expands nodes on the Lineage tab".to_string();
            }
        }
    }

    fn jump_to(&mut self, tab: usize, id: &str) {
        self.switch_tab(tab);
        if let Some(pos) = self.rows().iter().position(|r| r.id == id) {
            self.list_state.select(Some(pos));
            self.status_msg = format!("jumped to {}", short_id(id));
        }
    }

    // -- rendering ------------------------------------------------------------

    pub fn render(&mut self, f: &mut Frame) {
        let area = f.area();
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .split(area);

        // Header: title + tabs.
        let title = Line::from(vec![
            Span::styled(
                " easter-console ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  {}   {} states · {} transitions · {} receipts",
                self.db_path,
                self.states.len(),
                self.transitions.len(),
                self.receipts.len()
            )),
        ]);
        let tabs = Tabs::new(TABS.to_vec())
            .select(self.tab)
            .block(Block::default().borders(Borders::BOTTOM))
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .divider("│");
        let header = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(3)])
            .split(layout[0]);
        f.render_widget(Paragraph::new(title), header[0]);
        f.render_widget(tabs, header[1]);

        // Main: list | detail.
        let main = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(layout[1]);

        let rows = self.rows();
        let items: Vec<ListItem> = rows
            .iter()
            .map(|r| {
                ListItem::new(vec![
                    Line::from(Span::styled(
                        r.title.clone(),
                        Style::default().add_modifier(Modifier::BOLD),
                    )),
                    Line::from(Span::styled(&r.subtitle, Style::default().fg(Color::DarkGray))),
                ])
            })
            .collect();
        let list_title = if self.searching {
            format!(" {}  [/{}_] ", TABS[self.tab], self.query)
        } else if self.query.is_empty() {
            format!(" {} ({} rows) ", TABS[self.tab], rows.len())
        } else {
            format!(" {}  [/{}] ({} rows) ", TABS[self.tab], self.query, rows.len())
        };
        let list = List::new(items)
            .block(Block::default().title(list_title).borders(Borders::ALL))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("▶ ");
        f.render_stateful_widget(list, main[0], &mut self.list_state);

        let detail_lines = self.detail();
        let detail = Paragraph::new(Text::from(detail_lines))
            .block(Block::default().title(" Detail ").borders(Borders::ALL))
            .wrap(Wrap { trim: false })
            .scroll((self.detail_scroll, 0));
        f.render_widget(detail, main[1]);

        // Footer.
        let footer_text = if self.searching {
            format!(" search: /{}_   (Enter/Esc done · type to filter)", self.query)
        } else if !self.status_msg.is_empty() {
            format!(" {}", self.status_msg)
        } else {
            " j/k move · J/K scroll detail · Enter expand/jump · 1-6 tabs · / search · e/d/t write · r reload · ? help · q quit "
                .to_string()
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                footer_text,
                Style::default().fg(Color::DarkGray),
            ))),
            layout[2],
        );

        if self.show_help {
            self.render_help(f, area);
        }

        if self.write_form.is_some() {
            self.render_form(f, area);
        }
    }

    fn render_form(&self, f: &mut Frame, area: Rect) {
        let Some(form) = &self.write_form else {
            return;
        };
        let label_w = form
            .fields
            .iter()
            .map(|x| x.label.len())
            .max()
            .unwrap_or(0);
        let mut lines = vec![
            h1(form.kind.title()),
            dim("one MCP server is spawned for the submit and killed right after"),
            blank(),
        ];
        for (i, field) in form.fields.iter().enumerate() {
            let cursor = if i == form.focus { "_" } else { "" };
            let shown: String = field.value.chars().take(56).collect();
            let style = if i == form.focus {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{:>w$}  ", field.label, w = label_w),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(format!("{shown}{cursor}"), style),
            ]));
        }
        if let Some(err) = &form.error {
            lines.push(blank());
            lines.push(Line::from(Span::styled(
                err.clone(),
                Style::default().fg(Color::Red),
            )));
        }
        lines.push(blank());
        lines.push(dim("Tab / Up / Down move · type to edit · Enter submits · Esc cancels"));
        let w = 78.min(area.width.saturating_sub(4));
        let h = (lines.len() as u16 + 4).min(area.height.saturating_sub(4));
        let popup = centered_rect(w, h, area);
        f.render_widget(Clear, popup);
        f.render_widget(
            Paragraph::new(Text::from(lines))
                .block(Block::default().title(" Write ").borders(Borders::ALL)),
            popup,
        );
    }

    fn render_help(&self, f: &mut Frame, area: Rect) {
        let lines = vec![
            h1("easter-console — keys"),
            blank(),
            kv("1–6 / Tab", "switch tabs (Lineage · States · Transitions · Receipts · Evidence · Grants)"),
            kv("j / k, ↑ / ↓", "move selection"),
            kv("J / K", "scroll detail pane"),
            kv("Enter", "Lineage: expand/collapse · others: jump to related record"),
            kv("/", "search the current tab (filters as you type)"),
            kv("Esc", "leave search · clear filter"),
            kv("g / G", "top / bottom of list"),
            kv("r", "reload the database from disk"),
            kv("e", "record evidence (MCP write: server spawned per submit)"),
            kv("d", "record a human decision (MCP write)"),
            kv("t", "propose a transition (MCP write)"),
            kv("?", "this help"),
            kv("q", "quit"),
            blank(),
            dim("Browsing reads a snapshot opened SQLITE_OPEN_READ_ONLY."),
            dim("Writes go through the MCP server to the live DB: the"),
            dim("server is spawned per submit and killed right after,"),
            dim("then the snapshot is refreshed from the live DB."),
        ];
        let w = 72.min(area.width.saturating_sub(4));
        let h = (lines.len() as u16 + 4).min(area.height.saturating_sub(4));
        let popup = centered_rect(w, h, area);
        f.render_widget(Clear, popup);
        f.render_widget(
            Paragraph::new(Text::from(lines))
                .block(Block::default().title(" Help ").borders(Borders::ALL)),
            popup,
        );
    }
}

// ---------------------------------------------------------------------------
// Line helpers
// ---------------------------------------------------------------------------

fn blank() -> Line<'static> {
    Line::from("")
}

fn dim(s: &str) -> Line<'static> {
    Line::from(Span::styled(s.to_string(), Style::default().fg(Color::DarkGray)))
}

fn h1(s: &str) -> Line<'static> {
    Line::from(Span::styled(
        s.to_string(),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ))
}

fn h2(s: &str) -> Line<'static> {
    Line::from(Span::styled(
        s.to_string(),
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    ))
}

fn kv(k: &str, v: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{k}: "), Style::default().fg(Color::DarkGray)),
        Span::raw(v.to_string()),
    ])
}

fn code_block(s: &str) -> Vec<Line<'static>> {
    s.lines()
        .map(|l| Line::from(Span::styled(l.to_string(), Style::default().fg(Color::Green))))
        .collect()
}

fn status_color(st: GrantStatus) -> Color {
    match st {
        GrantStatus::Live => Color::Green,
        GrantStatus::NotYetValid => Color::Cyan,
        GrantStatus::Expired => Color::Yellow,
        GrantStatus::Revoked => Color::Red,
    }
}

fn status_line(id: &str, label: &str, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            id.to_string(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("[{label}]"),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ])
}

fn outcome_color(outcome: &str) -> Color {
    match outcome {
        "ACCEPTED" | "BOOTSTRAP" => Color::Green,
        "REJECTED" => Color::Yellow,
        "FAILED" => Color::Red,
        _ => Color::White,
    }
}

fn outcome_line(id: &str, outcome: &str) -> Line<'static> {
    status_line(id, outcome, outcome_color(outcome))
}

fn centered_rect(w: u16, h: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    Rect {
        x,
        y,
        width: w.min(area.width),
        height: h.min(area.height),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{fixture_db, mcp_server_py, test_python};
    use ratatui::{backend::TestBackend, Terminal};

    fn test_config(db: &str) -> AppConfig {
        AppConfig {
            db_path: db.to_string(),
            live_db: None,
            mcp_server_py: mcp_server_py(),
            python: test_python(),
        }
    }

    fn test_app() -> App {
        let db = std::env::var("EASTER_TEST_DB").expect("set EASTER_TEST_DB to a kernel db");
        App::load(&test_config(&db)).expect("load test db")
    }

    /// App whose snapshot (`db_path`) and live DB are separate temp
    /// copies, with writes enabled. Returns the tempdir guard (must be
    /// kept alive) and the app.
    fn test_app_with_writes() -> (tempfile::TempDir, App) {
        let dir = tempfile::tempdir().unwrap();
        let live = fixture_db(dir.path(), "identity:test-nathan");
        let snap = dir.path().join("snap.db");
        std::fs::copy(&live, &snap).unwrap();
        let cfg = AppConfig {
            db_path: snap.to_string_lossy().into_owned(),
            live_db: Some(live.to_string_lossy().into_owned()),
            mcp_server_py: mcp_server_py(),
            python: test_python(),
        };
        let app = App::load(&cfg).expect("load test app");
        (dir, app)
    }

    fn type_text(app: &mut App, text: &str) {
        use crossterm::event::KeyCode::*;
        for c in text.chars() {
            assert!(app.handle_key(Char(c)));
        }
    }

    #[test]
    fn renders_every_tab_without_panic() {
        let mut app = test_app();
        let backend = TestBackend::new(140, 45);
        let mut terminal = Terminal::new(backend).unwrap();
        for tab in 0..TABS.len() {
            app.switch_tab(tab);
            // Walk the whole list to render every detail pane.
            let n = app.rows().len();
            for i in 0..n {
                app.list_state.select(Some(i));
                terminal.draw(|f| app.render(f)).unwrap();
            }
        }
    }

    #[test]
    fn interactions_do_not_panic() {
        use crossterm::event::KeyCode::*;
        let mut app = test_app();
        let backend = TestBackend::new(140, 45);
        let mut terminal = Terminal::new(backend).unwrap();

        // Expand/collapse on lineage.
        app.switch_tab(0);
        assert!(app.handle_key(Enter));
        terminal.draw(|f| app.render(f)).unwrap();
        assert!(app.handle_key(Enter));
        terminal.draw(|f| app.render(f)).unwrap();

        // Search filtering.
        assert!(app.handle_key(Char('/')));
        for c in "gw".chars() {
            assert!(app.handle_key(Char(c)));
        }
        terminal.draw(|f| app.render(f)).unwrap();
        assert!(app.handle_key(Esc));
        assert!(app.handle_key(Esc)); // clears filter

        // Detail scroll, top/bottom, reload, help.
        assert!(app.handle_key(Char('J')));
        assert!(app.handle_key(Char('K')));
        assert!(app.handle_key(Char('G')));
        assert!(app.handle_key(Char('g')));
        terminal.draw(|f| app.render(f)).unwrap();
        assert!(app.handle_key(Char('?')));
        terminal.draw(|f| app.render(f)).unwrap();
        assert!(app.handle_key(Esc));
        app.switch_tab(2);
        assert!(app.handle_key(Enter)); // jump transition -> to_state
        assert_eq!(app.tab, 1);
        terminal.draw(|f| app.render(f)).unwrap();
        assert!(!app.handle_key(Char('q'))); // 'q' signals quit outside search
    }

    #[test]
    fn write_form_records_evidence_and_refreshes_snapshot() {
        use crossterm::event::KeyCode::*;
        let (_dir, mut app) = test_app_with_writes();
        let backend = TestBackend::new(140, 45);
        let mut terminal = Terminal::new(backend).unwrap();

        // Open the evidence form and render it (must not panic).
        assert!(app.handle_key(Char('e')));
        terminal.draw(|f| app.render(f)).unwrap();

        // Fill identity, grant, payload; Tab moves between fields.
        type_text(&mut app, "identity:test-nathan");
        assert!(app.handle_key(Tab));
        type_text(&mut app, "grant:genesis-root");
        assert!(app.handle_key(Tab));
        type_text(&mut app, "{\"note\":\"from rust form test\"}");
        terminal.draw(|f| app.render(f)).unwrap();

        // Submit: one MCP call, snapshot refresh, reload.
        assert!(app.handle_key(Enter));
        assert!(
            app.status_msg.contains("recorded"),
            "unexpected status: {}",
            app.status_msg
        );
        // The reloaded snapshot shows the new evidence.
        assert!(app
            .evidence
            .iter()
            .any(|e| e.payload.contains("from rust form test")));

        // In-session memory prefills the next form.
        assert!(app.handle_key(Char('e')));
        terminal.draw(|f| app.render(f)).unwrap();
        assert!(app.handle_key(Esc));
    }

    #[test]
    fn write_form_rejects_bad_json_without_touching_mcp() {
        use crossterm::event::KeyCode::*;
        let (_dir, mut app) = test_app_with_writes();
        let backend = TestBackend::new(140, 45);
        let mut terminal = Terminal::new(backend).unwrap();

        assert!(app.handle_key(Char('e')));
        type_text(&mut app, "identity:test-nathan");
        assert!(app.handle_key(Tab));
        type_text(&mut app, "grant:genesis-root");
        assert!(app.handle_key(Tab));
        type_text(&mut app, "{not json");
        assert!(app.handle_key(Enter));
        // Form stays open with the validation error; nothing was sent.
        assert!(app.write_form.is_some());
        terminal.draw(|f| app.render(f)).unwrap();
        assert!(app.handle_key(Esc));
        assert!(app.write_form.is_none());
    }

    #[test]
    fn write_form_accepts_empty_json_object() {
        // Regression guard for the Python console's original `{}` bug:
        // an empty object is valid input, not "missing".
        use crossterm::event::KeyCode::*;
        let (_dir, mut app) = test_app_with_writes();

        // Grants tab: no from_state_id prefill (the States/Lineage tabs
        // prefill it from the selection, which the operator can edit).
        assert!(app.handle_key(Char('6')));
        assert!(app.handle_key(Char('t'))); // propose transition
        type_text(&mut app, "identity:test-nathan");
        assert!(app.handle_key(Tab));
        type_text(&mut app, "grant:genesis-root");
        assert!(app.handle_key(Tab));
        type_text(&mut app, "state:genesis");
        assert!(app.handle_key(Tab));
        type_text(&mut app, "{}"); // empty new_state_payload must be accepted
        assert!(app.handle_key(Enter));
        assert!(
            app.status_msg.contains("transition"),
            "unexpected status: {}",
            app.status_msg
        );
    }

    #[test]
    fn write_keys_disabled_without_live_db() {
        use crossterm::event::KeyCode::*;
        let mut app = test_app(); // live_db: None
        assert!(app.handle_key(Char('e')));
        assert!(app.write_form.is_none());
        assert!(app.status_msg.contains("writes disabled"));
    }
}
