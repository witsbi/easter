//! Presentation model: summaries, lineage tree, grant status.
//!
//! The kernel stores userland meaning in opaque JSON payloads. This module
//! knows the *conventions* from docs/agent-continuity-payloads.md (tip
//! labels, handoff fields, evidence kinds) purely for display — it never
//! treats a conventional field as kernel-validated.

use crate::db::{GrantRow, RevocationRow, StateRow, TransitionRow};
use chrono::Utc;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Best-effort one-line summary of a state (tip label).
/// Convention: {"project": ..., "status": ..., ...} -> "project · status".
pub fn summarize_state(payload: &str) -> String {
    match serde_json::from_str::<Value>(payload) {
        Ok(Value::Object(map)) => {
            let project = map.get("project").and_then(Value::as_str).unwrap_or("?");
            let status = map.get("status").and_then(Value::as_str).unwrap_or("?");
            if project != "?" || status != "?" {
                return format!("{project} · {status}");
            }
            compact_json(payload, 64)
        }
        _ => compact_json(payload, 64),
    }
}

/// Best-effort one-line summary of a transition (handoff detail).
/// Convention: {"task": ...} -> the task string.
pub fn summarize_transition(payload: &str) -> String {
    match serde_json::from_str::<Value>(payload) {
        Ok(Value::Object(map)) => match map.get("task").and_then(Value::as_str) {
            Some(task) if !task.is_empty() => task.to_string(),
            _ => compact_json(payload, 64),
        },
        _ => compact_json(payload, 64),
    }
}

/// Best-effort one-line summary of an evidence record.
/// Convention: {"kind": ..., "summary": ...} -> "kind: summary".
pub fn summarize_evidence(payload: &str) -> String {
    match serde_json::from_str::<Value>(payload) {
        Ok(Value::Object(map)) => {
            let kind = map.get("kind").and_then(Value::as_str).unwrap_or("?");
            let summary = map.get("summary").and_then(Value::as_str).unwrap_or("");
            if kind != "?" && !summary.is_empty() {
                return format!("{kind}: {summary}");
            }
            if kind != "?" {
                // project_anchor and friends carry their meaning in other fields
                let project = map.get("project").and_then(Value::as_str).unwrap_or("");
                if !project.is_empty() {
                    return format!("{kind}: {project}");
                }
                return kind.to_string();
            }
            compact_json(payload, 64)
        }
        _ => compact_json(payload, 64),
    }
}

fn compact_json(payload: &str, max: usize) -> String {
    let one_line: String = payload.chars().filter(|c| !c.is_whitespace()).collect();
    if one_line.chars().count() <= max {
        one_line
    } else {
        let mut s: String = one_line.chars().take(max.saturating_sub(1)).collect();
        s.push('…');
        s
    }
}

/// Pretty-print JSON for the detail pane; falls back to raw text.
pub fn pretty_json(payload: &str) -> String {
    match serde_json::from_str::<Value>(payload) {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| payload.to_string()),
        Err(_) => payload.to_string(),
    }
}

/// Shorten a long kernel ID for list display, keeping the prefix that
/// carries meaning ("state:", "transition:", ...).
pub fn short_id(id: &str) -> String {
    if id.len() <= 24 {
        return id.to_string();
    }
    if let Some((prefix, rest)) = id.split_once(':') {
        let head: String = rest.chars().take(8).collect();
        format!("{prefix}:{head}…")
    } else {
        let head: String = id.chars().take(12).collect();
        format!("{head}…")
    }
}

// ---------------------------------------------------------------------------
// Grant status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantStatus {
    Live,
    NotYetValid,
    Expired,
    Revoked,
}

impl GrantStatus {
    pub fn label(self) -> &'static str {
        match self {
            GrantStatus::Live => "LIVE",
            GrantStatus::NotYetValid => "PENDING",
            GrantStatus::Expired => "EXPIRED",
            GrantStatus::Revoked => "REVOKED",
        }
    }
}

/// Mirror of the kernel's own revocation semantics, for display only:
/// a grant dies on a REVOKE naming it, or on a REVOKE_ALL for its
/// identity whose authority_seq is later than the grant's own.
pub fn grant_status(grant: &GrantRow, revocations: &[RevocationRow]) -> GrantStatus {
    for r in revocations {
        match r.kind.as_str() {
            "REVOKE" if r.grant_id.as_deref() == Some(grant.grant_id.as_str()) => {
                return GrantStatus::Revoked;
            }
            "REVOKE_ALL"
                if r.identity_id.as_deref() == Some(grant.identity_id.as_str())
                    && r.authority_seq > grant.authority_seq =>
            {
                return GrantStatus::Revoked;
            }
            _ => {}
        }
    }
    // Timestamps are Z-suffixed ISO8601 UTC: lexicographic compare is valid.
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
    if grant.valid_from.as_str() > now.as_str() {
        return GrantStatus::NotYetValid;
    }
    match grant.expires_at.as_deref() {
        Some(exp) if exp <= now.as_str() => GrantStatus::Expired,
        _ => GrantStatus::Live,
    }
}

// ---------------------------------------------------------------------------
// Lineage tree
// ---------------------------------------------------------------------------

/// One node of the state lineage tree. Children are states reached by a
/// transition *from* this state. The kernel deliberately has no
/// canonical head, so a state may have many children (branches).
#[derive(Debug, Clone)]
pub struct LineageNode {
    pub state: StateRow,
    /// (transition, child node) pairs, oldest first.
    pub children: Vec<(TransitionRow, LineageNode)>,
}

/// Build the forest. Roots are states with no incoming transition
/// (state:genesis is the usual one). Orphan states whose from-side is
/// missing still appear as roots rather than vanishing.
pub fn build_lineage(states: &[StateRow], transitions: &[TransitionRow]) -> Vec<LineageNode> {
    let mut by_from: HashMap<&str, Vec<&TransitionRow>> = HashMap::new();
    for t in transitions {
        by_from.entry(t.from_state_id.as_str()).or_default().push(t);
    }
    let mut incoming: HashSet<&str> = HashSet::new();
    for t in transitions {
        incoming.insert(t.to_state_id.as_str());
    }

    fn build(
        state: &StateRow,
        states_by_id: &HashMap<&str, &StateRow>,
        by_from: &HashMap<&str, Vec<&TransitionRow>>,
        visiting: &mut HashSet<String>,
    ) -> LineageNode {
        // The UNIQUE(to_state_id) constraint makes true cycles impossible,
        // but guard anyway so a hand-edited DB can't hang the console.
        visiting.insert(state.state_id.clone());
        let mut children = Vec::new();
        if let Some(ts) = by_from.get(state.state_id.as_str()) {
            let mut ts = ts.clone();
            ts.sort_by(|a, b| a.created_at.cmp(&b.created_at));
            for t in ts {
                if visiting.contains(&t.to_state_id) {
                    continue;
                }
                if let Some(child_state) = states_by_id.get(t.to_state_id.as_str()) {
                    children.push((
                        (*t).clone(),
                        build(child_state, states_by_id, by_from, visiting),
                    ));
                }
            }
        }
        visiting.remove(&state.state_id);
        LineageNode {
            state: state.clone(),
            children,
        }
    }

    let states_by_id: HashMap<&str, &StateRow> =
        states.iter().map(|s| (s.state_id.as_str(), s)).collect();
    let mut visiting = HashSet::new();
    let mut roots: Vec<LineageNode> = states
        .iter()
        .filter(|s| !incoming.contains(s.state_id.as_str()))
        .map(|s| build(s, &states_by_id, &by_from, &mut visiting))
        .collect();
    roots.sort_by(|a, b| a.state.created_at.cmp(&b.state.created_at));
    roots
}

/// Flattened, display-ready tree row.
#[derive(Debug, Clone)]
pub struct TreeRow {
    pub state_id: String,
    pub depth: usize,
    pub has_children: bool,
    pub expanded: bool,
    pub is_last: bool,
}

/// Flatten the forest honoring the expanded set. `expanded` holds the
/// state_ids whose children are visible.
pub fn flatten_tree(roots: &[LineageNode], expanded: &HashSet<String>) -> Vec<TreeRow> {
    let mut out = Vec::new();
    for (i, root) in roots.iter().enumerate() {
        flatten_node(root, 0, i + 1 == roots.len(), expanded, &mut out);
    }
    out
}

fn flatten_node(
    node: &LineageNode,
    depth: usize,
    is_last: bool,
    expanded: &HashSet<String>,
    out: &mut Vec<TreeRow>,
) {
    let is_expanded = expanded.contains(&node.state.state_id);
    out.push(TreeRow {
        state_id: node.state.state_id.clone(),
        depth,
        has_children: !node.children.is_empty(),
        expanded: is_expanded,
        is_last,
    });
    if is_expanded {
        let n = node.children.len();
        for (i, (_, child)) in node.children.iter().enumerate() {
            flatten_node(child, depth + 1, i + 1 == n, expanded, out);
        }
    }
}
