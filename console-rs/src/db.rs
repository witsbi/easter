//! Read-only SQLite access to an EASTER kernel database.
//!
//! The console never writes: the connection is opened with
//! SQLITE_OPEN_READ_ONLY, and every query here is a SELECT.

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};

// ---------------------------------------------------------------------------
// Row types (one per kernel table)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct StateRow {
    pub state_id: String,
    pub created_at: String,
    pub payload: String,
}

#[derive(Debug, Clone)]
pub struct TransitionRow {
    pub transition_id: String,
    pub from_state_id: String,
    pub to_state_id: String,
    pub authority_grant_id: String,
    pub created_at: String,
    pub payload: String,
}

#[derive(Debug, Clone)]
pub struct ReceiptRow {
    pub receipt_seq: i64,
    pub receipt_id: String,
    pub operation_id: String,
    pub transition_id: Option<String>,
    pub outcome: String,
    pub created_at: String,
    pub payload: String,
}

#[derive(Debug, Clone)]
pub struct EvidenceRow {
    pub evidence_id: String,
    pub created_at: String,
    pub payload: String,
}

#[derive(Debug, Clone)]
pub struct GrantRow {
    pub grant_id: String,
    pub authority_seq: i64,
    pub identity_id: String,
    pub authority_id: String,
    pub granted_by: Option<String>,
    pub created_at: String,
    pub valid_from: String,
    pub expires_at: Option<String>,
    pub payload: String,
}

#[derive(Debug, Clone)]
pub struct RevocationRow {
    pub revocation_id: String,
    pub authority_seq: i64,
    pub kind: String,
    pub grant_id: Option<String>,
    pub identity_id: Option<String>,
    pub caused_by: String,
    pub authority_grant_id: String,
    pub created_at: String,
    pub payload: String,
}

#[derive(Debug, Clone)]
pub struct IdentityRow {
    pub identity_id: String,
    pub created_at: String,
    pub payload: String,
}

#[derive(Debug, Clone)]
pub struct AuthorityRow {
    pub authority_id: String,
    pub created_at: String,
    pub is_root: bool,
    pub payload: String,
}

#[derive(Debug, Clone)]
pub struct ExceptionRow {
    pub exception_id: String,
    pub receipt_id: String,
    pub created_at: String,
    pub payload: String,
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

pub struct Db {
    conn: Connection,
}

impl Db {
    /// Open read-only. Fails cleanly if the file is missing or not a DB.
    pub fn open_read_only(path: &str) -> Result<Self> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_context(|| format!("cannot open EASTER database (read-only): {path}"))?;
        // A quick probe so a non-kernel SQLite file fails fast with a
        // clear message instead of surfacing later as empty views.
        conn.query_row("SELECT COUNT(*) FROM states", [], |r| r.get::<_, i64>(0))
            .context("not an EASTER kernel database (no states table)")?;
        Ok(Self { conn })
    }

    fn all<T, F>(&self, sql: &str, map: F) -> Result<Vec<T>>
    where
        F: Fn(&rusqlite::Row) -> rusqlite::Result<T>,
    {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt
            .query_map([], &map)?
            .collect::<rusqlite::Result<Vec<T>>>()?;
        Ok(rows)
    }

    pub fn states(&self) -> Result<Vec<StateRow>> {
        self.all(
            "SELECT state_id, created_at, payload FROM states ORDER BY created_at",
            |r| {
                Ok(StateRow {
                    state_id: r.get(0)?,
                    created_at: r.get(1)?,
                    payload: r.get(2)?,
                })
            },
        )
    }

    pub fn transitions(&self) -> Result<Vec<TransitionRow>> {
        self.all(
            "SELECT transition_id, from_state_id, to_state_id, authority_grant_id,
                    created_at, payload
             FROM transitions ORDER BY created_at",
            |r| {
                Ok(TransitionRow {
                    transition_id: r.get(0)?,
                    from_state_id: r.get(1)?,
                    to_state_id: r.get(2)?,
                    authority_grant_id: r.get(3)?,
                    created_at: r.get(4)?,
                    payload: r.get(5)?,
                })
            },
        )
    }

    pub fn receipts(&self) -> Result<Vec<ReceiptRow>> {
        self.all(
            "SELECT receipt_seq, receipt_id, operation_id, transition_id,
                    outcome, created_at, payload
             FROM receipts ORDER BY receipt_seq",
            |r| {
                Ok(ReceiptRow {
                    receipt_seq: r.get(0)?,
                    receipt_id: r.get(1)?,
                    operation_id: r.get(2)?,
                    transition_id: r.get(3)?,
                    outcome: r.get(4)?,
                    created_at: r.get(5)?,
                    payload: r.get(6)?,
                })
            },
        )
    }

    pub fn evidence(&self) -> Result<Vec<EvidenceRow>> {
        self.all(
            "SELECT evidence_id, created_at, payload FROM evidence ORDER BY created_at",
            |r| {
                Ok(EvidenceRow {
                    evidence_id: r.get(0)?,
                    created_at: r.get(1)?,
                    payload: r.get(2)?,
                })
            },
        )
    }

    pub fn grants(&self) -> Result<Vec<GrantRow>> {
        self.all(
            "SELECT grant_id, authority_seq, identity_id, authority_id,
                    granted_by_identity_id, created_at, valid_from, expires_at, payload
             FROM authority_grants ORDER BY authority_seq",
            |r| {
                Ok(GrantRow {
                    grant_id: r.get(0)?,
                    authority_seq: r.get(1)?,
                    identity_id: r.get(2)?,
                    authority_id: r.get(3)?,
                    granted_by: r.get(4)?,
                    created_at: r.get(5)?,
                    valid_from: r.get(6)?,
                    expires_at: r.get(7)?,
                    payload: r.get(8)?,
                })
            },
        )
    }

    pub fn revocations(&self) -> Result<Vec<RevocationRow>> {
        self.all(
            "SELECT revocation_id, authority_seq, kind, grant_id, identity_id,
                    caused_by_identity_id, authority_grant_id, created_at, payload
             FROM authority_grant_revocations ORDER BY authority_seq",
            |r| {
                Ok(RevocationRow {
                    revocation_id: r.get(0)?,
                    authority_seq: r.get(1)?,
                    kind: r.get(2)?,
                    grant_id: r.get(3)?,
                    identity_id: r.get(4)?,
                    caused_by: r.get(5)?,
                    authority_grant_id: r.get(6)?,
                    created_at: r.get(7)?,
                    payload: r.get(8)?,
                })
            },
        )
    }

    pub fn identities(&self) -> Result<Vec<IdentityRow>> {
        self.all(
            "SELECT identity_id, created_at, payload FROM identities ORDER BY created_at",
            |r| {
                Ok(IdentityRow {
                    identity_id: r.get(0)?,
                    created_at: r.get(1)?,
                    payload: r.get(2)?,
                })
            },
        )
    }

    pub fn authorities(&self) -> Result<Vec<AuthorityRow>> {
        self.all(
            "SELECT authority_id, created_at, is_root, payload FROM authorities ORDER BY created_at",
            |r| {
                Ok(AuthorityRow {
                    authority_id: r.get(0)?,
                    created_at: r.get(1)?,
                    is_root: r.get::<_, i64>(2)? != 0,
                    payload: r.get(3)?,
                })
            },
        )
    }

    pub fn exceptions(&self) -> Result<Vec<ExceptionRow>> {
        self.all(
            "SELECT exception_id, receipt_id, created_at, payload FROM exceptions ORDER BY created_at",
            |r| {
                Ok(ExceptionRow {
                    exception_id: r.get(0)?,
                    receipt_id: r.get(1)?,
                    created_at: r.get(2)?,
                    payload: r.get(3)?,
                })
            },
        )
    }

    /// Evidence IDs cited in support of a receipt.
    pub fn evidence_for_receipt(&self, receipt_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT evidence_id FROM receipt_evidence WHERE receipt_id = ?1")?;
        let ids = stmt
            .query_map([receipt_id], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(ids)
    }

    /// Receipt IDs that cite a given evidence record.
    pub fn receipts_citing_evidence(&self, evidence_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT receipt_id FROM receipt_evidence WHERE evidence_id = ?1")?;
        let ids = stmt
            .query_map([evidence_id], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(ids)
    }
}
