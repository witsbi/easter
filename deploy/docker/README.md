# EASTER gateway on Docker (Mac)

Runs the GATEWAY-0 authenticated agent channel in a container with host
isolation: its own filesystem view, a non-root user, a private kernel
database, and a port published on loopback only.

## Start

From the repository root:

```bash
docker compose -f deploy/docker/docker-compose.yml up -d --build
```

First run seeds `/data` (a named volume, so it survives rebuilds):

- a fresh kernel database with root identity `identity:nathan`
  (override with `EASTER_ROOT_IDENTITY` **before** the first start), and
- a self-signed cert/key for the loopback TLS `gateway.py serve` requires.

Verify:

```bash
curl -k https://127.0.0.1:8443/health
# {"ok":true,"service":"easter-gateway-0"}
```

Logs: `docker compose -f deploy/docker/docker-compose.yml logs -f`

## Root ceremony: the gateway's lease

Per the design, there is no human-auth code path in the gateway. Nathan
as root performs the ceremony through the console channel -- here, that
is `docker compose exec` against the container's kernel database.

The guided script walks the three steps below, printing every command
and waiting for confirmation at each one. Run from the repo root:

```bash
sh deploy/docker/root-ceremony.sh
```

The manual equivalents (what the script runs) are documented here for
reference.

**1. Create the gateway identity** (root-authorized transition):

```bash
docker compose -f deploy/docker/docker-compose.yml exec gateway python - <<'EOF'
from kernel import Kernel
k = Kernel("/data/kernel.db")
k.transition(
    requester_identity_id="identity:nathan",
    from_state_id="state:genesis",
    authority_grant_id="grant:genesis-root",
    new_state_payload={"gateway": "provisioned"},
    transition_payload={"reason": "gateway identity bootstrap"},
    new_identities=[{"identity_id": "identity:gateway",
                     "payload": {"role": "gateway"}}],
)
print("identity:gateway created")
EOF
```

**2. Grant the gateway its expiring root lease.** Expiry is the
dead-man's switch; revocation is the kill switch. Thirty days here --
pick your own window:

```bash
docker compose -f deploy/docker/docker-compose.yml exec gateway python - <<'EOF'
from kernel import Kernel
from datetime import datetime, timedelta, timezone
k = Kernel("/data/kernel.db")
expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat().replace("+00:00", "Z")
g = k.grant(
    requester_identity_id="identity:nathan",
    authority_grant_id="grant:genesis-root",
    identity_id="identity:gateway",
    authority_id="authority:root",
    expires_at=expires,
    payload={"role": "gateway-lease", "note": "EASTER-GATEWAY-0 root lease"},
)
print("lease grant:", g["grant_id"], "expires", expires)
EOF
```

**3. Mint an agent token.** First give the agent its OWN identity and its
OWN grant (same pattern as above; grants are identity-bound, so the
gateway's lease grant cannot be reused — the kernel rejects an identity
wielding another identity's grant), then:

```bash
docker compose -f deploy/docker/docker-compose.yml exec gateway \
  python gateway.py mint --identity identity:worker \
  --grants <grant-id> --role agent --sessions /data/sessions.json
```

The token prints **once** -- store it with the agent. Only its hash is
kept server-side.

**4. Test the channel:**

```bash
curl -k -X POST https://127.0.0.1:8443/tools/get_identity \
  -H "Authorization: Bearer <token>" \
  -H 'Content-Type: application/json' -d '{}'
```

## Kill switches

- Revoke one agent token:
  `docker compose ... exec gateway python gateway.py revoke-token <token-or-prefix> --sessions /data/sessions.json`
- Revoke the gateway's power (invalidates grants it *holds*, not grants
  it *issued*): kernel `revoke_all` on `identity:gateway` via the console
  channel, then revoke affected agent identities individually if the
  fleet itself is suspect. Every revoke leaves a receipt.

## Reset (destroys everything)

```bash
docker compose -f deploy/docker/docker-compose.yml down -v
```

`-v` deletes the `easter-data` volume: kernel DB, sessions, and cert.
The next `up` re-seeds from scratch.

## Notes and deferred work

- The port is published on `127.0.0.1` only. LAN exposure needs real
  TLS certificates and host hardening first -- deliberately not here.
- The cert is self-signed: use `curl -k` / `verify=False` for now.
- Python dependencies for the container are pinned in
  `deploy/docker/requirements-gateway.txt` (mcp via `requirements-mcp.txt`,
  plus explicit starlette/uvicorn pins so the build doesn't float on mcp's
  open version ranges). Re-resolve before bumping mcp.
- To front an *existing* kernel DB instead of a fresh one, replace the
  named volume with a bind mount of the DB file. SQLite handles the
  container/host multi-process access, but take a backup first.
