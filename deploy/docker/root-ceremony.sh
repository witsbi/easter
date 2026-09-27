#!/bin/sh
# Root ceremony for the containerized EASTER gateway (GATEWAY-0).
#
# Run from the repository root:
#   sh deploy/docker/root-ceremony.sh
#
# There is no human-auth code path in the gateway. You, as root, perform
# this ceremony through the console channel (docker compose exec against
# the container's kernel database). The script prints what each step
# does and waits for your confirmation before running it -- nothing is
# hidden, and every step is yours to approve or skip.
#
# Preconditions: the stack is up and healthy:
#   docker compose -f deploy/docker/docker-compose.yml up -d --build
#   curl -k https://127.0.0.1:8443/health
set -eu

COMPOSE="docker compose -f deploy/docker/docker-compose.yml"
ROOT_IDENTITY="${EASTER_ROOT_IDENTITY:-identity:nathan}"

step() { printf '\n=== %s ===\n' "$1"; }

confirm() {
    # confirm "prompt" -> exit status 0 on yes
    printf '%s [y/N] ' "$1"
    read reply || return 1
    case "$reply" in
        [Yy]*) return 0 ;;
        *) return 1 ;;
    esac
}

prompt() {
    # prompt "message" "default" -> sets ANSWER
    printf '%s [%s]: ' "$1" "$2"
    read ANSWER || ANSWER=""
    [ -n "$ANSWER" ] || ANSWER="$2"
}

step "0. Preconditions"
if curl -sk --max-time 5 https://127.0.0.1:8443/health | grep -q '"ok":true'; then
    echo "gateway is up: https://127.0.0.1:8443/health answers"
else
    echo "gateway is not answering https://127.0.0.1:8443/health" >&2
    echo "start it first:" >&2
    echo "  $COMPOSE up -d --build" >&2
    exit 1
fi

step "1. Create the gateway identity"
echo "Root-authorized transition: $ROOT_IDENTITY (holding grant:genesis-root)"
echo "creates identity:gateway from state:genesis. Skipped if it exists."
if confirm "Run it?"; then
    # -T: stdin is a pipe (the heredoc), not a TTY.
    $COMPOSE exec -T gateway python - "$ROOT_IDENTITY" <<'EOF'
import sys
from kernel import Kernel
root_id = sys.argv[1]
k = Kernel("/data/kernel.db")
if k.get_identity("identity:gateway"):
    print("identity:gateway already exists -- skipping creation")
else:
    k.transition(
        requester_identity_id=root_id,
        from_state_id="state:genesis",
        authority_grant_id="grant:genesis-root",
        new_state_payload={"gateway": "provisioned"},
        transition_payload={"reason": "gateway identity bootstrap"},
        new_identities=[{"identity_id": "identity:gateway",
                         "payload": {"role": "gateway"}}],
    )
    print("identity:gateway created")
EOF
fi

step "2. Grant the gateway its expiring root lease"
echo "Expiry is the dead-man's switch; revocation is the kill switch."
prompt "Lease length in days" "30"
LEASE_DAYS="$ANSWER"
LEASE_GRANT_ID=""
if confirm "Grant authority:root to identity:gateway for ${LEASE_DAYS} days?"; then
    LEASE_GRANT_ID=$($COMPOSE exec -T gateway python - "$LEASE_DAYS" "$ROOT_IDENTITY" <<'EOF'
import sys
from datetime import datetime, timedelta, timezone
from kernel import Kernel
days, root_id = int(sys.argv[1]), sys.argv[2]
k = Kernel("/data/kernel.db")
expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat().replace("+00:00", "Z")
g = k.grant(
    requester_identity_id=root_id,
    authority_grant_id="grant:genesis-root",
    identity_id="identity:gateway",
    authority_id="authority:root",
    expires_at=expires,
    payload={"role": "gateway-lease", "note": "EASTER-GATEWAY-0 root lease"},
)
print(g["grant_id"])
print("expires " + expires, file=sys.stderr)
EOF
)
    echo "lease grant: $LEASE_GRANT_ID"
fi

step "3. Provision the agent"
echo "An agent needs its OWN kernel identity and its OWN grant."
echo "Grants are identity-bound: the kernel rejects an identity wielding"
echo "another identity's grant, so the gateway's lease cannot be reused."
prompt "Agent identity id" "identity:hermes"
AGENT_ID="$ANSWER"

if confirm "Create $AGENT_ID in the kernel (skipped if it exists)?"; then
    $COMPOSE exec -T gateway python - "$AGENT_ID" "$ROOT_IDENTITY" <<'EOF'
import sys
from kernel import Kernel
agent_id, root_id = sys.argv[1], sys.argv[2]
k = Kernel("/data/kernel.db")
if k.get_identity(agent_id):
    print(f"{agent_id} already exists -- skipping creation")
else:
    k.transition(
        requester_identity_id=root_id,
        from_state_id="state:genesis",
        authority_grant_id="grant:genesis-root",
        new_state_payload={"agent": agent_id},
        transition_payload={"reason": "agent identity bootstrap"},
        new_identities=[{"identity_id": agent_id,
                         "payload": {"role": "agent"}}],
    )
    print(f"{agent_id} created")
EOF
fi

prompt "Agent grant length in days" "30"
AGENT_DAYS="$ANSWER"
AGENT_GRANT_ID=""
echo "This issues a grant of authority:root to $AGENT_ID, valid ${AGENT_DAYS} days."
echo "That is full kernel authority through the channel: the agent can do"
echo "anything root can while the grant is live. Expiry is the dead-man's"
echo "switch; revocation is the kill switch."
if confirm "Issue the agent grant?"; then
    AGENT_GRANT_ID=$($COMPOSE exec -T gateway python - "$AGENT_DAYS" "$ROOT_IDENTITY" "$AGENT_ID" <<'EOF'
import sys
from datetime import datetime, timedelta, timezone
from kernel import Kernel
days, root_id, agent_id = int(sys.argv[1]), sys.argv[2], sys.argv[3]
k = Kernel("/data/kernel.db")
expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat().replace("+00:00", "Z")
g = k.grant(
    requester_identity_id=root_id,
    authority_grant_id="grant:genesis-root",
    identity_id=agent_id,
    authority_id="authority:root",
    expires_at=expires,
    payload={"role": "agent-grant", "note": "EASTER-GATEWAY-0 agent authority"},
)
print(g["grant_id"])
print("expires " + expires, file=sys.stderr)
EOF
)
    echo "agent grant: $AGENT_GRANT_ID"
fi

step "4. Mint the agent token"
echo "The token prints ONCE -- have somewhere to store it."
prompt "Role" "agent"
AGENT_ROLE="$ANSWER"
prompt "Token TTL in seconds" "86400"
AGENT_TTL="$ANSWER"
if [ -z "$AGENT_GRANT_ID" ]; then
    echo "no agent grant was issued -- skipping the mint. Re-run when ready." >&2
elif confirm "Mint token for $AGENT_ID (grant: $AGENT_GRANT_ID, role: $AGENT_ROLE, ttl: ${AGENT_TTL}s)?"; then
    echo "--- token: store it now ---"
    $COMPOSE exec -T gateway python gateway.py mint \
        --identity "$AGENT_ID" --grants "$AGENT_GRANT_ID" \
        --role "$AGENT_ROLE" --ttl "$AGENT_TTL" \
        --sessions /data/sessions.json
    echo "---------------------------"
fi

step "Done"
cat <<EOF
Channel test:
  curl -k -X POST https://127.0.0.1:8443/tools/get_identity \\
    -H "Authorization: Bearer <token>" \\
    -H 'Content-Type: application/json' -d '{}'

Kill switches:
  Revoke one agent token:
    $COMPOSE exec -T gateway python gateway.py revoke-token <token-or-prefix> --sessions /data/sessions.json
  Revoke the agent's authority (the grant itself, via the console channel):
    kernel revoke on the agent grant id; every later write with it fails.
  Revoke the gateway's power (invalidates grants it HOLDS, not grants it issued):
    kernel revoke_all on identity:gateway through this same console channel,
    then revoke affected agent identities individually if the fleet itself
    is suspect. Every revoke leaves a receipt.

Reset (destroys everything, including the kernel DB):
  $COMPOSE down -v
EOF
