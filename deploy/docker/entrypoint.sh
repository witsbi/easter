#!/bin/sh
# First-run provisioning for the EASTER gateway container, then exec the server.
#
#   1. Seed a fresh kernel DB at /data/kernel.db (never overwrites an
#      existing one). The root identity is $EASTER_ROOT_IDENTITY.
#   2. Generate a self-signed cert/key for the loopback TLS that
#      `gateway.py serve` requires. Loopback-only + self-signed is fine
#      for local agents; real TLS / LAN exposure is later work.
#   3. Exec the gateway on 0.0.0.0:8443 *inside* the container.
#      Host-side binding stays loopback-only via the compose `ports:`
#      entry -- the container listening on 0.0.0.0 is not LAN exposure.
set -eu

DATA=/data

if [ ! -f "$DATA/kernel.db" ]; then
    python - "$DATA/kernel.db" "${EASTER_ROOT_IDENTITY:-identity:nathan}" <<'EOF'
import sys
from initialize import initialize_database

db_path, root_id = sys.argv[1], sys.argv[2]
initialize_database(
    db_path,
    root_id,
    root_identity_payload={"role": "root_human", "note": "EASTER root"},
)
print(f"initialized fresh kernel db at {db_path} with root {root_id}", flush=True)
EOF
fi

if [ ! -f "$DATA/cert.pem" ] || [ ! -f "$DATA/key.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$DATA/key.pem" -out "$DATA/cert.pem" -days 825 \
        -subj "/CN=easter-gateway" \
        -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
    chmod 600 "$DATA/key.pem"
    chmod 644 "$DATA/cert.pem"
fi

exec python gateway.py serve \
    --host 0.0.0.0 --port 8443 \
    --cert "$DATA/cert.pem" --key "$DATA/key.pem" \
    --sessions "$DATA/sessions.json" \
    --kernel-db "$DATA/kernel.db"
