# nginx LAN reverse proxy for the EASTER gateway

`nginx:alpine` terminating TLS with a private-CA certificate, proxying
to the gateway over the shared `easter-lan` Docker network. LAN only —
nothing here is internet-facing, and no port forwarding should ever be
added for it.

## One-time setup (on the Mac)

Replace `LAN_HOSTNAME` everywhere below with the Mac's LAN hostname —
the `.local` name from System Settings → General → About
(e.g. `nathans-macbook.local`).

```bash
# 0. From the repo root, on the docker branch:
git pull origin feature/easter-gateway-docker
cd deploy/nginx

# 1. Private CA + server cert (cert must be issued BEFORE nginx starts,
#    otherwise it fails on the missing files):
brew install mkcert
mkcert -install
mkdir -p certs
mkcert -cert-file certs/easter.crt -key-file certs/easter.key <LAN_HOSTNAME>

# 2. Put the hostname in conf.d/easter.conf (both server_name lines):
sed -i '' 's/LAN_HOSTNAME/<LAN_HOSTNAME>/g' conf.d/easter.conf

# 3. Retire the placeholder container (bare nginx:alpine, no published
#    ports, default config — serves nothing):
docker stop dreamy_visvesvaraya && docker rm dreamy_visvesvaraya

# 4. Bring up the gateway first (creates easter-lan), then nginx:
cd ../docker
docker compose -f docker-compose.yml up -d --build
cd ../nginx
docker compose up -d
```

(`certs/` is gitignored — the private key never gets committed.)

## Verify

From the Mac, trusting the private CA:

```bash
curl --cacert "$(mkcert -CAROOT)/rootCA.pem" https://<LAN_HOSTNAME>/health
# {"ok":true,"service":"easter-gateway-0"}
```

With a minted agent token:

```bash
curl --cacert "$(mkcert -CAROOT)/rootCA.pem" -X POST https://<LAN_HOSTNAME>/tools/get_identity \
  -H "Authorization: Bearer <token>" \
  -H 'Content-Type: application/json' -d '{}'
```

## Clients (other LAN machines)

Install the mkcert root CA from `mkcert -CAROOT` on each client so the
private cert verifies. Then `https://<LAN_HOSTNAME>` just works.

## Notes

- The gateway's `/health` stays public through the proxy; everything
  else needs the bearer token. Token minting/revocation remain
  console-channel only (`docker exec`), never HTTP.
- Keep the Mac firewall on. This is LAN-only by design; exposing it to
  the internet would want a separate hardening pass first.
- `docker compose logs -f` in this directory tails the proxy logs.
