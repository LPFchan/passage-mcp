# Passage rollout and recovery

Deploy the private-vault backend first, the Common Auth gateway next, and open
admission with `0032_open_passage.sql` last. Keep Passage admin-only until each
preceding check passes. Follow LPFchan/auth's
[deploy/RUNBOOK.md](https://github.com/LPFchan/auth/blob/main/deploy/RUNBOOK.md)
for current gateway, worker, D1, and smoke
mechanics; this document owns Passage storage and rollout requirements.

## Storage and key custody

An immutable Common Auth subject selects one private vault, including folders,
search, trash, browser operations, and MCP tools. There is no sharing.
The existing owner's Common Auth subject is `1`. Confirm that mapping against
the authoritative account record before deployment; never infer it from email.
In the production Compose checkout, explicitly set this in `.env`:

```dotenv
LEGACY_OWNER_SUB=1
```

Compose requires this value and passes it to the backend. The existing owner
ciphertext stays at `/var/lib/passage-mcp/store`, mounted at `/store`; its key
stays at `/etc/passage-mcp/age-identity`, mounted read-only at
`/run/secrets/age-identity`. Preserve both files and paths without replacement,
re-encryption, or permission changes. Missing owner configuration or keys must
stop startup; never assign the owner vault to a fallback account.

Create the separate persistent host directories before starting the container:

```sh
sudo install -d -o 1001 -g 1001 -m 0700 /var/lib/passage-mcp/tenants
sudo install -d -o 1001 -g 1001 -m 0700 /etc/passage-mcp/tenant-keys
```

Compose mounts them at `/tenants` and `/tenant-keys`, with `TENANTS_DIR` and
`TENANT_KEYS_DIR` set accordingly. Both roots must remain UID/GID `1001:1001`,
mode `0700`; generated per-user keys must be mode `0600`. Keep the backend
bound to `127.0.0.1:8002`; only the trusted gateway may reach it.

Keys are in server custody: this is not end-to-end encryption. Each new tenant
gets an independent server key as its sole encryption recipient. The existing
owner's additional recovery recipient remains unchanged and does not cover new
tenants. Securely back up tenant keys separately from ciphertext, with restricted
access. Include `.age-recipients` and `.trash` in ciphertext backups. Test restoring
each vault with its matching key in a private temporary environment. Losing a
new tenant's key and its backups makes its ciphertext unrecoverable.

## 1. Validate the backend

Use repo-local `.venv` dependencies and real `age` / `age-keygen` executables:

```sh
.venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest -q --basetemp="$(mktemp -d /tmp/passage-tests.XXXXXXXX)"
docker compose config --quiet
docker compose build
```

The combined HTTP integration test runs the real MCP server, browser routes,
and age encryption. Verify identity-only `/api/session` does not allocate a
vault; missing identity, subject mismatch, and wrong/missing origin fail before
provisioning. Two subjects must independently create/read/update/delete/recover
items and read the same private values through MCP. Owner keys and ciphertext
must remain byte-for-byte unchanged. Also retain tenancy, frontend account-switch,
and local stdio checks. Use disposable stores and dummy secrets for local smoke.

## 2. Deploy backend while admission remains locked

Record backend/gateway versions and registry admission state. Back up the owner
store and key separately and verify restoration. Prepare the tenant directories
and `.env` above, inspect the effective Compose mounts/environment, then run:

```sh
docker compose config --quiet
docker compose up -d --build
docker ps --filter name=passage-mcp --format '{{.Names}} {{.Ports}}'
docker inspect passage-mcp --format '{{json .Mounts}}'
```

Verify loopback binding, persistent mounts, owner readability, and unchanged
owner key/ciphertext. Run a private-listener two-subject smoke with dummy data.
Synthetic trusted identity headers are fixtures only on that private listener.
Do not open admission if storage, key creation, isolation, or recovery checks fail.

## 3. Deploy gateway, then open admission

Follow the auth deploy/RUNBOOK mechanics to deploy the reviewed OCI gateway and
run its smoke matrix. Browser and `/api` use cookie OAuth; `/mcp` uses scope
`passage` and resource `https://passage.lost.plus/mcp`; `/_auth/logout` uses OAuth.
The gateway must strip spoofed credentials/identity headers and inject trusted
percent-encoded `X-Lost-Plus-*` identity. Confirm unsigned browser login redirect,
API 401, owner browser/MCP access, logout, and health probes. Verify the reviewed
health/logout probe fixes are included before attempting gateway deployment.

Inspect pending D1 migrations and apply only the reviewed rollout set using the
auth RUNBOOK. `0032_open_passage.sql` is the final admission change: Passage
becomes `admin_only=0`, group `app`, alias `passage`. Preserve token scope, URLs,
and every visibility grant. Restricted accounts still require an explicit grant;
never clear their allowlists to grant Passage. Publish the homepage listing only
after acceptance succeeds.

## Acceptance and rollback

Use a regular account whose subject differs from `1`: its initial vault must be
empty, browser CRUD/trash and MCP must agree, and the owner vault must stay
unchanged. Verify account switching with pending requests, wrong-subject/origin
refusal, scoped and revoked tokens, logout, and denied restricted accounts.
Record statuses and assertions without secret response bodies; clean up dummy
items through their account's normal tools, including trash.

On failure, first restore Passage `admin_only=1` through the auth RUNBOOK and
verify regular cookie/token access is denied. Stop Passage immediately for
suspected cross-account exposure. Preserve all stores and keys. Restore the
recorded gateway version using auth rollback mechanics. Never run the previous
single-store backend while regular users remain admitted. Restore data only
after verifying matching ciphertext/key backups privately. A recreated account
with a new subject receives a new vault; never reassign old data by email.
