# passage-mcp

MCP server that lets AI agents read and manage secrets kept in an
[age](https://age-encryption.org)-encrypted [passage](https://github.com/FiloSottile/passage)
store. Each Common Auth account has a private vault, selected by its immutable
account subject. Version 1 has no sharing. Secrets are age ciphertext on disk;
the server holds the decryption identities separately and decrypts on request.
This is server-side key custody, not end-to-end encryption.

The name is historical. Until September 2026 this served secrets out of a
Vaultwarden instance, where they sat in plaintext. See DESIGN below.

The server uses the official MCP Python SDK v2 and supports the
`2026-07-28` stateless protocol via `server/discover`, with a stateless legacy
fallback for clients that still use `initialize`.

The browser app is `https://passage.lost.plus/`. Sign in through Common Auth;
browser API requests use its session cookie on the same origin. The MCP endpoint
is `https://passage.lost.plus/mcp`, protected by the `passage` scope. MCP clients
use Common Auth OAuth or a Common Auth token as `Authorization: Bearer <token>`
or `X-API-Key: <token>`. Service restrictions set by an administrator still apply.
The gateway injects the account identity; the backend must remain on a private
loopback port behind it. Local stdio uses the configured local store.

General availability requires the coordinated rollout in [DEPLOYMENT.md](DEPLOYMENT.md).
Do not open hub admission until the isolated backend is deployed and verified.

## Architecture

```
AI Agent harness ---- HTTPS/Common Auth ---- MCP Server ---- age ---- <store>/<folder>/<name>.age
                                                              |
                                                     separate server identities
```

Each vault uses passage's store layout, so `passage ls`, `passage show folder/name`, and
`passage insert` work on the same directory from a shell.

```
<store>/.age-recipients        public keys every entry is encrypted to
<store>/<folder>/<name>.age    one secret; plaintext is JSON {"password", "username"}
<store>/.trash/<folder>/...    soft-deleted entries
```

Exactly one `.age-recipients` file is allowed, at the store root. Move and
rename are plain file renames and never re-encrypt, so per-folder recipient
files are rejected at startup.

## Keys

The existing owner vault has two age recipients listed in `.age-recipients`:

- **Server key.** Its identity file lives outside the store, readable by the
  container user. The server decrypts with it at every read.
- **Recovery key.** Its identity is kept off the box by the operator. If the
  server key is lost, `age -d -i <recovery-identity> <file>.age` still works,
  and a new server key can be added to `.age-recipients` followed by
  `passage reencrypt`.

Startup fails if the server identity's public key is missing from
`.age-recipients`, since new writes would then be unreadable.

Other accounts receive separate stores and server identities on their first
vault operation. New vaults currently encrypt only to their server key; they
have no additional recovery recipient. Back up these keys securely and separately
from ciphertext. Losing a server key and its backups makes that vault unrecoverable.

## Deployment (oci-ubuntu)

See [DEPLOYMENT.md](DEPLOYMENT.md) for owner mapping, separate persistent
ciphertext/key directories, rollout gates, verification, and rollback.
The existing owner store stays at `/var/lib/passage-mcp/store` and its server
identity at `/etc/passage-mcp/age-identity`.

Back up all vault ciphertext, including `.age-recipients` and `.trash`, and keep
matching key backups separately with restricted access. Test restoration using
an isolated copy. Ciphertext backups alone cannot restore a vault after key loss.

## Stdio / local use

Defaults follow passage: store at `~/.passage/store`, identity at
`~/.passage/identities`. Override with `SECRETS_STORE_DIR` and
`AGE_IDENTITY_FILE`, or `store_dir` / `identity_file` in the config file.

```json
{
  "mcpServers": {
    "passage": {
      "command": "uvx",
      "args": ["passage-mcp-server", "--stdio", "--config", "~/.config/passage-mcp/config.json"]
    }
  }
}
```

`age` must be on `PATH`; HTTP tenant provisioning also requires `age-keygen`.

## Tools

Reads: `get_secret`, `get_login`, `list_secrets`, `list_folders`, `search_secrets`, `list_trash`
Writes: `add_secret`, `add_login`, `edit_secret`, `rename_secret`, `move_secret`, `delete_secret`, `recover_secret`, `empty_trash`, `add_folder`, `rename_folder`, `delete_folder`

`delete_secret` moves the entry to `.trash`; `empty_trash` removes it for good.

## Tests

```
.venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```

Tests need `age` and `age-keygen` on `PATH`.

## DESIGN

Bitwarden's model is client-side encryption; the server stores what clients
send. The previous MCP server wrote raw strings into fields real clients
expect to be ciphertext, so the Vaultwarden database held every secret in
plaintext and the web UI could not read them. Alternatives surveyed in
September 2026: implementing Bitwarden's crypto in this server, `bw serve`,
rbw, Bitwarden's Agent Access SDK, Infisical, OpenBao. passage was chosen
because the crypto and file format are age's, the store is a directory of
files, and the server is glue around four operations.
