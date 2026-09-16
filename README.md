# passage-mcp

MCP server that lets AI agents read and manage secrets kept in an
[age](https://age-encryption.org)-encrypted [passage](https://github.com/FiloSottile/passage)
store. Secrets are ciphertext on disk. The server holds no key material of its
own: it shells out to `age` with the path of an identity file.

The name is historical. Until September 2026 this served secrets out of a
Vaultwarden instance, where they sat in plaintext. See DESIGN below.

The server uses the official MCP Python SDK v2 and supports the
`2026-07-28` stateless protocol via `server/discover`, with a stateless legacy
fallback for clients that still use `initialize`.

The production HTTP endpoint is `https://vault.lost.plus/mcp`. The shared
Common Auth gateway protects it with the `passage` scope. Send a
Common Auth token as `Authorization: Bearer <token>` or `X-API-Key: <token>`.
The HTTP backend does not authenticate requests itself and must remain bound to
localhost behind the gateway. Stdio clients are unaffected.

## Architecture

```
AI Agent harness ---- HTTPS/Common Auth ---- MCP Server ---- age ---- <store>/<folder>/<name>.age
                                                              |
                                                     identity file (read-only)
```

Store layout is passage's, so `passage ls`, `passage show folder/name`, and
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

Two age identities, both listed in `.age-recipients`:

- **Server key.** Its identity file lives outside the store, readable by the
  container user. The server decrypts with it at every read.
- **Recovery key.** Its identity is kept off the box by the operator. If the
  server key is lost, `age -d -i <recovery-identity> <file>.age` still works,
  and a new server key can be added to `.age-recipients` followed by
  `passage reencrypt`.

Startup fails if the server identity's public key is missing from
`.age-recipients`, since new writes would then be unreadable.

## Deployment (oci-ubuntu)

| Path | Purpose | Owner / mode |
| --- | --- | --- |
| `/var/lib/passage-mcp/store` | the store (ciphertext only) | `1001:1001` `750` |
| `/etc/passage-mcp/age-identity` | server identity | `root:1001` `640` |
| `./config/config.json` | `allowed_folders` | repo, gitignored |

```
docker compose up -d --build
```

Back up the store directory freely. Never back up the identity file next to it.

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

`age` must be on `PATH`.

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
