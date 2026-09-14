# vaultwarden-mcp-server

MCP server that lets AI agents retrieve secrets from Vaultwarden without ever holding Vaultwarden credentials.

The server uses the official MCP Python SDK v2 and supports the
`2026-07-28` stateless protocol via `server/discover`, with a stateless legacy
fallback for clients that still use `initialize`.

The production HTTP endpoint is `https://vault.lost.plus/mcp`. The shared
Common Auth gateway protects it with the `vaultwarden-secrets` scope. Send a
Common Auth token as `Authorization: Bearer <token>` or `X-API-Key: <token>`.
The HTTP backend does not authenticate requests itself and must remain bound to
localhost behind the gateway. Stdio clients are unaffected.
Standalone HTTP runs default to loopback; the container explicitly binds
`0.0.0.0` only inside its loopback-published Docker boundary.

## Architecture

```
AI Agent harness ---- HTTPS/Common Auth ---- MCP Server ---- HTTP ---- Vaultwarden
                                      |                       |
                                      |   OAuth2 token        |
                                      +-- client_id/secret ---+  Folders of login items
```

## Setup

1. Run Vaultwarden and create secrets (see spec)
2. Create `~/.config/vaultwarden-mcp/config.json`
3. Register in your MCP harness:

```json
{
  "mcpServers": {
    "vaultwarden-secrets": {
      "command": "uvx",
      "args": ["vaultwarden-mcp-server", "--config", "~/.config/vaultwarden-mcp/config.json"]
    }
  }
}
```

## Tools

- `get_secret(folder, item_name)` — retrieve a secret
- `list_secrets(folder?)` — list available secrets
