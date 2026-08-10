# vaultwarden-mcp-server

MCP server that lets AI agents retrieve secrets from Vaultwarden without ever holding Vaultwarden credentials.

The server uses the official MCP Python SDK v2 and supports the
`2026-07-28` stateless protocol via `server/discover`, with a stateless legacy
fallback for clients that still use `initialize`.

## Architecture

```
AI Agent harness
   |  stdio
   v
MCP Server ---- HTTP ---- Vaultwarden (Docker)
   |                          |
   |   OAuth2 token           |
   +-- client_id/secret ------+  Folders of login items
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
