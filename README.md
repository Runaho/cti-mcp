# CTI MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) server that provides real-time Cyber Threat Intelligence — CVEs, CISA KEV entries, exploit data, and vulnerability reports from multiple sources.

Plug it into **Claude Desktop**, **Cursor**, **Hermes**, or any MCP-compatible client.

## Features

- **5 data sources**: CISA KEV, GitHub Security Advisory, GitHub PoC repos, NVD API, OSV.dev
- **SQLite cache** with background refresh — no rate limits, no repeated API calls
- **8 MCP tools**: query CVEs, search vulnerabilities, get KEV entries, generate HTML reports
- **Self-contained HTML report** — neobrutalism design, works offline
- **Pure Go** — single static binary, no CGO, no runtime dependencies

## Install

### Option 1: `go install` (requires Go 1.25+)

```bash
go install github.com/Runaho/cti-mcp/cmd/cti-mcp@latest
```

### Option 2: Homebrew

```bash
brew install runaho/tap/cti-mcp
```

### Option 3: Docker

```bash
docker run -d --name cti-mcp \
  -e GITHUB_TOKEN=ghp_xxxxx \
  -v cti-data:/data \
  ghcr.io/runaho/cti-mcp:latest
```

### Option 4: Download binary

Grab the latest release from [GitHub Releases](https://github.com/Runaho/cti-mcp/releases).

## Configuration

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cti": {
      "command": "cti-mcp",
      "env": {
        "GITHUB_TOKEN": "ghp_xxxxx"
      }
    }
  }
}
```

### Cursor

Add to your MCP settings:

```json
{
  "mcpServers": {
    "cti": {
      "command": "cti-mcp",
      "env": {
        "GITHUB_TOKEN": "ghp_xxxxx"
      }
    }
  }
}
```

### Hermes

```yaml
# ~/.hermes/config.yaml
mcp_servers:
  cti:
    command: cti-mcp
    env:
      GITHUB_TOKEN: "ghp_xxxxx"
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN` | (none) | GitHub API token. Without it, rate limited to 60 req/h. With it, 5000 req/h. **Strongly recommended.** |
| `CTI_MCP_DB_PATH` | `~/.cti-mcp/cti.db` | SQLite database path |
| `CTI_MCP_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |

## Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `get_recent_cves` | `hours`, `severity`, `limit` | Recent CVEs within a time window |
| `get_kev_entries` | `recent_days`, `limit` | CISA KEV catalog — actively exploited vulnerabilities |
| `get_cve_details` | `cve_id` | Full details for a specific CVE |
| `search_vulnerabilities` | `keyword`, `product`, `cwe`, `limit` | Search by keyword, product, or CWE |
| `get_exploited` | `limit` | CVEs that are in KEV and/or have PoC code |
| `generate_report` | `hours`, `format` | Full HTML threat intelligence report |
| `get_status` | — | Server health, cache status, token config |
| `refresh_sources` | `source` | Force refresh data from sources |

## How It Works

```
MCP Client (Claude/Cursor/Hermes)
        │ stdio (JSON-RPC)
        ▼
   cti-mcp Server
   ├── 8 MCP Tools
   ├── Background Cache (goroutines)
   │   ├── CISA KEV     → every 1h
   │   ├── GitHub Adv   → every 30m
   │   ├── GitHub PoC   → every 2h
   │   ├── NVD          → every 1h
   │   └── OSV.dev      → every 1h
   └── SQLite Store (~/.cti-mcp/cti.db)
       ├── cves         (JSON blob + indexed columns)
       ├── kev_entries
       └── source_health
```

Data is cached in SQLite with TTL-based background refresh. The first call after startup may be slightly slow while the cache populates. Use `get_status` to check progress.

## Data Sources

| Source | URL | Refresh | Notes |
|--------|-----|---------|-------|
| CISA KEV | `cisa.gov/known_exploited_vulnerabilities.json` | 1h | Always available, ~1600+ entries |
| GitHub Advisory | `api.github.com/advisories` | 30m | CRITICAL + HIGH, needs token for rate limits |
| GitHub PoC | `api.github.com/search/repositories` | 2h | Exploit/PoC repos with CVE IDs |
| NVD API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0` | 1h | Frequent 503s, fallback sources compensate |
| OSV.dev | `api.osv.dev/v1/query` | 1h | Go, PyPI, npm, Maven ecosystems |

## Development

```bash
# Build
go build -o cti-mcp ./cmd/cti-mcp

# Test
go test ./...

# Run locally
./cti-mcp serve

# Run with custom DB path
CTI_MCP_DB_PATH=/tmp/test.db ./cti-mcp serve
```

## License

MIT
