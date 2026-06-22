# CTI MCP Server

Cyber Threat Intelligence MCP server — provides real-time CVE and threat intelligence data from multiple sources via the Model Context Protocol.

## Sources

| Source | Type | Auth Required |
|--------|------|---------------|
| CISA KEV | Known Exploited Vulnerabilities | No |
| GitHub Advisory | Vulnerability database | `GITHUB_TOKEN` (recommended) |
| NVD | National Vulnerability Database | `NVD_API_KEY` (recommended) |
| OSV.dev | Open Source Vulnerabilities | No |
| GitHub PoC | Proof-of-concept exploits | `GITHUB_TOKEN` (recommended) |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `NVD_API_KEY` | Recommended | NVD API 2.0 key. Without it: 5 req/30s rolling (frequent 503s). With it: 50 req/30s. Request at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) |
| `GITHUB_TOKEN` | Recommended | GitHub PAT. Without it: 60 req/h. With it: 5000 req/h |
| `CTI_MCP_DB_PATH` | Optional | Custom SQLite database path |

### Getting API Keys

**NVD API Key:**
1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Fill out the form (free, takes ~5 minutes)
3. You'll receive the key via email
4. Set it: `export NVD_API_KEY="your-key-here"`

**GitHub Token:**
1. Visit https://github.com/settings/tokens
2. Create a fine-grained or classic PAT (no special scopes needed for public data)
3. Set it: `export GITHUB_TOKEN="ghp_your-token-here"`

## Health Check

The `get_status` MCP tool provides a complete system overview:

```json
{
  "tokens": {
    "github_token": "set",
    "nvd_api_key": "set"
  },
  "cache": {
    "cves_count": 4823,
    "kev_count": 1247,
    "populated": true
  },
  "sources": {
    "nvd": { "status": "ok", "entry_count": 3421 },
    "osv": { "status": "ok", "entry_count": 1287 }
  },
  "warnings": []
}
```

### AI Agent Workflow

**Before any data-heavy operation** (`refresh_sources`, `generate_report`, bulk queries), AI agents **must** call `get_status` first:

1. **`warnings` is empty** → all clear, proceed normally
2. **`warnings` is non-empty** → review them and decide: proceed anyway (sources work without keys, just slower) or ask the user to provide missing keys for better results

This prevents wasted work on rate-limited or misconfigured systems.

## Build & Run

```bash
# Build
go build -o cti-mcp ./cmd/cti-mcp

# Run (stdio MCP transport)
NVD_API_KEY="your-key" GITHUB_TOKEN="your-token" ./cti-mcp
```

## Architecture

- **Database:** SQLite (pure-Go `modernc.org/sqlite`, no CGO)
- **Transport:** MCP stdio
- **Caching:** Background refresh with per-source TTL
- **Sources:** 5 independent providers, each with health tracking
