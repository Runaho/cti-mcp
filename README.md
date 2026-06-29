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

## MCP Tools

### `get_recent_cves`
Get recent CVEs within a time window, filtered by severity.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hours` | int | 24 | Time window in hours |
| `severity` | string | ALL | Filter: CRITICAL, HIGH, MEDIUM, LOW, ALL |
| `limit` | int | 20 | Max results (max 100) |

```json
{ "hours": 24, "severity": "CRITICAL,HIGH", "limit": 50 }
```

### `get_kev_entries`
Get CISA KEV (Known Exploited Vulnerabilities) catalog entries.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `recent_days` | int | 30 | Filter to entries added in the last N days (0 for all) |
| `limit` | int | 50 | Max results |

```json
{ "recent_days": 2, "limit": 100 }
```

### `get_exploited`
Get highest-risk CVEs: actively exploited (KEV) and/or have public PoC exploit code. Sorted by CVSS score descending.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 20 | Max results (max 100) |
| `since_hours` | int | 0 | Time window in hours (0 = all time) |

```json
{ "limit": 50, "since_hours": 168 }
```

### `generate_report`
Generate a full HTML threat intelligence report with sectors, filters, KEV entries, and CVE details.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hours` | int | 24 | Time window in hours |
| `format` | string | html | Output format: html or markdown |

```json
{ "hours": 24, "format": "html" }
```

### Other Tools
- `get_cve_details` — Full details for a specific CVE by ID
- `search_vulnerabilities` — Search CVEs by keyword, product, or CWE
- `refresh_sources` — Force refresh data from all or specific sources
- `get_status` — Health check, cache status, token config

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

## Cron Job Example (Daily Threat Report)

```bash
# Via Hermes cron (no_agent script)
hermes cron create \
  --name "cti-threat-report" \
  --schedule "0 9 * * *" \
  --script "cti-report.py" \
  --no-agent \
  --deliver "telegram"
```

The `cti-report.py` script (in `~/.hermes/scripts/`):
1. Starts `cti-mcp` subprocess via stdio
2. Calls `refresh_sources` for fresh data
3. Calls `generate_report` with `hours=24`
4. Saves HTML to `~/projects/cti-mcp/reports/`
5. Emits `MEDIA:` path for Telegram delivery

Script accepts optional hours argument:
```bash
python3 ~/.hermes/scripts/cti-report.py 168  # weekly report
```

## Build & Run

```bash
# Build
go build -o cti-mcp ./cmd/cti-mcp

# Run (stdio MCP transport)
NVD_API_KEY="your-key" GITHUB_TOKEN="your-token" ./cti-mcp serve
```

## Architecture

- **Database:** SQLite (pure-Go `modernc.org/sqlite`, no CGO)
- **Transport:** MCP stdio
- **Caching:** Background refresh with per-source TTL
- **Sources:** 5 independent providers, each with health tracking
