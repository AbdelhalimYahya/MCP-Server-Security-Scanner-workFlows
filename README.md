# mcp-scan

A security scanner for MCP (Model Context Protocol) servers.

## Usage

```bash
# Scan a local directory
npx mcp-scan scan ./path/to/mcp-server

# Scan a GitHub repository
npx mcp-scan scan https://github.com/owner/repo
npx mcp-scan scan owner/repo

# Generate reports
npx mcp-scan scan ./path --json ./report.json --html ./report.html

# Filter by severity
npx mcp-scan scan ./path --min-severity high --quiet
```

## Flags

| Flag | Description |
|------|-------------|
| `--json <path>` | Write JSON report (default: `./mcp-scan-report.json`) |
| `--html <path>` | Write HTML report (default: `./mcp-scan-report.html`) |
| `--no-html` | Skip HTML report generation |
| `--min-severity <level>` | Only show findings at or above this severity |
| `--quiet` | Suppress terminal output |

## Rules

- **Plaintext Secrets** — hardcoded API keys, tokens, passwords in source
- **Insecure Binding** — servers binding to `0.0.0.0` or all network interfaces
- **Broad Tool Permissions** — dangerously permissive file-system or command tools
- **Missing Auth / Remote Transport** — TCP-based transports without authentication
- **Tool Description Injection** — tool descriptions containing executable-looking code
- **Vulnerable Dependencies** — outdated packages with known CVEs (`npm audit`)
