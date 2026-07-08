# mcp-scan

A free, open-source security scanner for MCP (Model Context Protocol) servers.

MCP is a standard that lets AI agents connect to external tools and data sources. Every MCP server is a potential attack surface — if one has a hardcoded API key, binds to all network interfaces, or exposes dangerous tools without authentication, it could be used to access data or execute commands it shouldn't. This tool finds those problems before someone else does.

## Quickstart

```bash
npx mcp-scan scan ./path/to/mcp-server
npx mcp-scan scan https://github.com/owner/repo
npx mcp-scan scan owner/repo --quiet --json report.json
```

No installation required. Works on local folders and public GitHub repos.

## What It Checks

| Check | What It Finds | Severity |
|-------|--------------|----------|
| **Plaintext Secrets** | Hardcoded API keys, tokens, passwords, and connection strings left in source code | critical |
| **Insecure Network Binding** | Servers listening on `0.0.0.0` (all interfaces) instead of `127.0.0.1`, exposing MCP to the network | high |
| **Overly Broad Tool Permissions** | MCP tools that run shell commands or access the filesystem without proper input validation or scoping | high |
| **Missing Authentication** | Remote-transport MCP servers that don't require any auth token or API key | critical |
| **Tool Description Injection** | Tool descriptions that contain instructions aimed at manipulating the AI agent's behavior | medium |
| **Vulnerable Dependencies** | Outdated npm packages with known CVEs via `npm audit` | varies |

## Example Output

Scanning a server with a hardcoded OpenAI API key:

```
╔══════════════════════════════════════════╗
║      MCP Server Security Scanner        ║
╚══════════════════════════════════════════╝

Target:  ./my-mcp-server
Files:   3
Time:    2026-07-08T11:42:40.000Z

  Score:  75/100   B

  Findings Summary
┌────────────────────┬──────────┐
│ Severity           │ Count    │
├────────────────────┼──────────┤
│ Critical           │ 1        │
└────────────────────┴──────────┘

  Critical (1)

    File: src/config.ts:2
    Issue: Hardcoded API token detected
    Detail: A known provider token format was found hardcoded in the source
            code. This type of secret can be used to access cloud services,
            incurring costs or exposing data.
    Code:   openaiKey: 'sk-t...5678',
    Fix: Move this secret to an environment variable or secrets manager.
         Load it at runtime via process.env.YOUR_KEY.

JSON report saved to: ./mcp-scan-report.json
HTML report saved to: ./mcp-scan-report.html
```

A clean server scores 100/A:

```
  Score:  100/100   A

  ✓ No security issues found!
    Your MCP server looks clean.
```

## Installation

### Use directly with npx (no install needed)

```bash
npx mcp-scan scan ./my-server
npx mcp-scan scan owner/repo --json report.json
```

### Install globally

```bash
npm install -g mcp-scan
mcp-scan scan ./my-server
```

### Add as a project dependency

```bash
npm install --save-dev mcp-scan
npx mcp-scan scan .
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `--json <path>` | Write JSON report to this path (default: `./mcp-scan-report.json`) |
| `--html <path>` | Write HTML report to this path (default: `./mcp-scan-report.html`) |
| `--no-html` | Skip HTML report generation |
| `--min-severity <level>` | Only show findings at or above this severity in terminal output. Levels: `critical`, `high`, `medium`, `low`, `info`. Default: `info` |
| `--quiet` | Suppress terminal report output (still writes JSON/HTML files) |
| `--help` | Show help with usage examples |
| `--version` | Show version number |

## Limitations

This tool performs **static analysis only**. It reads the source code of your MCP server but does not run it. This means:

- **No runtime detection.** It cannot catch vulnerabilities that only appear at runtime — logic flaws, authentication bypasses, race conditions, or incorrect permission enforcement that depends on runtime state.
- **No dependency tree analysis.** The vulnerable-dependencies check uses `npm audit` and covers only npm packages. Other ecosystems (Rust, Python, Go) are not checked.
- **Best-effort signal.** The tool may miss issues that don't match its detection patterns (false negatives), and it may flag code that is intentionally configured a certain way but not actually vulnerable in context (false positives). Review each finding manually.
- **Not a substitute for a security audit.** This is a quick first-pass check you can run in 30 seconds, not a comprehensive security review. Use it as part of a broader security process, not in place of one.

## Contributing

Contributions are welcome. To add a new detection rule:

1. Create a file in `src/rules/` that implements the `Rule` interface from `src/types.ts`:

```typescript
import type { Rule, Finding } from '../types.js';

export const myRule: Rule = {
  id: 'MY_NEW_RULE',
  name: 'My New Rule',
  severity: 'medium',
  check(fileContent: string, filePath: string): Finding[] {
    // Return an array of Finding objects for each issue detected.
    // Return an empty array if no issues are found.
    return [];
  },
};
```

2. Register it in `src/rules/index.ts` by importing and adding it to the `builtinRules` array.

3. Write a vitest test file at `src/rules/myRule.test.ts`.

4. Run `npm test` to verify your rule doesn't break existing checks.

## License

MIT. See [LICENSE](LICENSE).
