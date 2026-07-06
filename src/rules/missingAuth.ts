import type { Rule, Finding } from '../types.js';

const NETWORK_TRANSPORT_PATTERNS = [
  /\btransport\s*[=:]\s*["']sse["']/i,
  /\btransport\s*[=:]\s*["']http["']/i,
  /\btransport\s*[=:]\s*["']websocket["']/i,
];

const AUTH_SIGNALS = [
  /\bauthorization\b/i,
  /\bbearer\b/i,
  /\bapi[_-]?key\b/i,
  /\btrustedNetwork\s*[=:]\s*true\b/i,
  /\bsession\b/i,
  /\bcookie\b/i,
  /\bjwt\b/i,
  /auth\s*Middleware\b/i,
  /auth\s*Guard\b/i,
  /authenticate/i,
  /checkAuth\b/i,
  /requireAuth\b/i,
  /validateToken\b/i,
];

function detectNetworkTransport(fileContent: string): number | null {
  for (const pattern of NETWORK_TRANSPORT_PATTERNS) {
    const match = fileContent.match(pattern);
    if (match) {
      const lines = fileContent.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (pattern.test(lines[i])) return i + 1;
      }
    }
  }
  return null;
}

function hasAuthSignals(fileContent: string): boolean {
  return AUTH_SIGNALS.some((pattern) => pattern.test(fileContent));
}

export const missingAuthRule: Rule = {
  id: 'MISSING_AUTH_REMOTE_TRANSPORT',
  name: 'Missing Authentication on Remote Transport',
  severity: 'critical',

  check(fileContent: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    const transportLine = detectNetworkTransport(fileContent);
    if (transportLine === null) return findings;

    if (hasAuthSignals(fileContent)) return findings;

    const lines = fileContent.split('\n');
    const snippet = transportLine > 0 && transportLine <= lines.length
      ? lines[transportLine - 1].trim()
      : undefined;

    findings.push({
      id: this.id,
      severity: 'critical',
      title: 'MCP server exposed over network transport without authentication',
      description:
        'This file configures a network-accessible transport (HTTP, SSE, or WebSocket) but no authentication signals (bearer token, API key, Authorization header, JWT, session/cookie auth) were detected anywhere in the file. An MCP server reachable over the network without authentication means anyone who can reach the port can invoke every tool, including potentially destructive ones like file write, shell execution, or data deletion.',
      file: filePath,
      line: transportLine,
      snippet,
      recommendation:
        'Add authentication to every tool invocation. At minimum, require a bearer token or API key checked on every request (e.g., check Authorization header against a configured secret before dispatching to any tool handler). For anything beyond localhost, authentication is non-negotiable.',
    });

    return findings;
  },
};
