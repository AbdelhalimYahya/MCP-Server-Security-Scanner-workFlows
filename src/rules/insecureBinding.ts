import type { Rule, Finding } from '../types.js';

const ALL_INTERFACES_IPV4 = /0\.0\.0\.0/;
const ALL_INTERFACES_IPV6 = /::/;

const LOCALHOST_PATTERNS = [
  /127\.0\.0\.1/,
  /localhost/,
];

const NETWORK_TRANSPORT_PATTERNS = [
  /\btransport\s*[=:]\s*["']sse["']/i,
  /\btransport\s*[=:]\s*["']http["']/i,
  /\btransport\s*[=:]\s*["']websocket["']/i,
];

const AUTH_KEYWORDS = [
  /\bauth/i,
  /\btoken\b/i,
  /\bbearer\b/i,
  /\bauthorization\b/i,
  /\bapi[_-]?key\b/i,
];

function isTestFile(filePath: string): boolean {
  return /\.test\.(ts|js)$|\.spec\.(ts|js)$|[/\\]tests?[/\\]/.test(filePath);
}

function isRealBinding(line: string): boolean {
  if (/['"]0\.0\.0\.0['"]/.test(line) && /['"]host['"]\s*[:=]/.test(line)) return false;
  const bindingV4Pattern = /(?:^|[,{;\s])(?:host|listen|bind|address)\s*(?::|=)\s*["']0\.0\.0\.0["']/i;
  if (bindingV4Pattern.test(line)) return true;
  const bindingV6Pattern = /(?:^|[,{;\s])(?:host|listen|bind|address)\s*(?::|=)\s*["']::["']/i;
  if (bindingV6Pattern.test(line)) return true;
  const listenPattern = /\.listen\s*\([^)]*["'](?:0\.0\.0\.0|::)["']/;
  if (listenPattern.test(line)) return true;
  const envPattern = /^HOST=0\.0\.0\.0$/m;
  if (envPattern.test(line)) return true;
  return false;
}

export const insecureBindingRule: Rule = {
  id: 'INSECURE_NETWORK_BINDING',
  name: 'Insecure Network Binding',
  severity: 'high',

  check(fileContent: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    if (isTestFile(filePath)) return findings;

    const lines = fileContent.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      const isAllInterfaces = ALL_INTERFACES_IPV4.test(line) || ALL_INTERFACES_IPV6.test(line);
      if (!isAllInterfaces) continue;

      const isLocalhostAlso = LOCALHOST_PATTERNS.some((p) => p.test(line));
      if (isLocalhostAlso) continue;

      if (!isRealBinding(line)) continue;

      const address = ALL_INTERFACES_IPV6.test(line) && !ALL_INTERFACES_IPV4.test(line) ? '::' : '0.0.0.0';
      findings.push({
        id: this.id,
        severity: 'high',
        title: 'Server bound to all network interfaces',
        description: `The server is configured to listen on all network interfaces (${address}), making it accessible from any machine that can reach this host. This exposes the MCP server to the local network and potentially the internet.`,
        file: filePath,
        line: i + 1,
        snippet: line.trim(),
        recommendation:
          'For local-only MCP servers, bind to 127.0.0.1 so only processes on the same machine can connect. If remote access is genuinely needed, require authentication and use a reverse proxy with TLS.',
      });
    }

    const hasNetworkTransport = NETWORK_TRANSPORT_PATTERNS.some((p) => p.test(fileContent));
    if (hasNetworkTransport) {
      const hasAuth = AUTH_KEYWORDS.some((p) => p.test(fileContent));
      if (!hasAuth) {
        const transportLine = lines.findIndex((l) =>
          NETWORK_TRANSPORT_PATTERNS.some((p) => p.test(l)),
        );
        findings.push({
          id: this.id,
          severity: 'high',
          title: 'Network transport without authentication',
          description:
            'The MCP server is configured to use a network transport (SSE, HTTP, or WebSocket) but no authentication keywords (auth, token, bearer, authorization, API key) were found in the same file. A network-accessible MCP server without authentication allows anyone who can reach the port to invoke any tool.',
          file: filePath,
          line: transportLine + 1,
          snippet: lines[transportLine].trim(),
          recommendation:
            'Add authentication (e.g., bearer token, API key check) to every tool invocation. If remote access is genuinely needed, require authentication and use a reverse proxy with TLS.',
        });
      }
    }

    return findings;
  },
};
