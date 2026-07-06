import type { Rule, Finding } from '../types.js';

const EXEC_PATTERNS = [
  /child_process\.(?:exec|execSync)\s*\(/,
  /\.execSync\s*\(/,
  /spawn\s*\([^)]*,\s*\[[^\]]*\][^)]*shell\s*:\s*true/,
  /\bexec\s*\(/,
];

const FS_WRITE_PATTERNS = [
  /fs\.writeFile(?:Sync)?\s*\(/,
  /fs\.unlink(?:Sync)?\s*\(/,
  /fs\.rm(?:Sync)?\s*\(/,
  /fs\.promises\.(?:writeFile|unlink|rm)\s*\(/,
  /fs\.appendFile(?:Sync)?\s*\(/,
];

// Key-value forms: name: "x", description: "x"
const TOOL_NAME_RE = /\bname\s*[=:]\s*['"`][^'"`]+['"`]/;
const TOOL_DESC_RE = /\bdescription\s*[=:]\s*['"`]([^'"`]+)['"`]/;
const INPUT_SCHEMA_RE = /\binputSchema\s*[:=]/;
// Positional: server.tool("name", "description", ...)
const SERVER_TOOL_CALL_RE = /server\.tool\s*\(\s*['"`][^'"`]+['"`]\s*,\s*['"`]([^'"`]+)['"`]/;
const SERVER_TOOL_RE = /server\.tool\s*\(/;

const INPUT_PARAM_RE = /\b(input|params?)\b/;
const PATH_PROP_RE = /\bpath\b/;

const READONLY_DESC_RE = /\b(read|get|list|fetch|query|retrieve|view|show|lookup|check|find)\b/i;

function fileHasAllowlist(content: string): boolean {
  const lines = content.split('\n');
  let braceDepth = 0;
  for (const line of lines) {
    const stripped = line.replace(/\/\/.*$/, '').replace(/\/\*.*?\*\//g, '').trim();
    if (!stripped) continue;
    for (const ch of stripped) {
      if (ch === '[' || ch === '{') braceDepth++;
      if (ch === ']' || ch === '}') braceDepth--;
    }
    if (braceDepth <= 0 && /\[(?:'[a-z][a-z0-9_-]*'|"[a-z][a-z0-9_-]*")\s*[,]/.test(stripped)) {
      return true;
    }
  }
  return false;
}

function fileHasPathContainment(content: string): boolean {
  return /path\.resolve\s*\(/.test(content) && /\.startsWith\s*\(/.test(content);
}

function isStreaming(line: string, allLines: string[], idx: number): boolean {
  if (/\bstd(?:in|out|err)\b/.test(line)) return true;
  // Check if exec result is piped (next couple of lines reference stream.stdout/err/in)
  for (let j = idx + 1; j <= Math.min(allLines.length - 1, idx + 3); j++) {
    if (/\bstd(?:in|out|err)\b/.test(allLines[j]) && /\.pipe\b/.test(allLines[j])) {
      return true;
    }
  }
  return false;
}

function isSafeInlinePath(line: string): boolean {
  return /path\.(?:resolve|join|normalize)\s*\(/.test(line);
}

function isToolContext(lines: string[], idx: number): boolean {
  const start = Math.max(0, idx - 5);
  const end = Math.min(lines.length - 1, idx + 15);
  let hasName = false, hasDesc = false, hasSchemaOrServer = false;
  let hasPosTool = false;
  for (let i = start; i <= end; i++) {
    if (TOOL_NAME_RE.test(lines[i])) hasName = true;
    if (TOOL_DESC_RE.test(lines[i])) hasDesc = true;
    if (INPUT_SCHEMA_RE.test(lines[i]) || SERVER_TOOL_RE.test(lines[i])) hasSchemaOrServer = true;
    if (SERVER_TOOL_CALL_RE.test(lines[i])) hasPosTool = true;
  }
  return hasPosTool || (hasName && hasDesc) || (hasSchemaOrServer && hasName);
}

function hasInputVariable(line: string): boolean {
  return INPUT_PARAM_RE.test(line) || PATH_PROP_RE.test(line) || /\.path\b/.test(line);
}

function extractToolDescription(line: string): string | null {
  const m1 = line.match(SERVER_TOOL_CALL_RE);
  if (m1) return m1[1];
  const m2 = line.match(TOOL_DESC_RE);
  if (m2) return m2[1];
  return null;
}

export const broadPermissionsRule: Rule = {
  id: 'BROAD_TOOL_PERMISSIONS',
  name: 'Overly Broad Tool Permissions',
  severity: 'high',

  check(fileContent: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = fileContent.split('\n');

    const allowlistPresent = fileHasAllowlist(fileContent);
    const containmentPresent = fileHasPathContainment(fileContent);

    let flaggedExec = false;
    let flaggedWrite = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (!flaggedExec && !trimmed.startsWith('//')) {
        const isExec = EXEC_PATTERNS.some((p) => p.test(line));
        if (isExec && !isStreaming(line, lines, i)) {
          if (!allowlistPresent && isToolContext(lines, i)) {
            findings.push({
              id: this.id,
              severity: 'high',
              title: 'Shell execution without command allowlist',
              description:
                'An MCP tool executes shell commands via child_process.exec or spawn with shell:true, but no command allowlist was found in this file. An attacker who compromises the LLM can run arbitrary system commands (exfiltrate data, delete files, install malware).',
              file: filePath,
              line: i + 1,
              snippet: trimmed,
              recommendation:
                'Maintain a hardcoded allowlist of permitted command names (e.g., const ALLOWED = ["git", "ls", "cat"]). Validate the input command against this list before executing.',
            });
            flaggedExec = true;
          }
        }
      }
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (!flaggedWrite && !trimmed.startsWith('//')) {
        const isWrite = FS_WRITE_PATTERNS.some((p) => p.test(line));
        if (isWrite && !isSafeInlinePath(line)) {
          if (!containmentPresent && isToolContext(lines, i) && hasInputVariable(line)) {
            findings.push({
              id: this.id,
              severity: 'high',
              title: 'Filesystem write with unsanitized path from tool input',
              description:
                'A filesystem write or delete inside a tool handler uses a path derived from tool input without a containment check. An attacker could write to or delete any file on the system (e.g., overwrite ~/.ssh/authorized_keys, delete application code).',
              file: filePath,
              line: i + 1,
              snippet: trimmed,
              recommendation:
                'Resolve the path with path.resolve() relative to a designated safe directory, then guard with if (!resolved.startsWith(SAFE_DIR)) throw new Error("invalid path").',
            });
            flaggedWrite = true;
          }
        }
      }
    }

    const fileHasExec = EXEC_PATTERNS.some((p) => p.test(fileContent));
    const fileHasWrite = FS_WRITE_PATTERNS.some((p) => p.test(fileContent));

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (trimmed.startsWith('//')) continue;

      const desc = extractToolDescription(line);
      if (!desc) continue;
      if (!isToolContext(lines, i)) continue;
      if (!READONLY_DESC_RE.test(desc)) continue;

      if (fileHasExec) {
        findings.push({
          id: this.id,
          severity: 'medium',
          title: 'Tool claims to be read-only but uses shell execution',
          description: `The tool description "${desc}" suggests a read-only operation, yet the file contains shell execution calls. A tool advertised as harmless can be used to run system commands.`,
          file: filePath,
          line: i + 1,
          snippet: trimmed,
          recommendation:
            'Restrict this tool to truly read-only operations, or update the description to honestly reflect that it can execute commands.',
        });
      }

      if (fileHasWrite) {
        findings.push({
          id: this.id,
          severity: 'medium',
          title: 'Tool claims to be read-only but writes files',
          description: `The tool description "${desc}" suggests a read-only operation, yet the file contains filesystem writes. A tool advertised as read-only can modify or delete files.`,
          file: filePath,
          line: i + 1,
          snippet: trimmed,
          recommendation:
            'Remove write capabilities from this tool, or update the description to accurately reflect its capabilities.',
        });
      }
    }

    return findings;
  },
};
