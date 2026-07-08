import type { Rule, Finding, Severity } from '../types.js';

const EXEMPT_FILE_PATTERNS = [
  /\.env\.example$/,
  /\.env\.sample$/,
  /\.example\./,
  /[/\\]examples[/\\]/,
  /\.test\.ts$/,
  /\.spec\.ts$/,
  /\bmocks?\.[jt]s$/,
];

const PLACEHOLDER_PREFIXES = [
  'your-', 'your_',
  'test-', 'test_',
  'dummy-', 'dummy_',
  'placeholder-', 'placeholder_',
  'example-', 'example_',
  'fake-', 'fake_',
  'invalid-', 'invalid_',
  'legit-', 'legit_',
  'mini-', 'mini_',
  'expired-', 'expired_',
  'unknown-', 'unknown_',
  'tampered-', 'tampered_',
  'introspection-', 'introspection_',
  'rotated-',
  'second-',
  'new-',
  'init-',
];

const KNOWN_TOKEN_PATTERNS: { regex: RegExp; label: string }[] = [
  { regex: /AKIA[0-9A-Z]{16}/, label: 'AWS Access Key' },
  { regex: /sk-[A-Za-z0-9]{20,}/, label: 'OpenAI API Key' },
  { regex: /sk-ant-[A-Za-z0-9]{16,}/, label: 'Anthropic API Key' },
  { regex: /ghp_[A-Za-z0-9]{36}/, label: 'GitHub Personal Access Token' },
  { regex: /github_pat_[A-Za-z0-9]{4,}/, label: 'GitHub Fine-grained Token' },
  { regex: /xox[baprs]-\d{10,}-[A-Za-z0-9]{10,}/, label: 'Slack Token' },
  { regex: /sk_live_[A-Za-z0-9]{16,}/, label: 'Stripe Live Secret Key' },
];

const ASSIGNMENT_PATTERN = /(api[_-]?key|apikey|secret|token|password|auth)\s*[=:]\s*["'`]([^"'`]{13,})["'`]/i;

const CONNECTION_STRING_PATTERN = /(postgres|postgresql|mysql|mongodb|redis|rediss):\/\/([^@]+):([^@]+)@/i;

const ENTROPY_VAR_PATTERN = /(api[_-]?key|apikey|secret|token|password|auth|credential|passphrase|certificate)\s*[=:]\s*["'`]([^"'`]{20,})["'`]/i;

function shannonEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function redact(value: string): string {
  if (value.length <= 8) return value;
  return value.slice(0, 4) + '...' + value.slice(-4);
}

function isExemptFile(filePath: string): 'test' | 'example' | null {
  if (/[/\\]tests?[/\\]/.test(filePath)) return 'test';
  const m = EXEMPT_FILE_PATTERNS.some((p) => p.test(filePath));
  if (m) {
    if (/\.test\.ts$|\.spec\.ts$|\bmocks?\.[jt]s$/.test(filePath)) return 'test';
    return 'example';
  }
  return null;
}

const PLACEHOLDER_RE = new RegExp(`^(${PLACEHOLDER_PREFIXES.join('|')})`, 'i');

function isPlaceholderValue(val: string): boolean {
  if (/^env\(/.test(val)) return true;
  if (PLACEHOLDER_RE.test(val)) return true;
  return false;
}

function capSeverity(exemptType: 'test' | 'example' | null, original: Severity): Severity {
  if (exemptType === 'test') return 'low';
  if (exemptType === 'example') return 'low';
  return original;
}

interface MatchResult {
  rawValue: string;
  line: number;
  lineContent: string;
  matchType: 'known_token' | 'assignment' | 'connection_string' | 'entropy';
}

function scanLine(lineText: string, lineIndex: number, matchedValues: Set<string>): MatchResult[] {
  const results: MatchResult[] = [];

  for (const { regex } of KNOWN_TOKEN_PATTERNS) {
    const m = lineText.match(regex);
    if (m && !matchedValues.has(m[0])) {
      matchedValues.add(m[0]);
      results.push({ rawValue: m[0], line: lineIndex + 1, lineContent: lineText, matchType: 'known_token' });
    }
  }

  const connMatch = lineText.match(CONNECTION_STRING_PATTERN);
  if (connMatch && !matchedValues.has(connMatch[0])) {
    matchedValues.add(connMatch[0]);
    results.push({ rawValue: connMatch[0], line: lineIndex + 1, lineContent: lineText, matchType: 'connection_string' });
  }

  const assignMatch = lineText.match(ASSIGNMENT_PATTERN);
  if (assignMatch && !matchedValues.has(assignMatch[2])) {
    const val = assignMatch[2];
    const isAlreadyKnown = KNOWN_TOKEN_PATTERNS.some((p) => p.regex.test(val));
    if (!isAlreadyKnown) {
      matchedValues.add(val);
      results.push({ rawValue: val, line: lineIndex + 1, lineContent: lineText, matchType: 'assignment' });
    }
  }

  const entropyMatch = lineText.match(ENTROPY_VAR_PATTERN);
  if (entropyMatch && !matchedValues.has(entropyMatch[2])) {
    const val = entropyMatch[2];
    const isAlreadyKnown = KNOWN_TOKEN_PATTERNS.some((p) => p.regex.test(val));
    const isAlreadyFound = matchedValues.has(val);
    if (!isAlreadyKnown && !isAlreadyFound && shannonEntropy(val) >= 4.0) {
      matchedValues.add(val);
      results.push({ rawValue: val, line: lineIndex + 1, lineContent: lineText, matchType: 'entropy' });
    }
  }

  return results;
}

export const plaintextSecretsRule: Rule = {
  id: 'PLAINTEXT_SECRET',
  name: 'Plaintext Credentials & Secrets',
  severity: 'critical',

  check(fileContent: string, filePath: string): Finding[] {
    const exemptType = isExemptFile(filePath);
    const lines = fileContent.split('\n');
    const matchedValues = new Set<string>();
    const findings: Finding[] = [];

    for (let i = 0; i < lines.length; i++) {
      const matches = scanLine(lines[i], i, matchedValues);
      for (const m of matches) {
        if (isPlaceholderValue(m.rawValue)) continue;

        const severity = capSeverity(exemptType, 'critical');
        const lineContent = m.lineContent.replace(m.rawValue, redact(m.rawValue));

        let title: string;
        let description: string;
        let recommendation: string;

        if (exemptType === 'test') {
          title = 'Test file contains hardcoded credential';
          description = `A hardcoded credential found in a test file (${redact(m.rawValue)}). This is unlikely to be a production secret, but test values should still use env vars for consistency.`;
          recommendation = 'Consider using environment variables or test helpers to generate test credentials.';
        } else if (exemptType === 'example') {
          title = 'Example file contains potential secret';
          description = `This file appears to be an example/template, but it contains a real-looking secret (${redact(m.rawValue)}). Example files should use placeholder values like "your-api-key-here" — never real credentials.`;
          recommendation = 'Replace the secret value with a placeholder like "your-api-key-here".';
        } else {
          switch (m.matchType) {
            case 'known_token':
              title = `Hardcoded ${m.rawValue.startsWith('AKIA') ? 'AWS Access Key' : 'API token'} detected`;
              description = `A known provider token format was found hardcoded in the source code. This type of secret can be used to access cloud services, incurring costs or exposing data.`;
              recommendation = 'Move this secret to an environment variable or secrets manager. Load it at runtime via process.env.YOUR_KEY.';
              break;
            case 'connection_string':
              title = 'Database connection string with embedded credentials';
              description = `A database connection string containing a username and password was found hardcoded. Anyone with access to this codebase can use these credentials to connect directly to the database.`;
              recommendation = 'Use environment variables for the username and password parts of the connection string, or use managed identity authentication where available.';
              break;
            case 'assignment':
              title = 'Hardcoded credential assignment';
              description = `A variable with a credential-sounding name is assigned a string value longer than 12 characters. This is likely a hardcoded API key, token, or password.`;
              recommendation = 'Move this value to an environment variable or a secrets manager. Never hardcode secrets in source files.';
              break;
            case 'entropy':
              title = 'High-entropy string assigned to credential variable';
              description = `A variable with a credential-sounding name is assigned a high-entropy string (random-looking), which is typical of generated secrets like API keys or tokens.`;
              recommendation = 'If this is a secret, move it to an environment variable. If it is a non-secret identifier (UUID, hash), rename the variable to make that clear.';
              break;
          }
        }

        findings.push({
          id: this.id,
          severity,
          title,
          description,
          file: filePath,
          line: m.line,
          snippet: lineContent,
          recommendation,
        });
      }
    }

    return findings;
  },
};
