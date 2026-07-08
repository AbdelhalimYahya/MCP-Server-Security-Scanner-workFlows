import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from './runScan.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const CORPUS_DIR = join(__dirname, '..', '..', 'fixtures', 'corpus');

const ALL_RULE_IDS = [
  'PLAINTEXT_SECRET',
  'INSECURE_NETWORK_BINDING',
  'BROAD_TOOL_PERMISSIONS',
  'TOOL_DESCRIPTION_INJECTION_RISK',
  'MISSING_AUTH_REMOTE_TRANSPORT',
  'VULNERABLE_DEPENDENCY',
];

interface ExpectedResults {
  shouldFind: string[];
  shouldNotFind: string[];
}

describe('labeled test corpus', () => {
  const fixtures = ['clean-server-1', 'clean-server-2', 'vulnerable-plaintext-secret', 'vulnerable-insecure-binding', 'vulnerable-broad-permissions', 'vulnerable-no-auth'];

  for (const fixture of fixtures) {
    it(`${fixture} matches expected results`, async () => {
      const fixturePath = join(CORPUS_DIR, fixture);
      const expected: ExpectedResults = JSON.parse(
        readFileSync(join(fixturePath, 'expected-results.json'), 'utf8'),
      );

      const result = await runScan(fixturePath);
      const foundIds = new Set(result.findings.map((f) => f.id));

      for (const id of expected.shouldFind) {
        expect(foundIds.has(id), `Expected to find ${id} in ${fixture}, but it was not detected`).toBe(true);
      }

      for (const id of expected.shouldNotFind) {
        expect(foundIds.has(id), `Expected NOT to find ${id} in ${fixture}, but it was detected`).toBe(false);
      }

      const unexpectedIds = result.findings
        .map((f) => f.id)
        .filter((id) => !expected.shouldFind.includes(id));

      expect(unexpectedIds, `${fixture} has unexpected findings: ${unexpectedIds.join(', ')}`).toEqual([]);
    });
  }
});
