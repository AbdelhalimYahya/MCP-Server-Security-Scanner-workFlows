import { describe, it, expect } from 'vitest';
import { plaintextSecretsRule } from './plaintextSecrets.js';

function run(content: string, filePath = 'src/config.ts') {
  return plaintextSecretsRule.check(content, filePath);
}

const OAI = 'sk-' + 'abc123def456ghi789jklmnopqrs';
const AWS = 'AKIA' + 'IOSFODNN7EXAMPLE';
const ANT = 'sk-ant-' + 'abc123def456ghi789';
const GHP = 'ghp_' + 'abc123def456ghi789jklmnopqrs1234567890ab';
const SLK = 'xoxb-' + '123456789012' + '-' + 'abcdefghijklmnopqrs';
const STRIPE = 'sk_live_' + 'abc123def456ghi789';

describe('plaintextSecretsRule', () => {
  describe('true positives — should flag', () => {
    it('detects AWS access key', () => {
      const findings = run(`const awsKey = "${AWS}";`);
      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].id).toBe('PLAINTEXT_SECRET');
    });

    it('detects OpenAI API key', () => {
      const findings = run(`const openai = "${OAI}";`);
      expect(findings).toHaveLength(1);
    });

    it('detects Anthropic API key', () => {
      const findings = run(`const anthropic = "${ANT}";`);
      expect(findings).toHaveLength(1);
    });

    it('detects GitHub personal access token', () => {
      const findings = run(`const gh = "${GHP}";`);
      expect(findings).toHaveLength(1);
    });

    it('detects Slack token', () => {
      const findings = run(`const slack = "${SLK}";`);
      expect(findings).toHaveLength(1);
    });

    it('detects Stripe live secret key', () => {
      const findings = run(`const stripe = "${STRIPE}";`);
      expect(findings).toHaveLength(1);
    });

    it('detects database connection string with embedded credentials', () => {
      const findings = run(`const db = "postgres://admin:secret123@localhost:5432/mydb";`);
      expect(findings).toHaveLength(1);
    });

    it('detects generic API key assignment with long value', () => {
      const findings = run(`const apiKey = "my-super-secret-api-key-value";`);
      expect(findings).toHaveLength(1);
    });

    it('detects secret variable assignment', () => {
      const findings = run(`const secret = "very-secret-value-that-is-long";`);
      expect(findings).toHaveLength(1);
    });

    it('detects token in YAML-style assignment', () => {
      const findings = run(`api_key: "this-is-a-fake-api-key-12345"`);
      expect(findings).toHaveLength(1);
    });
  });

  describe('true negatives — should NOT flag', () => {
    it('does not flag a UUID', () => {
      const findings = run(`const id = "550e8400-e29b-41d4-a716-446655440000";`);
      expect(findings).toHaveLength(0);
    });

    it('does not flag an MD5 hash', () => {
      const findings = run(`const hash = "d41d8cd98f00b204e9800998ecf8427e";`);
      expect(findings).toHaveLength(0);
    });

    it('does not flag a short string', () => {
      const findings = run(`const name = "hello-world";`);
      expect(findings).toHaveLength(0);
    });

    it('does not flag a URL without credentials', () => {
      const findings = run(`const url = "https://example.com/api/data";`);
      expect(findings).toHaveLength(0);
    });

    it('does not flag a variable name that just contains "token" as part of another word', () => {
      const findings = run(`const tokenize = "some-value-here-for-testing";`);
      expect(findings).toHaveLength(0);
    });
  });

  describe('redaction', () => {
    it('redacts the secret value in the snippet', () => {
      const findings = run(`const key = "${OAI}";`);
      expect(findings).toHaveLength(1);
      expect(findings[0].snippet).not.toContain(OAI);
      expect(findings[0].snippet).toContain('...');
    });

    it('shows first 4 and last 4 chars in the redacted snippet', () => {
      const findings = run(`const key = "${OAI}";`);
      const snippet = findings[0].snippet!;
      expect(snippet).toContain('sk-a');
      expect(snippet).toContain('pqrs');
    });
  });

  describe('example/template files', () => {
    it('flags at low severity in .env.example files', () => {
      const findings = run(
        `API_KEY=${OAI}`,
        '.env.example',
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe('low');
    });

    it('flags at low severity in .env.sample files', () => {
      const findings = run(
        `API_KEY=${OAI}`,
        'config/.env.sample',
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe('low');
    });
  });
});
