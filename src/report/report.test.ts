import { describe, it, expect } from 'vitest';
import { tmpdir } from 'os';
import { join } from 'path';
import { readFileSync, existsSync, unlinkSync } from 'fs';
import type { ScanResult } from '../types.js';
import { writeJsonReport } from './jsonReport.js';
import { writeHtmlReport } from './htmlReport.js';

const sampleResult: ScanResult = {
  target: './test-fixtures/sample-server',
  scannedAt: '2026-07-07T12:00:00.000Z',
  filesScanned: 14,
  findings: [
    {
      id: 'PLAINTEXT_SECRET',
      severity: 'critical',
      title: 'Hardcoded API key',
      description: 'A plaintext API key was found.',
      file: 'src/config.ts',
      line: 12,
      snippet: 'const apiKey = "sk-a...3f2k"',
      recommendation: 'Move to env vars.',
    },
    {
      id: 'INSECURE_NETWORK_BINDING',
      severity: 'high',
      title: 'Bound to all interfaces',
      description: 'Server listens on 0.0.0.0.',
      file: 'src/server.ts',
      line: 45,
      snippet: 'app.listen(3000, "0.0.0.0")',
      recommendation: 'Bind to 127.0.0.1.',
    },
  ],
  score: 63,
  grade: 'C',
};

const cleanResult: ScanResult = {
  target: './test-fixtures/clean-server',
  scannedAt: '2026-07-07T12:00:00.000Z',
  filesScanned: 8,
  findings: [],
  score: 100,
  grade: 'A',
};

describe('writeJsonReport', () => {
  it('writes valid JSON that can be re-parsed', () => {
    const tmp = join(tmpdir(), `mcp-scan-test-${Date.now()}.json`);
    writeJsonReport(sampleResult, tmp);
    expect(existsSync(tmp)).toBe(true);

    const raw = readFileSync(tmp, 'utf8');
    const parsed: ScanResult = JSON.parse(raw);
    expect(parsed.score).toBe(63);
    expect(parsed.grade).toBe('C');
    expect(parsed.findings.length).toBe(2);
    expect(parsed.findings[0].id).toBe('PLAINTEXT_SECRET');

    unlinkSync(tmp);
  });

  it('writes JSON for zero-finding result', () => {
    const tmp = join(tmpdir(), `mcp-scan-clean-${Date.now()}.json`);
    writeJsonReport(cleanResult, tmp);
    const raw = readFileSync(tmp, 'utf8');
    const parsed: ScanResult = JSON.parse(raw);
    expect(parsed.score).toBe(100);
    expect(parsed.findings.length).toBe(0);

    unlinkSync(tmp);
  });

  it('creates the output directory if it does not exist', () => {
    const tmp = join(tmpdir(), `mcp-scan-nested-${Date.now()}`, 'sub', 'report.json');
    writeJsonReport(sampleResult, tmp);
    expect(existsSync(tmp)).toBe(true);

    const parsed: ScanResult = JSON.parse(readFileSync(tmp, 'utf8'));
    expect(parsed.score).toBe(63);

    unlinkSync(tmp);
  });
});

describe('writeHtmlReport', () => {
  it('contains the score and grade in the output', () => {
    const tmp = join(tmpdir(), `mcp-scan-report-${Date.now()}.html`);
    writeHtmlReport(sampleResult, tmp);
    const html = readFileSync(tmp, 'utf8');

    expect(html).toContain('63/100');
    expect(html).toContain('C');
    expect(html).toContain('MCP Security Scan Report');

    unlinkSync(tmp);
  });

  it('contains finding details', () => {
    const tmp = join(tmpdir(), `mcp-scan-report-${Date.now()}.html`);
    writeHtmlReport(sampleResult, tmp);
    const html = readFileSync(tmp, 'utf8');

    expect(html).toContain('Hardcoded API key');
    expect(html).toContain('Bound to all interfaces');
    expect(html).toContain('PLAINTEXT_SECRET');

    unlinkSync(tmp);
  });

  it('shows congratulatory message for zero findings', () => {
    const tmp = join(tmpdir(), `mcp-scan-clean-${Date.now()}.html`);
    writeHtmlReport(cleanResult, tmp);
    const html = readFileSync(tmp, 'utf8');

    expect(html).toContain('No security issues found!');
    expect(html).toContain('100/100');

    unlinkSync(tmp);
  });

  it('creates the output directory if it does not exist', () => {
    const tmp = join(tmpdir(), `mcp-scan-nested-${Date.now()}`, 'sub', 'report.html');
    writeHtmlReport(sampleResult, tmp);
    expect(existsSync(tmp)).toBe(true);

    const html = readFileSync(tmp, 'utf8');
    expect(html).toContain('63/100');

    unlinkSync(tmp);
  });
});
