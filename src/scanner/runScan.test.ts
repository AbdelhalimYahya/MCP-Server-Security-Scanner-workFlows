import { describe, it, expect } from 'vitest';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from './runScan.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURE_DIR = join(__dirname, '..', '..', 'fixtures', 'sample-vulnerable-server');

describe('runScan integration', () => {
  it('returns all required fields', async () => {
    const result = await runScan(FIXTURE_DIR);
    expect(result).toHaveProperty('target', FIXTURE_DIR);
    expect(result).toHaveProperty('scannedAt');
    expect(typeof result.scannedAt).toBe('string');
    expect(result).toHaveProperty('filesScanned');
    expect(result.filesScanned).toBeGreaterThan(0);
    expect(result).toHaveProperty('findings');
    expect(Array.isArray(result.findings)).toBe(true);
    expect(result).toHaveProperty('score');
    expect(typeof result.score).toBe('number');
    expect(result).toHaveProperty('grade');
    expect(['A', 'B', 'C', 'D', 'F']).toContain(result.grade);
  });

  it('detects plaintext secrets in config.env', async () => {
    const result = await runScan(FIXTURE_DIR);
    const secretFindings = result.findings.filter((f) => f.id === 'PLAINTEXT_SECRET');
    expect(secretFindings.length).toBeGreaterThanOrEqual(1);
    expect(secretFindings[0].file).toMatch(/config\.env$/);
  });

  it('detects insecure network binding in server.ts', async () => {
    const result = await runScan(FIXTURE_DIR);
    const bindingFindings = result.findings.filter((f) => f.id === 'INSECURE_NETWORK_BINDING');
    expect(bindingFindings.length).toBeGreaterThanOrEqual(1);
    expect(bindingFindings[0].file).toMatch(/server\.ts$/);
  });

  it('calculates a score below 100 due to findings', async () => {
    const result = await runScan(FIXTURE_DIR);
    expect(result.score).toBeLessThan(100);
    expect(result.grade).not.toBe('A');
  });

  it('does not flag clean.ts', async () => {
    const result = await runScan(FIXTURE_DIR);
    const cleanFindings = result.findings.filter((f) => f.file.match(/clean\.ts$/));
    expect(cleanFindings).toHaveLength(0);
  });

  it('handles empty or non-existent directory gracefully', async () => {
    const result = await runScan(join(FIXTURE_DIR, 'nonexistent'));
    expect(result.filesScanned).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.score).toBe(100);
    expect(result.grade).toBe('A');
  });

  it('finds at least two distinct rule violations', async () => {
    const result = await runScan(FIXTURE_DIR);
    const uniqueIds = new Set(result.findings.map((f) => f.id));
    expect(uniqueIds.size).toBeGreaterThanOrEqual(2);
  });

  it('all finding objects have required fields', async () => {
    const result = await runScan(FIXTURE_DIR);
    for (const finding of result.findings) {
      expect(finding).toHaveProperty('id');
      expect(finding).toHaveProperty('severity');
      expect(finding).toHaveProperty('title');
      expect(finding).toHaveProperty('description');
      expect(finding).toHaveProperty('file');
      expect(finding).toHaveProperty('recommendation');
    }
  });
});
