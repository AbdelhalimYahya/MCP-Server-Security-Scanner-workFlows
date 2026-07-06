import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockExecFileSync = vi.fn();
const mockExistsSync = vi.fn();

vi.mock('child_process', () => ({
  execFileSync: mockExecFileSync,
}));

vi.mock('fs', () => ({
  existsSync: mockExistsSync,
}));

const { vulnerableDependenciesRule } = await import('./vulnerableDependencies.js');

function makePath(dir: string) {
  return `${dir}/package.json`;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('vulnerableDependenciesRule', () => {
  describe('not a package.json file — should skip', () => {
    it('skips non-package.json files', () => {
      const findings = vulnerableDependenciesRule.check('{}', 'src/server.ts');
      expect(findings.length).toBe(0);
    });
  });

  describe('no package-lock.json — should skip', () => {
    it('returns no findings when package-lock.json is absent', () => {
      mockExistsSync.mockReturnValue(false);

      const content = JSON.stringify({ dependencies: { express: '^4.18.0' } });
      const findings = vulnerableDependenciesRule.check(content, makePath('/project-b'));
      expect(findings.length).toBe(0);
      expect(mockExecFileSync).not.toHaveBeenCalled();
    });
  });

  describe('npm audit succeeds — should return findings', () => {
    it('parses a single critical vulnerability', () => {
      mockExistsSync.mockReturnValue(true);
      mockExecFileSync.mockReturnValue(JSON.stringify({
        vulnerabilities: {
          'lodash': {
            name: 'lodash',
            severity: 'critical',
            via: ['CVE-2023-1234'],
            range: '>=4.17.0 <4.17.21',
            fixAvailable: { name: 'lodash', version: '4.17.21' },
          },
        },
        metadata: {
          vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 1, total: 1 },
        },
      }));

      const findings = vulnerableDependenciesRule.check('{}', makePath('/project-c/package.json'));
      expect(findings.length).toBe(1);
      expect(findings[0].id).toBe('VULNERABLE_DEPENDENCY');
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].title).toContain('lodash');
      expect(findings[0].recommendation).toContain('4.17.21');
    });

    it('parses multiple vulnerabilities with different severities', () => {
      mockExistsSync.mockReturnValue(true);
      mockExecFileSync.mockReturnValue(JSON.stringify({
        vulnerabilities: {
          'express': {
            name: 'express',
            severity: 'high',
            via: ['Regular Expression Denial of Service'],
            range: '>=4.0.0 <4.19.0',
            fixAvailable: { name: 'express', version: '4.19.0' },
          },
          'minimist': {
            name: 'minimist',
            severity: 'low',
            via: ['Prototype Pollution'],
            range: '>=0.0.0 <1.2.6',
            fixAvailable: { name: 'minimist', version: '1.2.6' },
          },
          'axios': {
            name: 'axios',
            severity: 'moderate',
            via: ['Server-Side Request Forgery'],
            range: '>=0.8.0 <1.7.0',
            fixAvailable: true,
          },
        },
      }));

      const findings = vulnerableDependenciesRule.check('{}', makePath('/project-d/package.json'));
      expect(findings.length).toBe(3);
      expect(findings[0].id).toBe('VULNERABLE_DEPENDENCY');
      expect(findings.map((f) => f.severity)).toContain('high');
      expect(findings.map((f) => f.severity)).toContain('low');
      expect(findings.map((f) => f.severity)).toContain('medium');
    });

    it('uses "medium" fallback for info/low severity', () => {
      mockExistsSync.mockReturnValue(true);
      mockExecFileSync.mockReturnValue(JSON.stringify({
        vulnerabilities: {
          'some-pkg': {
            name: 'some-pkg',
            severity: 'info',
            via: ['Minor advisory'],
            range: '*',
            fixAvailable: false,
          },
        },
      }));

      const findings = vulnerableDependenciesRule.check('{}', makePath('/project-e/package.json'));
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe('info');
    });
  });

  describe('npm audit fails — should degrade gracefully', () => {
    it('handles npm audit binary not found (ENOENT)', () => {
      mockExistsSync.mockReturnValue(true);
      const enoent = new Error('spawn npm ENOENT');
      (enoent as any).code = 'ENOENT';
      mockExecFileSync.mockImplementation(() => { throw enoent; });

      const findings = vulnerableDependenciesRule.check('{}', makePath('/project-f/package.json'));
      expect(findings.length).toBe(0);
    });

    it('handles npm audit timeout', () => {
      mockExistsSync.mockReturnValue(true);
      mockExecFileSync.mockImplementation(() => { throw new Error('Timeout'); });

      const findings = vulnerableDependenciesRule.check('{}', makePath('/project-g/package.json'));
      expect(findings.length).toBe(0);
    });

    it('handles invalid JSON output from npm audit', () => {
      mockExistsSync.mockReturnValue(true);
      mockExecFileSync.mockReturnValue('not valid json');

      const findings = vulnerableDependenciesRule.check('{}', makePath('/project-h/package.json'));
      expect(findings.length).toBe(0);
    });
  });
});
