import type { Rule, Finding } from '../types.js';
import { execFileSync } from 'child_process';
import { existsSync } from 'fs';
import { dirname, basename } from 'path';

interface AuditVulnerability {
  name: string;
  severity: 'info' | 'low' | 'moderate' | 'high' | 'critical';
  via: Array<string | { title?: string; source?: number }>;
  fixAvailable: boolean | { name: string; version: string } | { isSemVerMajor: boolean };
  range: string;
}

interface AuditReport {
  vulnerabilities?: Record<string, AuditVulnerability>;
  metadata?: {
    vulnerabilities?: Record<string, number>;
  };
}

const SEVERITY_MAP: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
  critical: 'critical',
  high: 'high',
  moderate: 'medium',
  low: 'low',
  info: 'info',
};

let auditCache: { dir: string; findings: Finding[] } | null = null;

function runNpmAudit(dir: string): Finding[] {
  const findings: Finding[] = [];

  const lockFile = existsSync(`${dir}/package-lock.json`);
  if (!lockFile) return findings;

  try {
    const stdout = execFileSync('npm', ['audit', '--json'], {
      cwd: dir,
      encoding: 'utf8',
      timeout: 30000,
      maxBuffer: 10 * 1024 * 1024,
    });

    const report: AuditReport = JSON.parse(stdout);
    const vulns = report.vulnerabilities;
    if (!vulns) return findings;

    for (const [pkgName, vuln] of Object.entries(vulns)) {
      const severity = SEVERITY_MAP[vuln.severity] ?? 'medium';
      const viaDescriptions = vuln.via
        .map((v) => (typeof v === 'string' ? v : v.title ?? `advisory #${v.source}`))
        .filter(Boolean);

      let fixText = '';
      if (vuln.fixAvailable === true) {
        fixText = 'Upgrade available via `npm update` or `npm audit fix`.';
      } else if (typeof vuln.fixAvailable === 'object' && vuln.fixAvailable !== null) {
        const fix = vuln.fixAvailable as { name?: string; version?: string; isSemVerMajor?: boolean };
        if (fix.name && fix.version) {
          fixText = `Upgrade ${fix.name} to ${fix.version}.`;
          if (fix.isSemVerMajor) fixText += ' (semver-major — may require code changes.)';
        }
      }
      if (!fixText) fixText = 'No automatic fix available. Review and manually update this dependency.';

      const pkgJsonPath = dir.replace(/\\/g, '/') + '/package.json';
      findings.push({
        id: 'VULNERABLE_DEPENDENCY',
        severity,
        title: `Vulnerable dependency: ${pkgName}`,
        description:
          `${pkgName}@${vuln.range} has ${vuln.severity}-severity vulnerabilities: ${
            viaDescriptions.join(', ') || 'see advisory details'
          }.`,
        file: pkgJsonPath,
        recommendation: fixText,
      });
    }
  } catch {
  }

  return findings;
}

export const vulnerableDependenciesRule: Rule = {
  id: 'VULNERABLE_DEPENDENCY',
  name: 'Outdated / Vulnerable Dependencies',
  severity: 'high',

  check(fileContent: string, filePath: string): Finding[] {
    const fileName = basename(filePath);
    if (fileName !== 'package.json') return [];

    const dir = dirname(filePath);
    if (auditCache && auditCache.dir === dir) return auditCache.findings;

    const findings = runNpmAudit(dir);
    auditCache = { dir, findings };
    return findings;
  },
};
