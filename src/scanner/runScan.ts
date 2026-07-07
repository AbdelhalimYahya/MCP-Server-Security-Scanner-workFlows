import type { ScanResult, Rule } from '../types.js';
import { walkFiles } from './fileWalker.js';
import { getBuiltinRules } from '../rules/index.js';
import { calculateScore } from '../scoring/score.js';
import { readFile } from 'node:fs/promises';

export async function runScan(targetPath: string): Promise<ScanResult> {
  let allFiles: string[];
  try {
    allFiles = await walkFiles(targetPath);
  } catch {
    allFiles = [];
  }
  const rules: Rule[] = getBuiltinRules();
  const findings = [];

  for (const filePath of allFiles) {
    let content: string;
    try {
      content = await readFile(filePath, 'utf8');
    } catch {
      continue;
    }

    for (const rule of rules) {
      const fileFindings = rule.check(content, filePath);
      findings.push(...fileFindings);
    }
  }

  const { score, grade } = calculateScore(findings);
  const scannedAt = new Date().toISOString();

  return {
    target: targetPath,
    scannedAt,
    filesScanned: allFiles.length,
    findings,
    score,
    grade,
  };
}
