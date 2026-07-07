import type { Finding, Severity } from '../types.js';

const DEDUCTIONS: Record<Severity, number> = {
  critical: 25,
  high: 12,
  medium: 5,
  low: 2,
  info: 0,
};

const LOW_CAP = 10;

const GRADE_THRESHOLDS: [number, 'A' | 'B' | 'C' | 'D' | 'F'][] = [
  [90, 'A'],
  [75, 'B'],
  [60, 'C'],
  [40, 'D'],
  [0, 'F'],
];

export function calculateScore(
  findings: Finding[],
): { score: number; grade: 'A' | 'B' | 'C' | 'D' | 'F' } {
  let totalDeduction = 0;
  let lowDeduction = 0;

  for (const finding of findings) {
    const deduction = DEDUCTIONS[finding.severity] ?? 0;
    if (finding.severity === 'low') {
      lowDeduction += deduction;
    } else {
      totalDeduction += deduction;
    }
  }

  totalDeduction += Math.min(lowDeduction, LOW_CAP);

  const score = Math.max(0, 100 - totalDeduction);

  const grade = GRADE_THRESHOLDS.find(([threshold]) => score >= threshold)![1];

  return { score, grade };
}
