import type { ScanResult } from '../types.js';
import chalk from 'chalk';
import Table from 'cli-table3';

function gradeColor(grade: string): chalk.Chalk {
  if (grade === 'A' || grade === 'B') return chalk.green;
  if (grade === 'C') return chalk.yellow;
  return chalk.red;
}

function severityColor(severity: string): chalk.Chalk {
  if (severity === 'critical') return chalk.red;
  if (severity === 'high') return chalk.redBright;
  if (severity === 'medium') return chalk.yellow;
  if (severity === 'low') return chalk.blue;
  return chalk.gray;
}

export function printTerminalReport(result: ScanResult): void {
  console.log();
  console.log(chalk.bold('╔══════════════════════════════════════════╗'));
  console.log(chalk.bold('║      MCP Server Security Scanner        ║'));
  console.log(chalk.bold('╚══════════════════════════════════════════╝'));
  console.log();

  console.log(chalk.dim('Target:') + '  ' + chalk.white(result.target));
  console.log(chalk.dim('Files:') + '   ' + chalk.white(String(result.filesScanned)));
  console.log(chalk.dim('Time:') + '    ' + chalk.white(result.scannedAt));
  console.log();

  const colorFn = gradeColor(result.grade);
  const gradeLabel = ` ${result.grade} `;
  console.log(
    chalk.bold('  Score: ') +
      chalk.bold(colorFn(` ${result.score}/100 `)) +
      chalk.bgBlack(colorFn.bold(` ${gradeLabel} `)),
  );
  console.log();

  const severityCounts: Record<string, number> = {};
  for (const f of result.findings) {
    severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
  }

  if (result.findings.length === 0) {
    console.log(chalk.green.bold('  ✓ No security issues found!'));
    console.log(chalk.green('    Your MCP server looks clean.'));
    console.log();
    return;
  }

  const summaryTable = new Table({
    head: [
      chalk.bold('Severity'),
      chalk.bold('Count'),
    ],
    style: { head: [], border: [] },
    colWidths: [20, 10],
  });

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of severityOrder) {
    if (severityCounts[sev]) {
      summaryTable.push([
        severityColor(sev)(sev.charAt(0).toUpperCase() + sev.slice(1)),
        severityColor(sev)(String(severityCounts[sev])),
      ]);
    }
  }
  console.log(chalk.bold('  Findings Summary'));
  console.log(summaryTable.toString());
  console.log();

  const severityOrderFull = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of severityOrderFull) {
    const sevFindings = result.findings.filter((f) => f.severity === sev);
    if (sevFindings.length === 0) continue;

    const label = sev.charAt(0).toUpperCase() + sev.slice(1);
    console.log(severityColor(sev).bold(`  ${label} (${sevFindings.length})`));
    console.log();

    for (const finding of sevFindings) {
      console.log(chalk.bold('    File: ') + chalk.white(finding.file) + (finding.line ? chalk.dim(`:${finding.line}`) : ''));
      console.log(chalk.bold('    Issue: ') + chalk.white(finding.title));
      console.log(chalk.bold('    Detail: ') + chalk.dim(finding.description));

      if (finding.snippet) {
        console.log(chalk.bold('    Code: ') + chalk.gray(finding.snippet));
      }

      console.log(chalk.bold('    Fix: ') + chalk.cyan(finding.recommendation));
      console.log();
    }
  }
}
