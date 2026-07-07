import type { ScanResult } from '../types.js';
import { writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';

function gradeColor(grade: string): string {
  if (grade === 'A' || grade === 'B') return '#22c55e';
  if (grade === 'C') return '#eab308';
  return '#ef4444';
}

function severityColor(severity: string): string {
  if (severity === 'critical') return '#ef4444';
  if (severity === 'high') return '#f97316';
  if (severity === 'medium') return '#eab308';
  if (severity === 'low') return '#3b82f6';
  return '#6b7280';
}

function severityBg(severity: string): string {
  if (severity === 'critical') return '#fef2f2';
  if (severity === 'high') return '#fff7ed';
  if (severity === 'medium') return '#fefce8';
  if (severity === 'low') return '#eff6ff';
  return '#f9fafb';
}

export function writeHtmlReport(result: ScanResult, outputPath: string): void {
  mkdirSync(dirname(outputPath), { recursive: true });

  const color = gradeColor(result.grade);
  const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];

  const sevCounts: Record<string, number> = {};
  for (const f of result.findings) {
    sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
  }

  const summaryRows = sevOrder
    .filter((s) => sevCounts[s])
    .map(
      (s) =>
        `<tr>
          <td style="color:${severityColor(s)};font-weight:600">${s.charAt(0).toUpperCase() + s.slice(1)}</td>
          <td style="text-align:center;font-weight:600">${sevCounts[s]}</td>
        </tr>`,
    )
    .join('\n          ');

  const findingBlocks = sevOrder
    .filter((s) => sevCounts[s])
    .map((sev) => {
      const items = result.findings
        .filter((f) => f.severity === sev)
        .map(
          (f, i) =>
            `<details style="background:${severityBg(sev)};border:1px solid ${severityColor(sev)}40;border-radius:8px;padding:12px 16px;margin-bottom:8px">
              <summary style="cursor:pointer;font-weight:600;color:#1f2937;font-size:14px">
                <span style="color:${severityColor(sev)};margin-right:8px">&#9679;</span>
                ${f.title}
                <span style="color:#6b7280;font-weight:400;font-size:13px;margin-left:8px">— ${f.file}${f.line ? ':' + f.line : ''}</span>
              </summary>
              <div style="margin-top:10px;padding-left:4px">
                <div style="font-size:12px;color:#9ca3af;margin-bottom:4px">Rule: ${f.id}</div>
                <p style="color:#4b5563;font-size:14px;margin:4px 0">${f.description}</p>
                ${f.snippet ? `<pre style="background:#1f2937;color:#e5e7eb;padding:10px 14px;border-radius:6px;font-size:13px;overflow-x:auto;margin:8px 0">${f.snippet}</pre>` : ''}
                <div style="margin-top:8px;padding:10px 14px;background:#f0fdf4;border-left:4px solid #22c55e;border-radius:4px;font-size:13px;color:#166534">
                  <strong>Recommendation:</strong> ${f.recommendation}
                </div>
              </div>
            </details>`,
        )
        .join('\n            ');

      return `
        <div style="margin-bottom:24px">
          <h2 style="color:${severityColor(sev)};font-size:18px;margin:0 0 10px 0;padding-bottom:6px;border-bottom:2px solid ${severityColor(sev)}40">
            ${sev.charAt(0).toUpperCase() + sev.slice(1)}
            <span style="font-size:14px;font-weight:400;color:#6b7280">(${sevCounts[sev]})</span>
          </h2>
          ${items}
        </div>`;
    })
    .join('\n        ');

  const zeroMsg = result.findings.length === 0
    ? '<div style="text-align:center;padding:40px 0"><div style="font-size:48px">&#9989;</div><h2 style="color:#22c55e">No security issues found!</h2><p style="color:#6b7280">Your MCP server looks clean.</p></div>'
    : '';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCP Security Scan Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 24px; background: #f8fafc; color: #1f2937; }
  .container { max-width: 800px; margin: 0 auto; }
  .header { text-align: center; margin-bottom: 32px; }
  .score-badge { display: inline-flex; align-items: center; gap: 16px; padding: 16px 32px; border-radius: 16px; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .score-number { font-size: 36px; font-weight: 700; }
  .grade-badge { display: inline-block; padding: 4px 16px; border-radius: 999px; font-size: 24px; font-weight: 700; color: white; }
  .meta { color: #6b7280; font-size: 14px; margin-top: 12px; }
  .meta span { margin: 0 8px; }
  table { width: 100%; border-collapse: collapse; margin: 16px 0 24px; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
  th, td { padding: 10px 16px; text-align: left; border-bottom: 1px solid #f1f5f9; }
  th { background: #f8fafc; font-size: 13px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; }
  h1 { font-size: 24px; margin: 0; color: #1f2937; }
  footer { text-align: center; color: #9ca3af; font-size: 12px; margin-top: 40px; padding-top: 16px; border-top: 1px solid #e5e7eb; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>MCP Security Scan Report</h1>
    <div class="score-badge">
      <span class="score-number" style="color:${color}">${result.score}/100</span>
      <span class="grade-badge" style="background:${color}">${result.grade}</span>
    </div>
    <div class="meta">
      <span>Target: ${result.target}</span> &#183;
      <span>Files: ${result.filesScanned}</span> &#183;
      <span>${new Date(result.scannedAt).toLocaleString()}</span>
    </div>
  </div>

  ${zeroMsg}

  ${result.findings.length > 0
    ? `<div style="background:white;border-radius:8px;padding:16px;margin-bottom:24px;box-shadow:0 1px 2px rgba(0,0,0,0.05)">
        <h2 style="font-size:16px;margin:0 0 4px 0">Findings Summary</h2>
        <table>
          <tr><th>Severity</th><th style="text-align:center">Count</th></tr>
          ${summaryRows}
        </table>
      </div>
      ${findingBlocks}`
    : ''}
</div>
<footer>Generated by MCP Server Security Scanner</footer>
</body>
</html>`;

  writeFileSync(outputPath, html, 'utf8');
}
