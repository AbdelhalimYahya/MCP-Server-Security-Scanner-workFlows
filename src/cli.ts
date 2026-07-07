#!/usr/bin/env node

import { Command } from 'commander';
import { mkdtemp, rm, access } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { simpleGit } from 'simple-git';

import { isGitHubUrl, normalizeGitHubUrl } from './scanner/gitUtils.js';
import { runScan } from './scanner/runScan.js';
import { printTerminalReport } from './report/terminalReport.js';
import { writeJsonReport } from './report/jsonReport.js';
import { writeHtmlReport } from './report/htmlReport.js';
import type { Severity } from './types.js';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function parseSeverity(val: string): Severity {
  const lower = val.toLowerCase() as Severity;
  if (!SEVERITY_ORDER.includes(lower)) {
    console.error(`Invalid severity level: "${val}". Must be one of: ${SEVERITY_ORDER.join(', ')}`);
    process.exit(1);
  }
  return lower;
}

function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

const program = new Command();

program
  .name('mcp-scan')
  .description('A security scanner for MCP (Model Context Protocol) servers')
  .version('0.1.0')
  .addHelpText('after', `
Examples:
  mcp-scan scan ./path/to/mcp-server
  mcp-scan scan https://github.com/owner/repo
  mcp-scan scan owner/repo --json ./report.json --no-html
  mcp-scan scan ./path --quiet --min-severity high
  npx mcp-scan scan ./path`);

program
  .command('scan <target>')
  .description('Scan an MCP server for security issues')
  .option('--json <path>', 'Write JSON report to this path (default: ./mcp-scan-report.json)', 'mcp-scan-report.json')
  .option('--html <path>', 'Write HTML report to this path (default: ./mcp-scan-report.html)', 'mcp-scan-report.html')
  .option('--no-html', 'Skip HTML report generation')
  .option('--min-severity <level>', 'Only print findings at or above this severity', parseSeverity, 'info')
  .option('--quiet', 'Suppress terminal report, just write files')
  .action(async (target: string, options: { json: string; html: string | false; minSeverity: Severity; quiet: boolean }) => {
    try {
      if (!isGitHubUrl(target)) {
        try {
          await access(target);
        } catch {
          console.error(`Error: target path does not exist or is not readable: ${target}`);
          process.exit(1);
        }
      }

      const jsonPath = resolve(options.json);
      const htmlPath = options.html !== false ? resolve(options.html) : null;

      let scanTarget = target;
      let clonedDir: string | null = null;

      if (isGitHubUrl(target)) {
        const repoUrl = normalizeGitHubUrl(target);
        if (!options.quiet) console.log('Cloning repository...');
        const tmpDir = await mkdtemp(join(tmpdir(), 'mcp-scan-'));
        clonedDir = tmpDir;
        try {
          await simpleGit().clone(repoUrl, tmpDir, ['--depth', '1']);
          console.log('Repository cloned successfully.');
          scanTarget = tmpDir;
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          console.error(`Failed to clone repository: ${message}`);
          console.error('Make sure the repository exists, is public, and the URL is correct.');
          process.exit(1);
        }
      }

      const result = await runScan(scanTarget);

      const filteredResult = {
        ...result,
        findings: result.findings.filter((f) => severityRank(f.severity) <= severityRank(options.minSeverity)),
      };

      if (!options.quiet) {
        printTerminalReport(filteredResult);
      }

      try {
        writeJsonReport(result, jsonPath);
        if (!options.quiet) {
          console.log(`JSON report saved to: ${jsonPath}`);
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`Failed to write JSON report: ${message}`);
      }

      if (htmlPath) {
        try {
          writeHtmlReport(result, htmlPath);
          if (!options.quiet) {
            console.log(`HTML report saved to: ${htmlPath}`);
          }
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          console.error(`Failed to write HTML report: ${message}`);
        }
      }

      if (clonedDir) {
        await rm(clonedDir, { recursive: true, force: true }).catch(() => {});
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Scan failed: ${message}`);
      process.exit(1);
    }
  });

program.parse(process.argv);
