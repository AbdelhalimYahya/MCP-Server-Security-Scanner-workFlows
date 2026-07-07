#!/usr/bin/env node

import { Command } from 'commander';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { simpleGit } from 'simple-git';

import { isGitHubUrl, normalizeGitHubUrl } from './scanner/gitUtils.js';
import { runScan } from './scanner/runScan.js';

const program = new Command();

program
  .name('mcp-scan')
  .description('A security scanner for MCP (Model Context Protocol) servers')
  .version('0.1.0');

program
  .command('scan <target>')
  .description('Scan an MCP server for security issues')
  .action(async (target: string) => {
    try {
      if (isGitHubUrl(target)) {
        const repoUrl = normalizeGitHubUrl(target);
        console.log('Cloning repository...');
        const tmpDir = await mkdtemp(join(tmpdir(), 'mcp-scan-'));
        try {
          await simpleGit().clone(repoUrl, tmpDir, ['--depth', '1']);
          console.log('Repository cloned successfully.');
          const result = await runScan(tmpDir);
          console.log(`Target scanned: ${target}`);
          console.log(`Files scanned: ${result.filesScanned}`);
          console.log(`Findings: ${result.findings.length}`);
          result.findings.forEach((f) => {
            console.log(`  [${f.severity}] ${f.id}: ${f.title} (${f.file})`);
          });
          console.log(`Score: ${result.score} / Grade: ${result.grade}`);
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          console.error(`Failed to clone repository: ${message}`);
          console.error('Make sure the repository exists, is public, and the URL is correct.');
          process.exit(1);
        } finally {
          await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
        }
      } else {
        const result = await runScan(target);
        console.log(`Scanning target: ${target}`);
        console.log(`Files scanned: ${result.filesScanned}`);
        console.log(`Findings: ${result.findings.length}`);
        result.findings.forEach((f) => {
          console.log(`  [${f.severity}] ${f.id}: ${f.title} (${f.file})`);
        });
        console.log(`Score: ${result.score} / Grade: ${result.grade}`);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Scan failed: ${message}`);
      process.exit(1);
    }
  });

program.parse(process.argv);
