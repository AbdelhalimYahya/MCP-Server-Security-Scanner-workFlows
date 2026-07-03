#!/usr/bin/env node

import { Command } from 'commander';

const program = new Command();

program
  .name('mcp-scan')
  .description('A security scanner for MCP (Model Context Protocol) servers')
  .version('0.1.0');

program
  .command('scan <target>')
  .description('Scan an MCP server for security issues')
  .action((target: string) => {
    console.log(`Scanning target: ${target}`);
  });

program.parse(process.argv);
