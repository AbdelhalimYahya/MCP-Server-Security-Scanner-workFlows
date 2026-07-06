import { describe, it, expect } from 'vitest';
import { mkdir, writeFile, rm } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { findMcpConfigFiles } from './mcpConfigDetector.js';

async function withTempFiles(
  contents: Record<string, string>,
  fn: (dir: string, files: string[]) => Promise<void>,
): Promise<void> {
  const base = join(tmpdir(), `mcp-scan-test-${randomUUID()}`);
  const createdFiles: string[] = [];
  try {
    for (const [filePath, content] of Object.entries(contents)) {
      const fullPath = join(base, filePath);
      createdFiles.push(fullPath);
      await mkdir(dirname(fullPath), { recursive: true });
      await writeFile(fullPath, content);
    }
    await fn(base, createdFiles);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
}

describe('findMcpConfigFiles', () => {
  it('detects MCP config in JSON files with mcpServers key', async () => {
    await withTempFiles(
      {
        'mcp.json': JSON.stringify({ mcpServers: { serverName: { command: 'node' } } }),
        'unrelated.json': JSON.stringify({ name: 'test', version: '1.0.0' }),
      },
      async (_base, files) => {
        const result = await findMcpConfigFiles(files);
        expect(result).toHaveLength(1);
        expect(result[0]).toMatch(/mcp\.json$/);
      },
    );
  });

  it('detects MCP config in YAML files with transport key', async () => {
    await withTempFiles(
      {
        'config.yaml': 'transport: sse\ncapabilities:\n  tools: true',
        'notes.yaml': 'title: hello',
      },
      async (_base, files) => {
        const result = await findMcpConfigFiles(files);
        expect(result).toHaveLength(1);
        expect(result[0]).toMatch(/config\.yaml$/);
      },
    );
  });

  it('detects package.json with @modelcontextprotocol/sdk dependency', async () => {
    await withTempFiles(
      {
        'package.json': JSON.stringify({
          name: 'mcp-server',
          dependencies: { '@modelcontextprotocol/sdk': '^1.0.0' },
        }),
        'other/package.json': JSON.stringify({
          name: 'other',
          dependencies: { express: '^4.0.0' },
        }),
      },
      async (_base, files) => {
        const result = await findMcpConfigFiles(files);
        expect(result).toHaveLength(1);
        expect(result[0]).toMatch(/package\.json$/);
        expect(result[0]).not.toMatch(/other/);
      },
    );
  });

  it('detects source files importing from @modelcontextprotocol/sdk', async () => {
    await withTempFiles(
      {
        'server.ts': "import { Server } from '@modelcontextprotocol/sdk';",
        'utils.js': 'const x = 1;',
      },
      async (_base, files) => {
        const result = await findMcpConfigFiles(files);
        expect(result).toHaveLength(1);
        expect(result[0]).toMatch(/server\.ts$/);
      },
    );
  });

  it('returns empty array for files with no MCP signals', async () => {
    await withTempFiles(
      {
        'readme.md': '# just docs',
        'app.js': 'console.log("hello");',
        'data.xml': '<root/>',
      },
      async (_base, files) => {
        const result = await findMcpConfigFiles(files);
        expect(result).toEqual([]);
      },
    );
  });

  it('handles unreadable files gracefully (no crash)', async () => {
    const result = await findMcpConfigFiles(['\\\\nonexistent\\share\\file.json']);
    expect(result).toEqual([]);
  });
});
