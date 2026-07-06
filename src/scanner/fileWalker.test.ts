import { describe, it, expect } from 'vitest';
import { mkdir, writeFile, rm } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { walkFiles } from './fileWalker.js';

async function createTempDir(contents: Record<string, string>): Promise<string> {
  const base = join(tmpdir(), `mcp-scan-test-${randomUUID()}`);
  for (const [filePath, content] of Object.entries(contents)) {
    const fullPath = join(base, filePath);
    const dir = dirname(fullPath);
    if (dir !== fullPath) {
      await mkdir(dir, { recursive: true });
    }
    await writeFile(fullPath, content);
  }
  return base;
}

async function cleanupTempDir(dir: string): Promise<void> {
  await rm(dir, { recursive: true });
}

describe('walkFiles', () => {
  it('finds allowed files and skips node_modules', async () => {
    const dir = await createTempDir({
      'config.json': '{}',
      'src/index.ts': 'console.log("hi");',
      'src/data.yaml': 'key: value',
      'node_modules/fake.js': 'should not appear',
      '.git/HEAD': 'ref: refs/heads/main',
      'dist/bundle.js': 'should not appear',
    });

    try {
      const files = await walkFiles(dir);
      const relative = files.map((f) => f.replace(dir, '').replace(/\\/g, '/'));

      expect(relative).toContain('/config.json');
      expect(relative).toContain('/src/index.ts');
      expect(relative).toContain('/src/data.yaml');
      expect(relative).not.toContain('/node_modules/fake.js');
      expect(relative).not.toContain('/.git/HEAD');
      expect(relative).not.toContain('/dist/bundle.js');
    } finally {
      await cleanupTempDir(dir);
    }
  });

  it('skips files larger than 2MB', async () => {
    const dir = await createTempDir({
      'small.json': '{}',
      'large.json': 'x'.repeat(3 * 1024 * 1024),
    });

    try {
      const files = await walkFiles(dir);
      expect(files).toHaveLength(1);
      expect(files[0]).toMatch(/small\.json$/);
    } finally {
      await cleanupTempDir(dir);
    }
  });

  it('returns only files with allowed extensions', async () => {
    const dir = await createTempDir({
      'a.json': '{}',
      'b.yaml': 'key: val',
      'c.txt': 'not scanned',
      'd.md': 'not scanned',
    });

    try {
      const files = await walkFiles(dir);
      const relative = files.map((f) => f.replace(dir, '').replace(/\\/g, '/')).sort();
      expect(relative).toEqual(['/a.json', '/b.yaml']);
    } finally {
      await cleanupTempDir(dir);
    }
  });

  it('returns absolute paths', async () => {
    const dir = await createTempDir({ 'file.json': '{}' });

    try {
      const files = await walkFiles(dir);
      expect(files).toHaveLength(1);
      expect(files[0]).toMatch(/^[A-Z]:\\|^\\/);
    } finally {
      await cleanupTempDir(dir);
    }
  });
});
