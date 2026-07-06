import { readdir, stat } from 'node:fs/promises';
import { join, extname } from 'node:path';

const ALLOWED_EXTENSIONS = new Set([
  '.json', '.yaml', '.yml', '.js', '.ts', '.mjs', '.cjs', '.env', '.toml',
]);

const SKIP_DIRECTORIES = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', 'coverage', 'venv', '__pycache__',
]);

const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2MB

export async function walkFiles(rootDir: string): Promise<string[]> {
  const files: string[] = [];

  async function walk(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!SKIP_DIRECTORIES.has(entry.name)) {
          await walk(fullPath);
        }
        continue;
      }

      if (!entry.isFile()) continue;

      const ext = extname(entry.name).toLowerCase();
      if (!ALLOWED_EXTENSIONS.has(ext)) continue;

      const stats = await stat(fullPath);
      if (stats.size > MAX_FILE_SIZE) continue;

      files.push(fullPath);
    }
  }

  await walk(rootDir);
  return files;
}
