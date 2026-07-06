import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';

const MCP_CONFIG_KEYS = ['mcpServers', 'tools', 'command', 'transport', 'capabilities'];
const MCP_SDK_PACKAGES = ['@modelcontextprotocol/sdk', '@modelcontextprotocol/inspector'];
const LOCK_FILE_NAMES = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb'];

export async function findMcpConfigFiles(files: string[]): Promise<string[]> {
  const matched: string[] = [];

  for (const file of files) {
    try {
      const content = await readFile(file, 'utf-8');
      const lowerName = file.toLowerCase();
      const lowerContent = content.toLowerCase();

      if (isJsonOrYaml(lowerName) && !isLockFile(lowerName)) {
        if (containsMcpConfigKeys(lowerContent)) {
          matched.push(file);
          continue;
        }
      }

      if (isPackageJson(lowerName)) {
        if (containsMcpDependency(content)) {
          matched.push(file);
          continue;
        }
      }

      if (isSourceFile(lowerName)) {
        if (importsFromMcpSdk(content)) {
          matched.push(file);
          continue;
        }
      }
    } catch {
      // skip unreadable files
    }
  }

  return matched;
}

function isLockFile(filePath: string): boolean {
  return LOCK_FILE_NAMES.includes(basename(filePath));
}

function isJsonOrYaml(fileName: string): boolean {
  return (
    fileName.endsWith('.json') ||
    fileName.endsWith('.yaml') ||
    fileName.endsWith('.yml')
  );
}

function containsMcpConfigKeys(content: string): boolean {
  return MCP_CONFIG_KEYS.some((key) => content.includes(key.toLowerCase()));
}

function isPackageJson(fileName: string): boolean {
  return fileName.endsWith('package.json');
}

function containsMcpDependency(content: string): boolean {
  try {
    const pkg = JSON.parse(content);
    const deps = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
      ...(pkg.peerDependencies || {}),
    };
    return MCP_SDK_PACKAGES.some((sdk) => deps[sdk] !== undefined);
  } catch {
    return false;
  }
}

function isSourceFile(fileName: string): boolean {
  return (
    fileName.endsWith('.js') ||
    fileName.endsWith('.ts') ||
    fileName.endsWith('.mjs') ||
    fileName.endsWith('.cjs')
  );
}

function importsFromMcpSdk(content: string): boolean {
  const importRegex = /from\s+['"]@modelcontextprotocol\/sdk['"]/;
  const requireRegex = /require\(['"]@modelcontextprotocol\/sdk['"]\)/;
  return importRegex.test(content) || requireRegex.test(content);
}
