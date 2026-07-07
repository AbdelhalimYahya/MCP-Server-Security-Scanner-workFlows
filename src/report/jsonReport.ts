import type { ScanResult } from '../types.js';
import { writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';

export function writeJsonReport(result: ScanResult, outputPath: string): void {
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf8');
}
