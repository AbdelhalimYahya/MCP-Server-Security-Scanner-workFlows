/** Severity level of a security finding. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** A single security issue detected during a scan. */
export interface Finding {
  /** Unique rule identifier, e.g. "PLAINTEXT_SECRET" */
  id: string;
  /** How severe this issue is */
  severity: Severity;
  /** Short human-readable title of the issue */
  title: string;
  /** Plain-English explanation of the risk */
  description: string;
  /** Relative path to the file where the issue was found */
  file: string;
  /** Line number where the issue was found (if applicable) */
  line?: number;
  /** The offending line of code, redacted if it contains a secret */
  snippet?: string;
  /** Plain-English recommendation for how to fix the issue */
  recommendation: string;
}

/** The complete result of scanning a target. */
export interface ScanResult {
  /** The path or URL that was scanned */
  target: string;
  /** ISO-8601 timestamp of when the scan was performed */
  scannedAt: string;
  /** Total number of files scanned */
  filesScanned: number;
  /** All security findings discovered during the scan */
  findings: Finding[];
  /** Overall security score from 0 (worst) to 100 (best) */
  score: number;
  /** Letter grade derived from the score */
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
}

/** Interface that every detection rule must implement. */
export interface Rule {
  /** Unique rule identifier, e.g. "INSECURE_NETWORK_BINDING" */
  id: string;
  /** Human-readable rule name */
  name: string;
  /** Default severity for findings produced by this rule */
  severity: Severity;
  /**
   * Run the rule against a file's content.
   * @param fileContent - The full text content of the file
   * @param filePath - Relative path to the file (for reporting)
   * @returns An array of Findings (empty if no issues detected)
   */
  check(fileContent: string, filePath: string): Finding[];
}
