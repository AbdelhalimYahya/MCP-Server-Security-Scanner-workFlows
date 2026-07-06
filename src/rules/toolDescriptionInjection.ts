import type { Rule, Finding } from '../types.js';

const TOOL_NAME_RE = /\bname\s*[=:]\s*['"`][^'"`]+['"`]/;
const INPUT_SCHEMA_RE = /\binputSchema\s*[:=]/;
const SERVER_TOOL_CALL_RE = /server\.tool\s*\(\s*['"`][^'"`]+['"`]\s*,\s*['"`]([^'"`]+)['"`]/;
const SERVER_TOOL_RE = /server\.tool\s*\(/;

const DESC_LINE_RE = /\bdescription\s*[=:]\s*['"`]([^'"`]+)['"`]/;
const DESC_TEMPLATE_START_RE = /\bdescription\s*[=:]\s*`/;

const INJECTION_PHRASES = [
  /ignore\s+(?:previous|all|prior)\s+(?:instructions|commands|directives)/i,
  /you\s+must\s+always/i,
  /do\s+not\s+tell\s+(?:the\s+)?(?:user|human)/i,
  /always\s+respond\s+with/i,
  /^\s*system\s*:/im,
  /^\s*assistant\s*:/im,
  /override\s+(?:all\s+)?(?:instructions|commands|directives)/i,
  /disregard\s+(?:previous|all|prior)/i,
  /never\s+(?:tell|reveal|disclose|show|mention)/i,
  /pretend\s+(?:that\s+)?(?:you\s+)?(?:are|to)/i,
];

const INVISIBLE_UNICODE_RE = /[\u200b-\u200f\u2028-\u202f\u2060-\u2064\ufeff\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u2000-\u200a\u2028\u2029\u202a-\u202e\u2066-\u2069\u2800\u3164\uffa0]/;

const BASE64_BLOB_RE = /[A-Za-z0-9+/]{40,}/;

function extractBacktickBlock(lines: string[], startIdx: number): { text: string; endIdx: number } | null {
  if (!lines[startIdx].includes('`')) return null;
  const before = lines[startIdx].substring(0, lines[startIdx].indexOf('`'));
  let after = lines[startIdx].substring(lines[startIdx].indexOf('`') + 1);
  let text = '';
  let j = startIdx;

  while (j < lines.length) {
    const idx = after.indexOf('`');
    if (idx !== -1) {
      text += after.substring(0, idx);
      return { text, endIdx: j };
    }
    text += after + '\n';
    j++;
    after = lines[j];
  }
  return { text, endIdx: j - 1 };
}

function findToolDescriptions(lines: string[]): Array<{ text: string; line: number; snippet: string }> {
  const results: Array<{ text: string; line: number; snippet: string }> = [];
  const parsedLines = new Set<number>();

  for (let i = 0; i < lines.length; i++) {
    if (parsedLines.has(i)) continue;
    const line = lines[i];

    if (!isToolContext(lines, i)) continue;

    // Check for single-line server.tool("name", "desc", ...)
    const posMatch = line.match(SERVER_TOOL_CALL_RE);
    if (posMatch) {
      results.push({ text: posMatch[1], line: i + 1, snippet: line.trim() });
      parsedLines.add(i);
      continue;
    }

    // Multi-line server.tool("name", "desc", ...) where args span multiple lines
    if (SERVER_TOOL_RE.test(line) && !parsedLines.has(i)) {
      // Collect the full argument block within server.tool(...)
      let argBlock = '';
      let parenDepth = 0;
      let started = false;
      let descText: string | null = null;
      let descLine = -1;

      for (let j = i; j < lines.length; j++) {
        const l = lines[j];
        let inBacktick = false;
        for (let ci = 0; ci < l.length; ci++) {
          const ch = l[ci];
          if (ch === '`') { inBacktick = !inBacktick; }
          if (inBacktick) continue;
          if (ch === '(') { parenDepth++; started = true; }
          if (ch === ')') { parenDepth--; }
        }
        if (!started) continue;
        if (j > i) argBlock += '\n';
        argBlock += l;
        if (parenDepth <= 0) break;
      }

      // Extract the second string/backtick argument from argBlock
      let scanPos = 0;
      let strArgCount = 0;
      // Skip past the function name and first paren
      const parenIdx = argBlock.indexOf('(');
      if (parenIdx >= 0) scanPos = parenIdx + 1;

      while (scanPos < argBlock.length) {
        // Skip whitespace and commas
        const remain = argBlock.slice(scanPos);
        const trimMatch = remain.match(/^\s*,\s*/);
        if (trimMatch) { scanPos += trimMatch[0].length; continue; }
        const spaceMatch = remain.match(/^\s+/);
        if (spaceMatch) { scanPos += spaceMatch[0].length; continue; }

        // Check for string literal
        if (remain[0] === '"' || remain[0] === "'") {
          const quote = remain[0];
          const endIdx = remain.indexOf(quote, 1);
          if (endIdx > 0) {
            strArgCount++;
            const content = remain.slice(1, endIdx);
            if (strArgCount === 2) {
              descText = content;
              descLine = i + lines.slice(i, i + 10).findIndex((_, idx) => {
                const lineIdx = i + idx;
                return lineIdx < lines.length && lines[lineIdx].includes(quote);
              });
              if (descLine < 0) descLine = i;
              break;
            }
            scanPos += endIdx + 1;
            continue;
          }
        }

        // Check for backtick (multi-line possible)
        if (remain[0] === '`') {
          const endIdx = remain.indexOf('`', 1);
          strArgCount++;
          if (endIdx > 0) {
            const content = remain.slice(1, endIdx);
            if (strArgCount === 2) {
              descText = content;
              // Find the line where this backtick block ends
              let accumLines = 0;
              let tempScan = 0;
              for (let li = 0; li < lines.length - i; li++) {
                const l = lines[i + li];
                tempScan += l.length + 1; // +1 for newline
                if (tempScan > scanPos + endIdx) {
                  descLine = i + li;
                  break;
                }
              }
              if (descLine < 0) descLine = i;
              break;
            }
            scanPos += endIdx + 1;
          } else {
            // Unclosed backtick - this is a multi-line template literal
            if (strArgCount === 2) {
              // Find the closing backtick in subsequent argBlock
              const remainingBlock = remain.slice(1);
              const closeIdx = remainingBlock.indexOf('`');
              if (closeIdx >= 0) {
                descText = remainingBlock.slice(0, closeIdx);
              } else {
                descText = remainingBlock;
              }
              let accumLines = 0;
              let tempScan = 0;
              for (let li = 0; li < lines.length - i; li++) {
                const l = lines[i + li];
                tempScan += l.length + 1;
                if (tempScan > scanPos + (closeIdx >= 0 ? closeIdx + 1 : remain.length)) {
                  descLine = i + li;
                  break;
                }
              }
              if (descLine < 0) descLine = i;
              break;
            }
            // Not second arg yet, find closing backtick
            const remClose = remain.indexOf('`', 1);
            if (remClose > 0) scanPos += remClose + 1;
            else break; // can't find close
          }
          continue;
        }

        // Skip other tokens (identifiers, braces, etc.)
        const tokenMatch = remain.match(/^[^\s,)'"]+/);
        if (tokenMatch) { scanPos += tokenMatch[0].length; continue; }
        break;
      }

      if (descText !== null && descLine >= 0 && isToolContext(lines, i)) {
        results.push({ text: descText, line: descLine + 1, snippet: lines[descLine].trim() });
        for (let k = i; k <= descLine; k++) parsedLines.add(k);
        continue;
      }
    }

    // Check for description: `...` (multi-line template literal)
    const templMatch = line.match(DESC_TEMPLATE_START_RE);
    if (templMatch) {
      const btResult = extractBacktickBlock(lines, i);
      if (btResult) {
        results.push({ text: btResult.text, line: i + 1, snippet: line.trim() });
        for (let k = i; k <= btResult.endIdx; k++) parsedLines.add(k);
        continue;
      }
    }

    // Single-line description: "..." or description: '...'
    const oneLineMatch = line.match(DESC_LINE_RE);
    if (oneLineMatch) {
      results.push({ text: oneLineMatch[1], line: i + 1, snippet: line.trim() });
      parsedLines.add(i);
    }
  }

  return results;
}

function isToolContext(lines: string[], idx: number): boolean {
  const start = Math.max(0, idx - 5);
  const end = Math.min(lines.length - 1, idx + 15);
  let hasName = false, hasSchemaOrServer = false;
  let hasPosTool = false;
  for (let i = start; i <= end; i++) {
    if (TOOL_NAME_RE.test(lines[i])) hasName = true;
    if (INPUT_SCHEMA_RE.test(lines[i]) || SERVER_TOOL_RE.test(lines[i])) hasSchemaOrServer = true;
    if (SERVER_TOOL_CALL_RE.test(lines[i])) hasPosTool = true;
  }
  // server.tool(...) alone implies a tool definition (name + desc are positional args)
  if (hasSchemaOrServer) return true;
  return hasPosTool || (hasName && hasSchemaOrServer);
}

export const toolDescriptionInjectionRule: Rule = {
  id: 'TOOL_DESCRIPTION_INJECTION_RISK',
  name: 'Tool Description / Prompt Injection Risk',
  severity: 'medium',

  check(fileContent: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = fileContent.split('\n');
    const descriptions = findToolDescriptions(lines);

    for (const desc of descriptions) {
      const { text, line, snippet } = desc;

      for (const phrase of INJECTION_PHRASES) {
        const phraseMatch = text.match(phrase);
        if (phraseMatch) {
          findings.push({
            id: this.id,
            severity: 'medium',
            title: 'Tool description contains agent-injection phrasing',
            description: `The tool description contains "${phraseMatch[0].trim()}" — imperative instruction language aimed at manipulating an AI agent's behavior rather than describing the tool to a human developer. Tool descriptions are included verbatim in the LLM's context and can be used for prompt injection.`,
            file: filePath,
            line,
            snippet,
            recommendation:
              'Rewrite this description in plain, factual language describing what the tool does (e.g., "Creates a new user record"), not instructions to the AI model about how to behave. Tool descriptions should describe the tool, not command the agent.',
          });
        }
      }

      if (text.length > 500) {
        findings.push({
          id: this.id,
          severity: 'medium',
          title: 'Suspiciously long tool description (>500 characters)',
          description: `This tool description is ${text.length} characters long. Legitimate tool descriptions are normally concise (under 200 characters). Unusually long descriptions are a common prompt-injection vector because they can embed hidden instructions among verbose text.`,
          file: filePath,
          line,
          snippet,
          recommendation:
            'Trim this description to 200 characters or less. If you need to provide extended context to the LLM, use a dedicated configuration mechanism rather than the tool description field.',
        });
      }

      if (INVISIBLE_UNICODE_RE.test(text)) {
        const invisibleChars = [...text].filter((c) => INVISIBLE_UNICODE_RE.test(c));
        const hexCodes = [...new Set(invisibleChars.map((c) => 'U+' + c.charCodeAt(0).toString(16).padStart(4, '0')))].join(', ');
        findings.push({
          id: this.id,
          severity: 'medium',
          title: 'Tool description contains hidden unicode characters',
          description: `The tool description contains ${invisibleChars.length} invisible unicode character(s) (${hexCodes}). These characters are not visible to a human reader but are processed by the AI model, and are commonly used to smuggle prompt injection payloads past human review.`,
          file: filePath,
          line,
          snippet,
          recommendation:
            'Remove all invisible/control unicode characters from the description. Use a plain-text validator to ensure only visible ASCII or common printable unicode characters are present.',
        });
      }

      const base64Match = text.match(BASE64_BLOB_RE);
      if (base64Match) {
        findings.push({
          id: this.id,
          severity: 'medium',
          title: 'Tool description contains base64-encoded blob',
          description: `A ${base64Match[0].length}-character base64-like string was found embedded in the tool description. Base64 blobs are not human-readable and are sometimes used to encode instructions or data that bypass human review but are decoded by the AI model.`,
          file: filePath,
          line,
          snippet,
          recommendation:
            'Remove the base64-encoded data from the description. If binary data needs to be provided to the tool, pass it as a tool parameter rather than encoding it into the description string.',
        });
      }
    }

    return findings;
  },
};
