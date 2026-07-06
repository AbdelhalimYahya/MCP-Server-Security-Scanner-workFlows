import { describe, it, expect } from 'vitest';
import { insecureBindingRule } from './insecureBinding.js';

function run(content: string, filePath = 'src/server.ts') {
  return insecureBindingRule.check(content, filePath);
}

describe('insecureBindingRule', () => {
  describe('.listen("0.0.0.0") — should flag', () => {
    it('flags app.listen with 0.0.0.0', () => {
      const findings = run(`app.listen(3000, "0.0.0.0");`);
      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe('high');
      expect(findings[0].id).toBe('INSECURE_NETWORK_BINDING');
    });

    it('flags host: "0.0.0.0" in config', () => {
      const findings = run(`const config = { host: "0.0.0.0", port: 3000 };`);
      expect(findings).toHaveLength(1);
    });

    it('flags HOST=0.0.0.0 env pattern', () => {
      const findings = run(`HOST=0.0.0.0`);
      expect(findings).toHaveLength(1);
    });

    it('flags IPv6 all-interfaces "::"', () => {
      const findings = run(`server.listen(8080, "::");`);
      expect(findings).toHaveLength(1);
    });
  });

  describe('127.0.0.1 or localhost — should NOT flag', () => {
    it('does not flag 127.0.0.1 binding', () => {
      const findings = run(`app.listen(3000, "127.0.0.1");`);
      expect(findings).toHaveLength(0);
    });

    it('does not flag localhost binding', () => {
      const findings = run(`app.listen(3000, "localhost");`);
      expect(findings).toHaveLength(0);
    });

    it('does not flag host: "127.0.0.1"', () => {
      const findings = run(`const config = { host: "127.0.0.1", port: 3000 };`);
      expect(findings).toHaveLength(0);
    });
  });

  describe('stdio transport — should NOT flag', () => {
    it('does not flag stdio transport', () => {
      const content = `
import { Server } from '@modelcontextprotocol/sdk';
const server = new Server({ transport: 'stdio' });
server.start();
`;
      const findings = run(content);
      expect(findings).toHaveLength(0);
    });
  });

  describe('transport + auth — should NOT flag', () => {
    it('does not flag network transport with auth present', () => {
      const content = `
const transport = "sse";
const authToken = "abc123";
function checkAuth(req) {
  return req.headers.authorization === authToken;
}
`;
      const findings = run(content);
      expect(findings).toHaveLength(0);
    });
  });
});
