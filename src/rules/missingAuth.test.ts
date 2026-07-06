import { describe, it, expect } from 'vitest';
import { missingAuthRule } from './missingAuth.js';

function run(content: string, filePath = 'src/server.ts') {
  return missingAuthRule.check(content, filePath);
}

describe('missingAuthRule', () => {
  describe('stdio transport — should NOT flag', () => {
    it('does not flag stdio transport', () => {
      const content = `
import { Server } from '@modelcontextprotocol/sdk';
const server = new Server();
server.start({ transport: 'stdio' });
`;
      const findings = run(content);
      expect(findings.length).toBe(0);
    });
  });

  describe('network transport with auth present — should NOT flag', () => {
    it('does not flag when Authorization header is checked', () => {
      const content = `
import express from 'express';
const app = express();
app.use((req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).send('Unauthorized');
  }
  next();
});
const transport = "sse";
app.listen(3000);
`;
      const findings = run(content);
      expect(findings.length).toBe(0);
    });

    it('does not flag when apiKey is checked', () => {
      const content = `
const config = { transport: "http" };
function checkApiKey(req) {
  const key = req.headers['x-api-key'];
  if (key !== process.env.API_KEY) throw new Error('forbidden');
}
`;
      const findings = run(content);
      expect(findings.length).toBe(0);
    });

    it('does not flag when trustedNetwork is true', () => {
      const content = `
const config = {
  transport: "websocket",
  trustedNetwork: true
};
`;
      const findings = run(content);
      expect(findings.length).toBe(0);
    });

    it('does not flag when JWT auth is used', () => {
      const content = `
const transport = "sse";
function authenticate(token) {
  return jwt.verify(token, process.env.JWT_SECRET);
}
`;
      const findings = run(content);
      expect(findings.length).toBe(0);
    });

    it('does not flag when requireAuth guard is present', () => {
      const content = `
const server = new Server({ transport: 'sse' });
server.use(requireAuth);
`;
      const findings = run(content);
      expect(findings.length).toBe(0);
    });
  });

  describe('network transport without auth — should flag critical', () => {
    it('flags sse transport without any auth', () => {
      const content = `
import { Server } from '@modelcontextprotocol/sdk';
const server = new Server();
const transport = "sse";
server.start();
`;
      const findings = run(content);
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].id).toBe('MISSING_AUTH_REMOTE_TRANSPORT');
    });

    it('flags http transport without any auth', () => {
      const content = `
const mcpConfig = {
  transport: "http",
  port: 3000
};
`;
      const findings = run(content);
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe('critical');
    });

    it('flags websocket transport without any auth', () => {
      const content = `
const transport = 'websocket';
const wss = new WebSocketServer({ port: 8080 });
`;
      const findings = run(content);
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe('critical');
    });
  });
});
