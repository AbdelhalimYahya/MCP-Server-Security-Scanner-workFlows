import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from 'http';
import { readFileSync } from 'fs';
import { join } from 'path';

const API_KEY = process.env.API_KEY ?? 'fallback-dev-key';

const server = new Server({
  name: 'clean-server',
  version: '0.1.0',
});

server.setRequestHandler({ method: 'tools/list' }, async () => ({
  tools: [
    {
      name: 'get-config',
      description: 'Reads a configuration value',
      inputSchema: {
        type: 'object',
        properties: {
          key: { type: 'string' },
        },
      },
    },
  ],
}));

server.setRequestHandler({ method: 'tools/call' }, async (request) => {
  const authHeader = request.headers?.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new Error('Unauthorized');
  }
  const configPath = join(process.cwd(), 'config.json');
  const config = JSON.parse(readFileSync(configPath, 'utf8'));
  return { content: [{ type: 'text', text: config[request.params.arguments.key] }] };
});

const httpServer = createServer();
httpServer.listen(3000, '127.0.0.1', () => {
  console.log('Listening on localhost:3000');
});
