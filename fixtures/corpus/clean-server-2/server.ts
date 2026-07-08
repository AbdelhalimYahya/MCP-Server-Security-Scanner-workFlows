import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const server = new Server({
  name: 'readonly-server',
  version: '0.1.0',
});

server.setRequestHandler({ method: 'tools/list' }, async () => ({
  tools: [
    {
      name: 'current-time',
      description: 'Returns the current server time',
      inputSchema: {
        type: 'object',
        properties: {},
      },
    },
  ],
}));

server.setRequestHandler({ method: 'tools/call' }, async () => {
  return { content: [{ type: 'text', text: new Date().toISOString() }] };
});

const transport = new StdioServerTransport();
await server.connect(transport);
