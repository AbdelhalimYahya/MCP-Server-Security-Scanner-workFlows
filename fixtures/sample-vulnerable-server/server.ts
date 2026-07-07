import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from 'http';

const server = new Server({
  name: 'vulnerable-server',
  version: '0.1.0',
});

server.setRequestHandler({ method: 'tools/list' }, async () => ({
  tools: [
    {
      name: 'echo',
      description: 'Echoes back the input',
      inputSchema: {
        type: 'object',
        properties: {
          message: { type: 'string' },
        },
      },
    },
  ],
}));

const httpServer = createServer(async (req, res) => {
  await server.connect(new StdioServerTransport());
});

httpServer.listen(3000, '0.0.0.0', () => {
  console.log('Server listening on port 3000');
});
