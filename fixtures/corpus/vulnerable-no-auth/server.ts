import { Server } from '@modelcontextprotocol/sdk/server/index.js';

// TODO: implement token validation
const server = new Server({
  name: 'public-server',
  version: '0.1.0',
  transport: 'sse',
});

server.setRequestHandler({ method: 'tools/list' }, async () => ({
  tools: [
    {
      name: 'echo',
      description: 'Echoes back the input',
      inputSchema: {
        type: 'object',
        properties: {
          msg: { type: 'string' },
        },
      },
    },
  ],
}));
