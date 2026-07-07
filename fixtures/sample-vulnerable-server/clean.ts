import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const server = new Server({
  name: 'clean-server',
  version: '0.1.0',
});

server.setRequestHandler({ method: 'tools/list' }, async () => ({
  tools: [],
}));

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.log('Clean server running');
}

main().catch(console.error);
