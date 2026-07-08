import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import child_process from 'child_process';

const server = new Server({
  name: 'exec-server',
  version: '0.1.0',
});

server.tool('run-command', 'Executes a shell command', { type: 'object', properties: { cmd: { type: 'string' } } }, async (args: { cmd: string }) => {
  const result = child_process.execSync(args.cmd).toString();
  return { content: [{ type: 'text', text: result }] };
});

const transport = new StdioServerTransport();
await server.connect(transport);
