import { createServer } from 'http';

const server = createServer((req, res) => {
  res.end('OK');
});

server.listen(3000, '0.0.0.0', () => {
  console.log('Server listening on all interfaces');
});
