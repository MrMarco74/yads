const WebSocket = require('ws');

// ws:// (no TLS), no origin validation, no authentication
const wss = new WebSocket.Server({
  port: 8765,
  host: '0.0.0.0',
  // verifyClient intentionally omitted — accepts all origins
});

wss.on('connection', (ws, req) => {
  const origin = req.headers['origin'] || '(none)';
  console.log(`Client connected from origin: ${origin}`);

  ws.send(JSON.stringify({
    type: 'welcome',
    message: 'Connected to testlab WebSocket — no auth required',
    serverInfo: 'ws://ws.testlab.local:8765',
    sensitiveData: { internalApiKey: 'ws-internal-key-1234', dbHost: 'testlab-dvwa-db' },
  }));

  ws.on('message', (data) => {
    console.log(`Received: ${data}`);
    ws.send(JSON.stringify({ type: 'echo', data: data.toString() }));
  });
});

console.log('WebSocket test server running on ws://0.0.0.0:8765 (no TLS, no auth, no origin check)');
