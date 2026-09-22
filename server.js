const http = require('http');
const fs = require('fs');
const path = require('path');

const port = process.env.PORT || 3000;
const root = __dirname;

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify(payload));
}

function serveFile(request, response) {
  const requestedPath = request.url === '/' ? '/index.html' : request.url;
  const filePath = path.join(root, path.normalize(requestedPath));
  if (!filePath.startsWith(root)) {
    sendJson(response, 403, { message: 'Forbidden' });
    return;
  }

  const contentTypes = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript' };
  fs.readFile(filePath, (error, content) => {
    if (error) {
      sendJson(response, 404, { message: 'File not found' });
      return;
    }
    response.writeHead(200, { 'Content-Type': contentTypes[path.extname(filePath)] || 'application/octet-stream' });
    response.end(content);
  });
}

function proxyUrlScan(request, response) {
  let body = '';
  request.on('data', (chunk) => { body += chunk; });
  request.on('end', () => {
    let requestData;
    try {
      requestData = JSON.parse(body);
    } catch (error) {
      sendJson(response, 400, { message: 'Invalid request body' });
      return;
    }

    const apiKey = requestData.apiKey;
    if (!apiKey || !requestData.url) {
      sendJson(response, 400, { message: 'URL and API key are required' });
      return;
    }

    fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'API-Key': apiKey },
      body: JSON.stringify({ url: requestData.url, visibility: 'unlisted' })
    })
      .then(async (scanResponse) => {
        const scanBody = await scanResponse.text();
        response.writeHead(scanResponse.status, { 'Content-Type': 'application/json' });
        response.end(scanBody);
      })
      .catch((error) => sendJson(response, 502, { message: error.message }));
  });
}

function proxyScanResult(request, response) {
  let body = '';
  request.on('data', (chunk) => { body += chunk; });
  request.on('end', () => {
    let requestData;
    try {
      requestData = JSON.parse(body);
    } catch (error) {
      sendJson(response, 400, { message: 'Invalid request body' });
      return;
    }

    if (!requestData.uuid || !requestData.apiKey) {
      sendJson(response, 400, { message: 'Scan ID and API key are required' });
      return;
    }

    fetch(`https://urlscan.io/api/v1/result/${encodeURIComponent(requestData.uuid)}/`, {
      headers: { 'API-Key': requestData.apiKey }
    })
      .then(async (scanResponse) => {
        const scanBody = await scanResponse.text();
        response.writeHead(scanResponse.status, { 'Content-Type': 'application/json' });
        response.end(scanBody);
      })
      .catch((error) => sendJson(response, 502, { message: error.message }));
  });
}

http.createServer((request, response) => {
  if (request.method === 'POST' && request.url === '/api/urlscan') {
    proxyUrlScan(request, response);
    return;
  }
  if (request.method === 'POST' && request.url === '/api/urlscan/result') {
    proxyScanResult(request, response);
    return;
  }
  if (request.method === 'GET') {
    serveFile(request, response);
    return;
  }
  sendJson(response, 405, { message: 'Method not allowed' });
}).listen(port, () => {
  console.log(`CyberMirror running at http://localhost:${port}`);
});