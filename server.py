import json
import os
import urllib.error
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class CyberMirrorHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/urlscan/result':
            self.proxy_scan_result()
            return
        if self.path != '/api/urlscan':
            self.send_json(404, {'message': 'Not found'})
            return

        length = int(self.headers.get('Content-Length', 0))
        try:
            request_data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError):
            self.send_json(400, {'message': 'Invalid request body'})
            return

        url = request_data.get('url')
        api_key = request_data.get('apiKey')
        if not url or not api_key:
            self.send_json(400, {'message': 'URL and API key are required'})
            return

        payload = json.dumps({'url': url, 'visibility': 'unlisted'}).encode('utf-8')
        upstream_request = urllib.request.Request(
            'https://urlscan.io/api/v1/scan/',
            data=payload,
            headers={'Content-Type': 'application/json', 'API-Key': api_key},
            method='POST'
        )

        try:
            with urllib.request.urlopen(upstream_request, timeout=30) as upstream_response:
                self.send_json(upstream_response.status, json.loads(upstream_response.read()))
        except urllib.error.HTTPError as error:
            try:
                error_body = json.loads(error.read())
            except json.JSONDecodeError:
                error_body = {'message': f'urlscan.io returned {error.code}'}
            error_body['status'] = error.code
            self.send_json(error.code, error_body)
        except urllib.error.URLError as error:
            self.send_json(502, {'message': f'Could not reach urlscan.io: {error.reason}'})

    def proxy_scan_result(self):
        length = int(self.headers.get('Content-Length', 0))
        try:
            request_data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError):
            self.send_json(400, {'message': 'Invalid request body'})
            return

        uuid = request_data.get('uuid')
        api_key = request_data.get('apiKey')
        if not uuid or not api_key:
            self.send_json(400, {'message': 'Scan ID and API key are required'})
            return

        upstream_request = urllib.request.Request(
            f'https://urlscan.io/api/v1/result/{uuid}/',
            headers={'API-Key': api_key},
            method='GET'
        )
        try:
            with urllib.request.urlopen(upstream_request, timeout=30) as upstream_response:
                self.send_json(upstream_response.status, json.loads(upstream_response.read()))
        except urllib.error.HTTPError as error:
            try:
                error_body = json.loads(error.read())
            except json.JSONDecodeError:
                error_body = {'message': f'urlscan.io returned {error.code}'}
            error_body['status'] = error.code
            self.send_json(error.code, error_body)
        except urllib.error.URLError as error:
            self.send_json(502, {'message': f'Could not reach urlscan.io: {error.reason}'})

    def send_json(self, status, payload):
        response_body = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '3000'))
    server = ThreadingHTTPServer(('localhost', port), CyberMirrorHandler)
    print(f'CyberMirror running at http://localhost:{port}')
    server.serve_forever()