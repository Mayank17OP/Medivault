#!/usr/bin/env python3
import os
import subprocess
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import requests
import json

class MediVaultProxyHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory='.', **kwargs)
    
    def do_GET(self):
        # Check if it's an API request or auth request
        if self.path.startswith('/api/') or self.path.startswith('/auth/'):
            self.proxy_to_backend()
        else:
            # Serve static files
            super().do_GET()
    
    def do_POST(self):
        if self.path.startswith('/api/') or self.path.startswith('/auth/'):
            self.proxy_to_backend()
        else:
            self.send_error(404)
    
    def do_PUT(self):
        if self.path.startswith('/api/') or self.path.startswith('/auth/'):
            self.proxy_to_backend()
        else:
            self.send_error(404)
    
    def do_DELETE(self):
        if self.path.startswith('/api/') or self.path.startswith('/auth/'):
            self.proxy_to_backend()
        else:
            self.send_error(404)
    
    def proxy_to_backend(self):
        try:
            # Backend URL
            backend_url = f'http://localhost:8000{self.path}'
            
            # Read request body if present
            content_length = int(self.headers.get('Content-Length', 0))
            body = None
            if content_length > 0:
                body = self.rfile.read(content_length)
            
            # Prepare headers
            headers = {}
            for header, value in self.headers.items():
                if header.lower() not in ['host', 'content-length']:
                    headers[header] = value
            
            # Make request to backend
            response = requests.request(
                method=self.command,
                url=backend_url,
                data=body,
                headers=headers,
                timeout=30
            )
            
            # Send response back to client
            self.send_response(response.status_code)
            for header, value in response.headers.items():
                if header.lower() not in ['content-length', 'transfer-encoding']:
                    self.send_header(header, value)
            self.end_headers()
            
            if response.content:
                self.wfile.write(response.content)
                
        except requests.exceptions.ConnectionError:
            self.send_error(502, "Backend not available")
        except Exception as e:
            print(f"Proxy error: {e}")
            self.send_error(500, "Proxy error")

def start_backend():
    """Start the Flask backend in a subprocess"""
    try:
        subprocess.run(['python', 'simple_app.py'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Backend failed to start: {e}")

def start_proxy():
    """Start the proxy server"""
    server = HTTPServer(('0.0.0.0', 5000), MediVaultProxyHandler)
    print("MediVault proxy server running on http://0.0.0.0:5000")
    server.serve_forever()

if __name__ == '__main__':
    # Start backend in a separate thread
    backend_thread = threading.Thread(target=start_backend, daemon=True)
    backend_thread.start()
    
    # Give backend time to start
    time.sleep(3)
    
    # Start proxy server
    start_proxy()