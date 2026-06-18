#!/usr/bin/env python3
import json
import mimetypes
import os
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

import collector
import analyzer
import geoip

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / 'static'

cache = {}
cache_lock = threading.Lock()
collect_interval = 5


def collect_and_analyze():
    while True:
        try:
            data = collector.collect_all()
            analysis = analyzer.analyze(data)
            summary = analyzer.get_summary(analysis['alerts'])

            connections = data['connections']
            remote_ips = []
            for conn in connections:
                remote = conn.get('remote', '')
                if remote and ':' in remote:
                    ip = remote.rsplit(':', 1)[0]
                    if ip not in ('0.0.0.0', '::', '') and not ip.startswith('127.') and ip != '::1':
                        remote_ips.append(ip)
            country_map = geoip.resolve_batch(remote_ips)
            for conn in connections:
                remote = conn.get('remote', '')
                if remote and ':' in remote:
                    ip = remote.rsplit(':', 1)[0]
                    if ip in country_map:
                        name, code = country_map[ip]
                    else:
                        name, code = geoip.resolve(ip)
                    conn['country'] = name
                    conn['country_code'] = code

            payload = {
                'system': {
                    'hostname': data['hostname'],
                    'uptime': data['uptime'],
                    'os': data['os'],
                    'cpu_percent': data['cpu_percent'],
                    'memory': data['memory'],
                    'disk': data['disk'],
                    'load': data['load'],
                    'secure_boot': data['secure_boot'],
                },
                'interfaces': data['interfaces'],
                'ports': data['ports'],
                'connections': connections,
                'processes': data['processes'],
                'core_dumps': data['core_dumps'],
                'cron_jobs': data['cron_jobs'],
                'kernel_modules': data['kernel_modules'],
                'alerts': analysis['alerts'],
                'severity_counts': analysis['severity_counts'],
                'total_alerts': analysis['total_alerts'],
                'risk_score': summary['risk_score'],
                'alerts_by_type': summary['by_type'],
                'scan_time': analysis['scan_time'],
            }

            with cache_lock:
                cache.clear()
                cache.update(payload)
                cache['_last_update'] = time.time()

        except Exception as e:
            with cache_lock:
                cache['_error'] = str(e)
                cache['_last_update'] = time.time()

        time.sleep(collect_interval)


class DashboardHandler(BaseHTTPRequestHandler):

    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path):
        try:
            with open(path, 'rb') as f:
                content = f.read()
            mime_type, _ = mimetypes.guess_type(str(path))
            self.send_response(200)
            self.send_header('Content-Type', mime_type or 'application/octet-stream')
            self.send_header('Content-Length', len(content))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self._send_json({'error': 'Not found'}, 404)
        except PermissionError:
            self._send_json({'error': 'Forbidden'}, 403)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/api/status':
            with cache_lock:
                now = time.time()
                data = dict(cache)
                data['_server_time'] = datetime.now().isoformat()
                data['_collect_interval'] = collect_interval
                data['_staleness'] = round(now - data.get('_last_update', 0), 1) if data.get('_last_update') else -1
            self._send_json(data)

        elif path == '/api/collect':
            try:
                data = collector.collect_all()
                self._send_json({'status': 'ok', 'timestamp': datetime.now().isoformat(), 'data': data})
            except Exception as e:
                self._send_json({'status': 'error', 'error': str(e)}, 500)

        elif path == '/api/analyze':
            try:
                data = collector.collect_all()
                analysis = analyzer.analyze(data)
                summary = analyzer.get_summary(analysis['alerts'])
                self._send_json({
                    'status': 'ok',
                    'timestamp': datetime.now().isoformat(),
                    'alerts': analysis['alerts'],
                    'severity_counts': analysis['severity_counts'],
                    'total_alerts': analysis['total_alerts'],
                    'risk_score': summary['risk_score'],
                    'alerts_by_type': summary['by_type'],
                })
            except Exception as e:
                self._send_json({'status': 'error', 'error': str(e)}, 500)

        elif path == '/api/alerts':
            with cache_lock:
                self._send_json({
                    'alerts': cache.get('alerts', []),
                    'severity_counts': cache.get('severity_counts', {}),
                    'total_alerts': cache.get('total_alerts', 0),
                    'risk_score': cache.get('risk_score', 0),
                })

        elif path == '/' or path == '':
            self._send_file(STATIC_DIR / 'index.html')

        elif path.startswith('/api/'):
            self._send_json({'error': 'Unknown API endpoint'}, 404)

        else:
            rel = path.lstrip('/')
            filepath = STATIC_DIR / rel
            if filepath.exists() and filepath.is_file():
                self._send_file(filepath)
            else:
                self._send_file(STATIC_DIR / 'index.html')

    def log_message(self, format, *args):
        msg = format % args
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {self.client_address[0]} - {msg}")


def wait_for_cache():
    for i in range(30):
        with cache_lock:
            if '_last_update' in cache:
                return
        time.sleep(1)
    print("Warning: Cache not populated after 30 seconds, serving anyway")


if __name__ == '__main__':
    print("[*] Dashboard Menace - Security Monitoring System")
    print("[*] Starting collector thread...")
    collector_thread = threading.Thread(target=collect_and_analyze, daemon=True)
    collector_thread.start()

    print("[*] Waiting for initial data collection...")
    wait_for_cache()

    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))

    server = HTTPServer((host, port), DashboardHandler)
    print(f"[*] Dashboard available at http://{host}:{port}")
    print("[*] API endpoints:")
    print(f"      http://{host}:{port}/api/status     - Full system status")
    print(f"      http://{host}:{port}/api/alerts     - Security alerts only")
    print(f"      http://{host}:{port}/api/collect    - Raw system data")
    print(f"      http://{host}:{port}/api/analyze    - On-demand analysis")
    print("[*] Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        server.shutdown()
