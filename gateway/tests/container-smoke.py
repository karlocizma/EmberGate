"""Smoke-test the documented Compose service with an isolated project and volume.

Build the image first. Run from any directory:
python3 gateway/tests/container-smoke.py --engine podman --image localhost/embergate:roadmap
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine', default='docker')
    parser.add_argument('--image', default='embergate:ci')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    admin, proxy, tls = free_port(), free_port(), free_port()
    project = 'embergate-test-' + uuid.uuid4().hex[:12]
    config = (repo / 'compose.yaml').read_text()
    config = config.replace('${EMBERGATE_IMAGE:-ghcr.io/karlocizma/embergate:latest}', args.image)
    config = config.replace('${GATEWAY_BIND_ADDRESS:-127.0.0.1}', '127.0.0.1')
    for published, internal, isolated in [(9090, 9090, admin), (80, 8080, proxy), (443, 8443, tls)]:
        config = config.replace(f'127.0.0.1:{published}:{internal}', f'127.0.0.1:{isolated}:{internal}')
    env = {**os.environ, 'GATEWAY_ADMIN_PASSWORD': 'container-fixture-password',
           'GATEWAY_CLOUDFLARE_API_TOKEN': '', 'GATEWAY_ALERT_WEBHOOK_URL': ''}
    with tempfile.TemporaryDirectory(prefix='embergate-compose-') as directory:
        path = Path(directory) / 'compose.yaml'
        path.write_text(config)
        command = [args.engine, 'compose', '-p', project, '-f', str(path)]

        def compose(*arguments, capture=False):
            return subprocess.run(command + list(arguments), cwd=repo, env=env, check=True,
                                  capture_output=capture, text=True)

        def request(port, method, path, data=None, headers=None):
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            conn.request(method, path, None if data is None else json.dumps(data),
                         {'Content-Type': 'application/json', **(headers or {})})
            response = conn.getresponse()
            result = response.status, dict(response.getheaders()), response.read()
            conn.close()
            return result

        def ready():
            for _ in range(120):
                try:
                    status, _, _ = request(admin, 'GET', '/api/config')
                    if status == 401:
                        return
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(.25)
            raise AssertionError('Container did not become ready')

        def login():
            status, headers, _ = request(admin, 'POST', '/api/login',
                                        {'username': 'admin', 'password': env['GATEWAY_ADMIN_PASSWORD']},
                                        {'X-Gateway-Request': '1'})
            assert status == 200
            cookie = next(value for name, value in headers.items() if name.lower() == 'set-cookie').split(';')[0]
            return {'Cookie': cookie, 'X-Gateway-Request': '1'}

        try:
            compose('config', '--quiet')
            compose('up', '-d')
            ready()
            assert compose('exec', '-T', 'gateway', 'id', '-u', capture=True).stdout.strip() == '10001'
            headers = login()
            status, _, body = request(admin, 'GET', '/api/documentation', headers=headers)
            assert status == 200 and len(json.loads(body)['guides']) == 8
            status, _, body = request(admin, 'GET', '/api/config', headers=headers)
            config = json.loads(body)
            route_id = str(uuid.uuid4())
            config['routes'] = [{'id': route_id, 'name': 'Container fixture', 'host': 'container.test',
                                 'path_prefix': '/', 'upstream': 'http://127.0.0.1:9090',
                                 'enabled': True, 'preserve_host': False}]
            status, _, _ = request(admin, 'PUT', '/api/config', config, headers)
            assert status == 200
            status, _, body = request(proxy, 'GET', '/', headers={'Host': 'container.test'})
            assert status == 200 and b'EmberGate' in body
            compose('restart', '--timeout', '2')
            ready()
            status, _, body = request(admin, 'GET', '/api/config', headers=login())
            assert status == 200 and json.loads(body)['routes'][0]['id'] == route_id
            status, _, body = request(proxy, 'GET', '/', headers={'Host': 'container.test'})
            assert status == 200 and b'EmberGate' in body
            print('Compose smoke checks passed: non-root execution, authentication, embedded Help, real forwarding, and volume persistence across restart.')
        finally:
            compose('down', '--volumes', '--timeout', '1')


if __name__ == '__main__':
    run()
