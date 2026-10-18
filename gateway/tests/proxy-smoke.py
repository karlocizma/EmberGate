"""Integration check using the compiled gateway and a local HTTP upstream.

Run from gateway/: cargo build && python3 tests/proxy-smoke.py
"""
import http.client
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Upstream(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path, "host": self.headers.get("Host"),
                           "forwarded_proto": self.headers.get("X-Forwarded-Proto"),
                           "forwarded_for": self.headers.get("X-Forwarded-For")}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(port, method, path, data=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    body = json.dumps(data) if data is not None else None
    conn.request(method, path, body, {"Content-Type": "application/json", **(headers or {})})
    response = conn.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    conn.close()
    return result


def await_ready(process, admin_port):
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError("Gateway exited during startup")
        try:
            status, _, _ = request(admin_port, "GET", "/api/config")
            assert status == 401
            return
        except (ConnectionError, OSError):
            time.sleep(0.1)
    raise AssertionError("Gateway did not become ready")


def run():
    binary = Path("target/debug/embergate").resolve()
    if not binary.exists():
        raise SystemExit("Run cargo build first.")
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    proxy_port, admin_port = free_port(), free_port()
    while admin_port == proxy_port:
        admin_port = free_port()
    with tempfile.TemporaryDirectory(prefix="gateway-smoke-") as data_dir:
        env = {**os.environ, "GATEWAY_ADMIN_PASSWORD": "smoke-password-123",
               "GATEWAY_DATA_DIR": data_dir, "GATEWAY_PROXY_ADDR": f"127.0.0.1:{proxy_port}",
               "GATEWAY_ADMIN_ADDR": f"127.0.0.1:{admin_port}"}
        for key in ['GATEWAY_ALERT_WEBHOOK_URL','GATEWAY_CLOUDFLARE_API_TOKEN','GATEWAY_CLOUDFLARE_API_TOKEN_FILE']:
            env.pop(key,None)
        process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL)
        try:
            await_ready(process, admin_port)
            status, response_headers, _ = request(admin_port, "POST", "/api/login",
                {"password": "smoke-password-123"}, {"X-Gateway-Request": "1"})
            assert status == 200
            headers = {"Cookie": response_headers["set-cookie"].split(";")[0], "X-Gateway-Request": "1"}
            route = {"id": str(uuid.uuid4()), "name": "Smoke", "host": "smoke.test", "path_prefix": "/",
                     "upstream": f"http://127.0.0.1:{upstream.server_port}", "enabled": True, "preserve_host": False}
            status, _, body = request(admin_port, "PUT", "/api/config", {"version": 0, "routes": [route]}, headers)
            assert status == 200, body
            status, _, body = request(proxy_port, "GET", "/hello?query=preserved", headers={"Host": "smoke.test", "X-Forwarded-For": "spoofed"})
            assert status == 200, body
            received = json.loads(body)
            assert received["path"] == "/hello?query=preserved"
            assert received["host"] == f"127.0.0.1:{upstream.server_port}"
            assert received["forwarded_for"] == "127.0.0.1"
            assert request(proxy_port, "GET", "/", headers={"Host": "unknown.test"})[0] == 404
            # Updating a route takes effect without restarting the proxy.
            route["enabled"] = False
            assert request(admin_port, "PUT", "/api/config", {"version": 1, "routes": [route]}, headers)[0] == 200
            assert request(proxy_port, "GET", "/", headers={"Host": "smoke.test"})[0] == 404
            assert request(admin_port, "PUT", "/api/config", {"version": 1, "routes": []}, headers)[0] == 409
            assert json.loads(Path(data_dir, "routes.json").read_text())["version"] == 2
            assert json.loads(Path(data_dir, "routes.previous.json").read_text())["version"] == 1
            time.sleep(0.1)
            status, _, body = request(admin_port, "GET", "/api/logs", headers=headers)
            assert status == 200
            logs = json.loads(body)["logs"]
            assert len(logs) >= 3
            assert all("query=" not in log["path"] for log in logs)
            assert json.loads(request(admin_port, "GET", "/api/stats", headers=headers)[2])["requests"] >= 3
            route["enabled"] = True
            route["preserve_host"] = True
            assert request(admin_port, "PUT", "/api/config", {"version": 2, "routes": [route]}, headers)[0] == 200
            status, _, body = request(proxy_port, "GET", "/", headers={"Host": "smoke.test"})
            assert status == 200 and json.loads(body)["host"] == "smoke.test"

            # A fresh process loads saved routes and invalidates old sessions.
            # All test requests have completed. SIGINT is Pingora's fast shutdown;
            # SIGTERM intentionally waits through its five-minute drain period.
            process.send_signal(signal.SIGINT)
            process.wait(timeout=15)
            process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL)
            await_ready(process, admin_port)
            assert request(admin_port, "GET", "/api/config", headers=headers)[0] == 401
            status, response_headers, _ = request(admin_port, "POST", "/api/login",
                {"password": "smoke-password-123"}, {"X-Gateway-Request": "1"})
            assert status == 200
            headers["Cookie"] = response_headers["set-cookie"].split(";")[0]
            loaded = json.loads(request(admin_port, "GET", "/api/config", headers=headers)[2])
            assert loaded["version"] == 3 and loaded["routes"] == [route]
            assert request(proxy_port, "GET", "/", headers={"Host": "smoke.test"})[0] == 200
            assert request(admin_port, "POST", "/api/logout", headers=headers)[0] == 200
            assert request(admin_port, "GET", "/api/config", headers=headers)[0] == 401
            print("Proxy smoke checks passed: authentication, forwarding, live changes, restart persistence, conflicts, metrics, logs, logout.")
        finally:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            upstream.shutdown()


if __name__ == "__main__":
    run()
