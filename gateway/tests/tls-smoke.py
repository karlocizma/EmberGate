"""Test real TLS handshakes, chain delivery, certificate changes, and persistence.

Run from gateway/: cargo build --locked && python3 tests/tls-smoke.py
Uses a temporary private CA and local upstream; never contacts a certificate service.
"""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
from http.server import ThreadingHTTPServer

spec = importlib.util.spec_from_file_location("proxy_smoke", Path(__file__).with_name("proxy-smoke.py"))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


def openssl(directory, *args):
    subprocess.run(["openssl", *args], cwd=directory, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def generate_certificates(directory):
    openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "60",
            "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=Gateway test root",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl(directory, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "intermediate.key",
            "-out", "intermediate.csr", "-subj", "/CN=Gateway test intermediate")
    Path(directory, "intermediate.ext").write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    openssl(directory, "x509", "-req", "-in", "intermediate.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-set_serial", "2", "-days", "50", "-extfile", "intermediate.ext", "-out", "intermediate.pem")
    openssl(directory, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key",
            "-out", "leaf.csr", "-subj", "/CN=smoke.test")
    Path(directory, "leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:smoke.test,DNS:*.smoke.test\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    for filename, serial, days in [("leaf.pem", "3", "30"), ("renewed.pem", "4", "40")]:
        openssl(directory, "x509", "-req", "-in", "leaf.csr", "-CA", "intermediate.pem", "-CAkey", "intermediate.key",
                "-set_serial", serial, "-days", days, "-extfile", "leaf.ext", "-out", filename)


def https_request(port, context, hostname="smoke.test"):
    connection = http.client.HTTPSConnection(hostname, port, timeout=5, context=context)
    # Keep TLS hostname verification and SNI while dialing the local listener.
    connection._create_connection = lambda address, timeout, source_address: socket.create_connection(("127.0.0.1", port), timeout)
    connection.request("GET", "/secure?query=preserved", headers={"Host": "smoke.test"})
    response = connection.getresponse()
    if response.status == 200:
        assert response.getheader("Strict-Transport-Security") == "max-age=300"
        assert response.getheader("X-Content-Type-Options") == "nosniff"
    status, body = response.status, response.read()
    connection.close()
    return status, json.loads(body)


class CacheUpstream(helpers.Upstream):
    def end_headers(self):
        self.send_header("Cache-Control","public, max-age=60")
        super().end_headers()


def run():
    binary = Path("target/debug/embergate").resolve()
    if not binary.exists():
        raise SystemExit("Run cargo build --locked first.")
    with tempfile.TemporaryDirectory(prefix="gateway-tls-") as directory:
        generate_certificates(directory)
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), CacheUpstream)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        ports = set()
        while len(ports) < 3:
            ports.add(helpers.free_port())
        proxy_port, admin_port, https_port = ports
        env = {**os.environ, "GATEWAY_ADMIN_PASSWORD": "tls-test-password-123",
               "GATEWAY_DATA_DIR": str(Path(directory, "data")),
               "GATEWAY_PROXY_ADDR": f"127.0.0.1:{proxy_port}",
               "GATEWAY_ADMIN_ADDR": f"127.0.0.1:{admin_port}",
               "GATEWAY_HTTPS_ADDR": f"127.0.0.1:{https_port}"}
        for key in ['GATEWAY_ALERT_WEBHOOK_URL','GATEWAY_CLOUDFLARE_API_TOKEN','GATEWAY_CLOUDFLARE_API_TOKEN_FILE']:
            env.pop(key,None)
        process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            def login():
                status, headers, _ = helpers.request(admin_port, "POST", "/api/login", {"password": "tls-test-password-123"}, {"X-Gateway-Request": "1"})
                assert status == 200
                return {"Cookie": headers["set-cookie"].split(";")[0], "X-Gateway-Request": "1"}

            helpers.await_ready(process, admin_port)
            assert helpers.request(admin_port, "GET", "/api/certificates")[0] == 401
            headers = login()
            import uuid
            route = {"id": str(uuid.uuid4()), "name": "TLS smoke", "host": "smoke.test", "path_prefix": "/",
                     "upstream": f"http://127.0.0.1:{upstream.server_port}", "enabled": True, "preserve_host": False, "cache":{"max_ttl_seconds":300,"max_object_bytes":1048576,"cache_query_strings":True}, "response":{"redirect_https":True,"https_port":https_port,"hsts_max_age":300,"nosniff":True}}
            assert helpers.request(admin_port, "PUT", "/api/config", {"version": 0, "routes": [route]}, headers)[0] == 200
            status, redirect_headers, _ = helpers.request(proxy_port, "GET", "/secure?q=kept", headers={"Host":"smoke.test","X-Forwarded-Proto":"https"})
            assert status == 308
            assert {key.lower():value for key,value in redirect_headers.items()}["location"] == f"https://smoke.test:{https_port}/secure?q=kept"
            chain = Path(directory, "leaf.pem").read_text() + Path(directory, "intermediate.pem").read_text()
            key = Path(directory, "leaf.key").read_text()
            upload = {"name": "TLS test", "certificate_pem": chain, "private_key_pem": key}
            status, _, body = helpers.request(admin_port, "POST", "/api/certificates", upload, headers)
            assert status == 200, body
            metadata = json.loads(body)["certificates"][0]
            assert metadata["valid"] and set(metadata["domains"]) == {"smoke.test", "*.smoke.test"}
            assert b"PRIVATE KEY" not in body and b"CERTIFICATE-----" not in body
            certificate_id = metadata["id"]
            stored_file = Path(directory, "data", "certificates.json")
            assert stat.S_IMODE(stored_file.stat().st_mode) == 0o600
            context = ssl.create_default_context(cafile=str(Path(directory, "ca.pem")))
            # The client trusts only the root: the server must send the intermediate.
            status, received = https_request(https_port, context)
            assert status == 200 and received["path"] == "/secure?query=preserved"
            assert received["forwarded_proto"] == "https"
            # Exercise real HTTP/2 :authority without Host and ensure a repeat becomes a hit.
            import shutil
            curl=shutil.which("curl")
            if curl and "HTTP2" in subprocess.check_output([curl,"--version"],text=True):
                header_file=Path(directory,"h2-headers.txt")
                args=[curl,"--silent","--show-error","--fail","--http2","--noproxy","*","--cacert",str(Path(directory,"ca.pem")),"--resolve",f"smoke.test:{https_port}:127.0.0.1","-D",str(header_file),f"https://smoke.test:{https_port}/h2-cache"]
                first=json.loads(subprocess.check_output(args))
                assert "HTTP/2 200" in header_file.read_text()
                assert "x-current-cache: MISS" in header_file.read_text()
                second=json.loads(subprocess.check_output(args))
                assert first==second and "x-current-cache: HIT" in header_file.read_text()

            assert https_request(https_port, context, "app.smoke.test")[0] == 200
            for hostname in ["unknown.test", "a.b.smoke.test"]:
                try:
                    https_request(https_port, context, hostname)
                    raise AssertionError(f"Unexpected TLS success for {hostname}")
                except ssl.SSLError:
                    pass
            # Invalid uploads must not replace or disrupt the active certificate.
            wrong_key = {**upload, "private_key_pem": Path(directory, "ca.key").read_text()}
            endpoint = f"/api/certificates/{certificate_id}"
            assert helpers.request(admin_port, "PUT", endpoint, wrong_key, headers)[0] == 422
            assert helpers.request(admin_port, "POST", "/api/certificates", upload, headers)[0] == 422
            assert https_request(https_port, context)[0] == 200
            renewed = {**upload, "name": "Renewed", "certificate_pem": Path(directory, "renewed.pem").read_text() + Path(directory, "intermediate.pem").read_text()}
            status, _, body = helpers.request(admin_port, "PUT", endpoint, renewed, headers)
            assert status == 200, body
            assert json.loads(body)["certificates"][0]["fingerprint"] != metadata["fingerprint"]
            assert https_request(https_port, context)[0] == 200
            process.send_signal(signal.SIGINT)
            process.wait(timeout=15)
            process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            helpers.await_ready(process, admin_port)
            assert https_request(https_port, context)[0] == 200
            headers = login()
            assert json.loads(helpers.request(admin_port, "GET", "/api/certificates", headers=headers)[2])["certificates"][0]["name"] == "Renewed"
            assert helpers.request(admin_port, "DELETE", endpoint, headers=headers)[0] == 200
            try:
                https_request(https_port, context)
                raise AssertionError("Deleted certificate still served on a fresh TLS connection")
            except ssl.SSLError:
                pass
            print("TLS checks passed: certificate validation, chain delivery, SNI, wildcard bounds, live replacement/deletion, key permissions/redaction, restart persistence.")
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
