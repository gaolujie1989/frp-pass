"""Run with --frp-dir pointing to an unpacked official FRP release.

Uses only loopback sockets and synthetic credentials. Does not change a live FRPS.
"""

import argparse
import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from argon2 import PasswordHasher


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(port, processes):
    for _ in range(200):
        if any(process.poll() is not None for process in processes):
            raise RuntimeError("A subprocess exited before becoming ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("Local listener did not start")


class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"FRP_AUTH_LOCAL_TEST")

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--frp-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    hook, control, remote = [free_port() for _ in range(3)]
    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    processes, logs = [], []
    # FRPC honors http_proxy even for loopback: isolate the local test from host proxies.
    env = {key: value for key, value in os.environ.items() if "proxy" not in key.lower()}
    with tempfile.TemporaryDirectory(prefix="frp-ip-auth-test-") as directory:
        directory = Path(directory)
        password_hash = PasswordHasher().hash("local-test-password")
        config = directory / "config.toml"
        config.write_text(f'''trusted_proxies = ["127.0.0.1/32"]
plugin_sources = ["127.0.0.1/32"]
[channels]
ssh = "tcp"
[users.test]
password_hash = "{password_hash}"
channels = ["ssh"]
''')
        env["FRP_AUTH_CONFIG"] = str(config)
        server_config = directory / "frps.toml"
        server_config.write_text(f"""bindAddr = "127.0.0.1"
bindPort = {control}
proxyBindAddr = "127.0.0.1"
auth.token = "isolated-local-test-only"
[[httpPlugins]]
name = "ip-auth"
addr = "127.0.0.1:{hook}"
path = "/handler"
ops = ["NewProxy", "NewUserConn"]
""")
        client_config = directory / "frpc.toml"
        client_config.write_text(f"""serverAddr = "127.0.0.1"
serverPort = {control}
auth.token = "isolated-local-test-only"
[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = {backend.server_port}
remotePort = {remote}
""")

        def launch(name, command):
            log = (directory / f"{name}.log").open("w+")
            logs.append(log)
            processes.append(
                subprocess.Popen(command, env=env, cwd=root, stdout=log, stderr=subprocess.STDOUT)
            )

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def forwarded_request(path, data=None):
            headers = {
                "X-Forwarded-For": "127.0.0.1",
            }
            request = urllib.request.Request(
                f"http://127.0.0.1:{hook}{path}", data=data, headers=headers
            )
            return opener.open(request, timeout=3)

        def read_backend():
            try:
                return opener.open(f"http://127.0.0.1:{remote}/", timeout=2).read()
            except OSError:
                return b""

        try:
            launch(
                "auth",
                [
                    sys.executable,
                    "-m",
                    "gunicorn",
                    "--config",
                    "gunicorn.conf.py",
                    "--bind",
                    f"127.0.0.1:{hook}",
                    "frp_ip_auth.wsgi:application",
                ],
            )
            wait_port(hook, processes)
            launch("frps", [str(args.frp_dir.resolve() / "frps"), "-c", str(server_config)])
            wait_port(control, processes)
            launch("frpc", [str(args.frp_dir.resolve() / "frpc"), "-c", str(client_config)])
            wait_port(remote, processes)
            assert read_backend() == b"", "Connection should be rejected before login"
            with forwarded_request("/login") as response:
                assert "FRP 访问授权" in response.read().decode()
            data = urllib.parse.urlencode(
                {"username": "test", "password": "local-test-password"}
            ).encode()
            with forwarded_request("/login", data) as response:
                assert "授权成功" in response.read().decode()
            assert read_backend() == b"FRP_AUTH_LOCAL_TEST", "Authorized connection failed"
            with forwarded_request(
                "/handler",
                json.dumps(
                    {"op": "NewProxy", "content": {"proxy_name": "http", "proxy_type": "http"}}
                ).encode(),
            ) as response:
                # Form encoding is rejected, so even this malformed registration is closed.
                assert json.load(response)["reject"]
            print("PASS: real FRP TCP denied before login, allowed after HTTP password login")
        except Exception:
            for log in logs:
                log.flush()
                log.seek(0)
                print(log.name, log.read()[-3000:])
            raise
        finally:
            for process in reversed(processes):
                process.terminate()
            for process in reversed(processes):
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for log in logs:
                log.close()
            backend.shutdown()
            backend.server_close()


if __name__ == "__main__":
    main()
