"""CI smoke test for a built Docker image; uses synthetic local credentials."""

import json
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def main():
    image = "frp-pass:ci"
    root = Path(__file__).resolve().parents[1]
    gateway = json.loads(docker("network", "inspect", "bridge"))[0]["IPAM"]["Config"][0]["Gateway"]
    encoded = docker(
        "run",
        "--rm",
        "--entrypoint",
        "python",
        image,
        "-c",
        "from argon2 import PasswordHasher; print(PasswordHasher().hash('container-test-password'))",
    )
    with tempfile.TemporaryDirectory() as directory:
        config = Path(directory) / "config.toml"
        content = (
            (root / "config.example.toml")
            .read_text()
            .replace("REPLACE_WITH_GENERATED_ARGON2ID_HASH", encoded)
        )
        content = content.replace(
            'trusted_proxies = ["172.30.55.2/32"]', f'trusted_proxies = ["{gateway}/32"]'
        )
        config.write_text(content)
        # The image's non-root user must be able to traverse and read this synthetic fixture.
        Path(directory).chmod(0o755)
        config.chmod(0o644)
        container = docker(
            "run",
            "-d",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--tmpfs",
            "/tmp:rw,size=16m,mode=1777",
            "-p",
            "127.0.0.1::9000",
            "--mount",
            f"type=bind,src={config},dst=/config/config.toml,readonly",
            image,
        )
        try:
            port = docker("port", container, "9000/tcp").split(":")[-1]
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            for _ in range(100):
                try:
                    with opener.open(f"http://127.0.0.1:{port}/health", timeout=1) as response:
                        assert json.load(response)["status"] == "ok"
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise AssertionError("Container did not become healthy")
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/login",
                headers={
                    "Host": "access.example.com",
                    "X-Forwarded-Proto": "https",
                    "X-Forwarded-For": "198.51.100.1",
                },
            )
            with opener.open(request, timeout=3) as response:
                assert "FRP 访问授权" in response.read().decode()
            assert docker("inspect", "--format", "{{.Config.User}}", container) == "10001:10001"
            print("PASS: non-root read-only container serves health and login")
        finally:
            print(docker("logs", container))
            docker("rm", "-f", container)


if __name__ == "__main__":
    main()
