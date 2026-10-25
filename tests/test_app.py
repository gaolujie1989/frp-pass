import importlib.util
import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode

import pytest
from argon2 import PasswordHasher


def test_service_implementation_exists():
    assert importlib.util.find_spec("frp_ip_auth.app"), "Native WSGI service is missing"


@pytest.fixture
def settings_data():
    password_hash = PasswordHasher(time_cost=1, memory_cost=8192).hash("test-only-password")
    return {
        "public_origin": "https://access.example.com",
        "trusted_proxies": ["127.0.0.2/32"],
        "plugin_sources": ["127.0.0.1/32"],
        "channels": {"ssh": "tcp", "rdp": "tcp", "other": "tcp"},
        "users": {"alice": {"password_hash": password_hash, "channels": ["ssh", "rdp"]}},
    }


@pytest.fixture
def setup_app(settings_data):
    from frp_ip_auth.app import Application
    from frp_ip_auth.config import Settings

    clock = [1000.0]
    settings = Settings.from_dict(settings_data)
    return Application(settings, clock=lambda: clock[0]), clock


def request(
    app,
    path,
    method="GET",
    data=None,
    *,
    peer="127.0.0.2",
    ip="198.51.100.8",
    headers=None,
    raw=None,
):
    body = raw if raw is not None else (urlencode(data).encode() if data is not None else b"")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path.split("?", 1)[0],
        "QUERY_STRING": path.partition("?")[2],
        "SERVER_NAME": "access.example.com",
        "SERVER_PORT": "443",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(body),
        "wsgi.errors": io.StringIO(),
        "wsgi.multithread": True,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
        "REMOTE_ADDR": peer,
        "HTTP_HOST": "access.example.com",
        "HTTP_X_FORWARDED_PROTO": "https",
        "HTTP_X_FORWARDED_FOR": ip,
        "HTTP_ORIGIN": "https://access.example.com",
        "CONTENT_TYPE": "application/x-www-form-urlencoded",
        "CONTENT_LENGTH": str(len(body)),
    }
    environ.update(headers or {})
    result = {}

    def start(status, response_headers):
        result.update(status=int(status.split()[0]), headers=dict(response_headers))

    result["body"] = b"".join(app(environ, start))
    return result


def login(app, **kwargs):
    return request(
        app, "/login", "POST", {"username": "alice", "password": "test-only-password"}, **kwargs
    )


def callback(app, content, op="NewUserConn", **kwargs):
    payload = json.dumps({"version": "0.1.0", "op": op, "content": content}).encode()
    result = request(
        app,
        "/handler",
        "POST",
        peer="127.0.0.1",
        raw=payload,
        headers={"CONTENT_TYPE": "application/json"},
        **kwargs,
    )
    return result, json.loads(result["body"])


def connection(name="ssh", remote="198.51.100.8:12345", kind="tcp"):
    return {"proxy_name": name, "proxy_type": kind, "remote_addr": remote}


def test_login_grants_only_assigned_channels_for_300_seconds(setup_app):
    app, clock = setup_app
    assert callback(app, connection())[1]["reject"]
    result = login(app)
    assert result["status"] == 200 and "授权成功" in result["body"].decode()
    assert result["headers"]["Cache-Control"] == "no-store"
    assert callback(app, connection())[1] == {"reject": False, "unchange": True}
    assert not callback(app, connection("rdp"))[1]["reject"]
    assert callback(app, connection("other"))[1]["reject"]
    assert callback(app, connection(remote="198.51.100.9:1234"))[1]["reject"]
    clock[0] += 300
    assert callback(app, connection())[1]["reject"]


@pytest.mark.parametrize("username,password", [("alice", "wrong"), ("nobody", "wrong")])
def test_bad_credentials_do_not_grant(setup_app, username, password):
    app, _ = setup_app
    result = request(app, "/login", "POST", {"username": username, "password": password})
    assert result["status"] == 401
    assert callback(app, connection())[1]["reject"]


def test_failed_login_does_not_revoke_successful_grant(setup_app):
    app, _ = setup_app
    assert login(app)["status"] == 200
    request(app, "/login", "POST", {"username": "alice", "password": "wrong"})
    assert not callback(app, connection())[1]["reject"]


@pytest.mark.parametrize(
    "headers,peer",
    [
        ({}, "198.51.100.99"),
        ({"HTTP_X_FORWARDED_PROTO": "http"}, "127.0.0.2"),
        ({"HTTP_ORIGIN": "https://attacker.example"}, "127.0.0.2"),
        ({"HTTP_ORIGIN": ""}, "127.0.0.2"),
        ({"HTTP_HOST": "attacker.example"}, "127.0.0.2"),
        ({"HTTP_X_FORWARDED_FOR": "198.51.100.8, 1.2.3.4"}, "127.0.0.2"),
    ],
)
def test_login_rejects_untrusted_transport_and_headers(setup_app, headers, peer):
    app, _ = setup_app
    assert login(app, headers=headers, peer=peer)["status"] in (400, 403)
    assert callback(app, connection())[1]["reject"]


def test_login_limiter_resets_and_does_not_limit_plugin(setup_app):
    app, clock = setup_app
    for _ in range(5):
        assert (
            request(app, "/login", "POST", {"username": "alice", "password": "wrong"})["status"]
            == 401
        )
    assert login(app)["status"] == 429
    assert callback(app, connection())[0]["status"] == 200
    clock[0] += 60
    assert login(app)["status"] == 200


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b"null",
        b"[]",
        b"{",
        b'{"op":"NewUserConn","content":null}',
        b'{"op":"NewUserConn","op":"NewProxy","content":{}}',
    ],
)
def test_malformed_plugin_requests_fail_closed(setup_app, payload):
    app, _ = setup_app
    result = request(
        app,
        "/handler",
        "POST",
        peer="127.0.0.1",
        raw=payload,
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert result["status"] == 200
    assert json.loads(result["body"])["reject"] is True


def test_plugin_source_cannot_be_spoofed(setup_app):
    app, _ = setup_app
    assert request(app, "/handler", "POST", peer="127.0.0.2")["status"] == 403


@pytest.mark.parametrize("name,kind", [("unknown", "tcp"), ("ssh", "http"), ("ssh", "udp")])
def test_unknown_or_unsupported_proxy_is_rejected_at_registration(setup_app, name, kind):
    app, _ = setup_app
    assert callback(app, {"proxy_name": name, "proxy_type": kind}, op="NewProxy")[1]["reject"]


def test_registration_and_query_operation_agree(setup_app):
    app, _ = setup_app
    assert not callback(app, {"proxy_name": "ssh", "proxy_type": "tcp"}, op="NewProxy")[1]["reject"]
    payload = json.dumps(
        {"op": "NewProxy", "content": {"proxy_name": "ssh", "proxy_type": "tcp"}}
    ).encode()
    result = request(
        app,
        "/handler?op=NewUserConn",
        "POST",
        raw=payload,
        peer="127.0.0.1",
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert json.loads(result["body"])["reject"]


def test_registration_without_proxy_type_is_rejected(setup_app):
    app, _ = setup_app
    assert callback(app, {"proxy_name": "unknown"}, op="NewProxy")[1]["reject"]


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_nonstandard_json_constants_are_rejected(setup_app, constant):
    app, _ = setup_app
    payload = (
        '{"op":"NewProxy","content":{"proxy_name":"ssh",'
        '"proxy_type":"tcp","extra":' + constant + "}}"
    ).encode()
    result = request(
        app,
        "/handler",
        "POST",
        peer="127.0.0.1",
        raw=payload,
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert json.loads(result["body"])["reject"]


@pytest.mark.parametrize(
    "remote", ["", "198.51.100.8", "bad:123", "198.51.100.8:99999", "x@198.51.100.8:123"]
)
def test_invalid_remote_address_rejected(setup_app, remote):
    app, _ = setup_app
    login(app)
    assert callback(app, connection(remote=remote))[1]["reject"]


def test_ipv6_and_ipv4_mapped_addresses(setup_app):
    app, _ = setup_app
    assert login(app, ip="2001:db8::12")["status"] == 200
    assert not callback(app, connection(remote="[2001:db8::12]:123"))[1]["reject"]
    assert login(app, ip="::ffff:198.51.100.8")["status"] == 200
    assert not callback(app, connection())[1]["reject"]


def test_request_body_and_method_limits(setup_app):
    app, _ = setup_app
    assert request(app, "/login", "POST", raw=b"a" * 4097)["status"] == 413
    assert request(app, "/login", "PUT")["status"] == 405
    assert request(app, "/missing")["status"] == 404
    assert request(app, "/health", peer="127.0.0.1")["status"] == 200


def test_state_capacity_expiry_and_concurrency():
    from frp_ip_auth.state import GrantStore, LoginLimiter

    clock = [0.0]
    store = GrantStore(clock=lambda: clock[0], capacity=2)
    assert store.grant(["ssh"], "198.51.100.1", 300)
    assert store.grant(["ssh"], "198.51.100.2", 300)
    assert not store.grant(["ssh"], "198.51.100.3", 300)
    clock[0] = 300
    assert store.grant(["ssh"], "198.51.100.3", 300)
    limiter = LoginLimiter(clock=lambda: clock[0], capacity=1)
    assert limiter.admit("1") and not limiter.admit("2")
    clock[0] += 60
    assert limiter.admit("2")
    limiter = LoginLimiter(clock=lambda: clock[0])
    barrier = threading.Barrier(20)

    def attempt(_):
        barrier.wait()
        return limiter.admit("shared-ip")

    with ThreadPoolExecutor(max_workers=20) as pool:
        assert sum(pool.map(attempt, range(20))) == 5


@pytest.mark.parametrize(
    "changes",
    [
        {"public_origin": "http://access.example.com"},
        {"channels": {"web": "http"}},
        {"users": {}},
        {"plugin_sources": []},
        {"trusted_proxies": ["not-a-network"]},
        {"users": {"alice": {"password_hash": "plaintext", "channels": ["ssh"]}}},
    ],
)
def test_invalid_config_fails_startup(settings_data, changes):
    from frp_ip_auth.config import Settings

    data = settings_data.copy()
    data.update(changes)
    with pytest.raises(ValueError):
        Settings.from_dict(data)
