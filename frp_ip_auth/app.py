"""Native WSGI login page and fail-closed FRP server plugin."""

import html
import ipaddress
import json
import logging
import threading
import time
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

from .state import GrantStore, LoginLimiter

LOG = logging.getLogger("frp_ip_auth")
GRANT_SECONDS = 300
MAX_BODY = 4096
SECURITY_HEADERS = [
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    ),
]


class RequestError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def canonical_ip(value):
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Invalid IP address")
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def in_networks(ip, networks):
    address = ipaddress.ip_address(ip)
    return any(address in network for network in networks)


def remote_ip(value):
    if not isinstance(value, str) or any(char in value for char in "/@?#%"):
        raise ValueError("Invalid remote_addr")
    parsed = urlsplit("//" + value)
    if parsed.port is None or not 1 <= parsed.port <= 65535:
        raise ValueError("remote_addr must contain a valid port")
    return canonical_ip(parsed.hostname)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("Nonstandard JSON constant")


class Application:
    def __init__(self, settings, *, clock=time.monotonic):
        self.settings = settings
        self.grants = GrantStore(clock=clock)
        self.limiter = LoginLimiter(clock=clock)
        self.hasher = PasswordHasher()
        self._dummy_hash = self.hasher.hash("dummy-account-not-a-login-password")
        self._password_slots = threading.BoundedSemaphore(2)
        self._template = Path(__file__).with_name("templates").joinpath("login.html").read_text()

    def __call__(self, environ, start_response):
        try:
            status, body, content_type = self.dispatch(environ)
        except RequestError as exc:
            status, body, content_type = exc.status, exc.message, "text/plain; charset=utf-8"
        except Exception:
            LOG.exception("request_failed")
            status, body, content_type = 503, "Service unavailable", "text/plain; charset=utf-8"
        if isinstance(body, dict):
            body = json.dumps(body, ensure_ascii=False)
        encoded = body.encode("utf-8")
        headers = SECURITY_HEADERS + [
            ("Content-Type", content_type),
            ("Content-Length", str(len(encoded))),
        ]
        if status == 429:
            headers.append(("Retry-After", "60"))
        start_response(f"{status} {HTTPStatus(status).phrase}", headers)
        return [encoded]

    def dispatch(self, env):
        path, method = env.get("PATH_INFO", ""), env.get("REQUEST_METHOD", "")
        if path == "/health" and method == "GET":
            return 200, {"status": "ok"}, "application/json"
        if path == "/handler":
            peer = self.peer_ip(env)
            if not in_networks(peer, self.settings.plugin_sources):
                raise RequestError(403, "Forbidden")
            if method != "POST":
                raise RequestError(405, "POST required")
            return 200, self.handle_plugin(env), "application/json"
        if path not in {"/", "/login"}:
            raise RequestError(404, "Not found")
        if method not in {"GET", "POST"} or (path == "/" and method != "GET"):
            raise RequestError(405, "Method not allowed")
        ip = self.client_ip(env)
        if method == "GET":
            return self.page(ip)
        if not self.limiter.admit(ip):
            self.audit("login_rate_limited", ip=ip)
            raise RequestError(429, "Too many login attempts; retry after 60 seconds")
        if not self._password_slots.acquire(blocking=False):
            raise RequestError(429, "Login verification busy; retry later")
        try:
            return self.login(env, ip)
        finally:
            self._password_slots.release()

    def peer_ip(self, env):
        try:
            return canonical_ip(env.get("REMOTE_ADDR"))
        except ValueError as exc:
            raise RequestError(400, "Invalid source address") from exc

    def client_ip(self, env):
        peer = self.peer_ip(env)
        trusted = in_networks(peer, self.settings.trusted_proxies)
        if trusted:
            try:
                # Exactly one trusted hop. Proxy must overwrite, not append, this header.
                return canonical_ip(env.get("HTTP_X_FORWARDED_FOR"))
            except ValueError as exc:
                raise RequestError(400, "Invalid forwarded address") from exc
        return peer

    def read_body(self, env, content_type):
        if env.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower() != content_type:
            raise RequestError(415, "Unsupported media type")
        length = env.get("CONTENT_LENGTH", "")
        if not isinstance(length, str) or not length.isascii() or not length.isdecimal():
            raise RequestError(411, "Content-Length required")
        size = int(length)
        if size > MAX_BODY:
            raise RequestError(413, "Request body too large")
        body = env["wsgi.input"].read(size)
        if len(body) != size:
            raise RequestError(400, "Incomplete request body")
        return body

    def login(self, env, ip):
        try:
            body = self.read_body(env, "application/x-www-form-urlencoded").decode("utf-8")
            fields = parse_qs(body, keep_blank_values=True, strict_parsing=True, max_num_fields=4)
            if set(fields) != {"username", "password"} or any(len(v) != 1 for v in fields.values()):
                raise ValueError("Invalid form")
            username, password = fields["username"][0], fields["password"][0]
            if not 1 <= len(username) <= 128 or not 1 <= len(password.encode()) <= 1024:
                raise ValueError("Invalid credentials length")
        except (ValueError, UnicodeError) as exc:
            raise RequestError(400, "Invalid login form") from exc
        user = self.settings.users.get(username)
        try:
            self.hasher.verify(user.password_hash if user else self._dummy_hash, password)
            valid = user is not None
        except VerificationError:
            valid = False
        if not valid:
            self.audit("login_denied", ip=ip, username=username)
            return self.page(ip, "用户名或密码错误", status=401)
        if not self.grants.grant(user.channels, ip, GRANT_SECONDS):
            raise RequestError(503, "Authorization capacity reached; retry later")
        self.audit(
            "login_granted", ip=ip, username=username, channels=user.channels, ttl=GRANT_SECONDS
        )
        message = f"授权成功。当前 IP 可在五分钟内新建连接。通道：{'、'.join(user.channels)}。"
        return self.page(ip, message, success=True)

    def page(self, ip, message="", *, status=200, success=False):
        body = self._template.replace("{{ip}}", html.escape(ip)).replace(
            "{{message}}", html.escape(message)
        )
        body = body.replace("{{state}}", "success" if success else "notice")
        return status, body, "text/html; charset=utf-8"

    def handle_plugin(self, env):
        reject = {"reject": True, "reject_reason": "Connection is not authorized"}
        try:
            raw = self.read_body(env, "application/json")
            data = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
            if not isinstance(data, dict) or set(data) - {"version", "op", "content"}:
                return reject
            query = parse_qs(
                env.get("QUERY_STRING", ""),
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=4,
            )
            if set(query) - {"op", "version"} or any(len(value) != 1 for value in query.values()):
                return reject
            op = data.get("op", query.get("op", [None])[0])
            if not isinstance(op, str) or ("op" in query and query["op"][0] != op):
                return reject
            version = data.get("version", query.get("version", ["0.1.0"])[0])
            if version != "0.1.0" or ("version" in query and query["version"][0] != version):
                return reject
            content = data.get("content")
            if not isinstance(content, dict) or op not in {"NewProxy", "NewUserConn"}:
                return reject
            name, kind = content.get("proxy_name"), content.get("proxy_type")
            if (
                not isinstance(name, str)
                or name not in self.settings.channels
                or self.settings.channels[name] != kind
            ):
                return reject
            if op == "NewProxy" or self.grants.allowed(name, remote_ip(content.get("remote_addr"))):
                return {"reject": False, "unchange": True}
        except (RequestError, ValueError, TypeError, UnicodeError, RecursionError):
            pass
        return reject

    @staticmethod
    def audit(event, **fields):
        LOG.info(json.dumps({"event": event, **fields}, ensure_ascii=False))
