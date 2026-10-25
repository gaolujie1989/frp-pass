"""Strict startup configuration; configuration errors never enable bypasses."""

import ipaddress
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from argon2 import extract_parameters
from argon2.exceptions import InvalidHashError
from argon2.low_level import Type

SUPPORTED_TYPES = frozenset({"tcp", "stcp", "https", "tcpmux"})
NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")


@dataclass(frozen=True)
class User:
    password_hash: str
    channels: tuple[str, ...]


@dataclass(frozen=True)
class Settings:
    public_origin: str
    trusted_proxies: tuple
    plugin_sources: tuple
    channels: dict[str, str]
    users: dict[str, User]

    @classmethod
    def from_file(cls, path, public_origin=None):
        with Path(path).open("rb") as file:
            data = tomllib.load(file)
        if public_origin:
            data["public_origin"] = public_origin
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data):
        expected = {"public_origin", "trusted_proxies", "plugin_sources", "channels", "users"}
        if not isinstance(data, dict) or set(data) != expected:
            raise ValueError("Config requires exactly: " + ", ".join(sorted(expected)))
        origin = data["public_origin"]
        if not isinstance(origin, str):
            raise ValueError("public_origin must be an HTTPS origin")
        try:
            url = urlsplit(origin)
            port = url.port
        except ValueError as exc:
            raise ValueError("Invalid public_origin") from exc
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.path
            or url.query
            or url.fragment
            or any(c.isspace() for c in origin)
            or port == 0
        ):
            raise ValueError("public_origin must be https://hostname[:port] without a path")

        def networks(key):
            values = data[key]
            if not isinstance(values, list) or not values:
                raise ValueError(f"{key} requires explicit IP networks")
            try:
                return tuple(ipaddress.ip_network(value) for value in values)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid network in {key}") from exc

        channels = data["channels"]
        if not isinstance(channels, dict) or not channels:
            raise ValueError("At least one channel is required")
        if any(
            not isinstance(name, str)
            or not NAME.fullmatch(name)
            or not isinstance(kind, str)
            or kind not in SUPPORTED_TYPES
            for name, kind in channels.items()
        ):
            raise ValueError("Invalid channel name/type; HTTP and UDP are not supported")
        raw_users = data["users"]
        if not isinstance(raw_users, dict) or not raw_users:
            raise ValueError("At least one user is required")
        users = {}
        for name, user in raw_users.items():
            if not isinstance(name, str) or not NAME.fullmatch(name):
                raise ValueError("Invalid username")
            if not isinstance(user, dict) or set(user) != {"password_hash", "channels"}:
                raise ValueError(f"User {name} requires password_hash and channels")
            password_hash = user["password_hash"]
            try:
                params = extract_parameters(password_hash)
            except (InvalidHashError, ValueError, TypeError, AttributeError) as exc:
                raise ValueError(f"User {name} requires a valid Argon2id hash") from exc
            if params.type != Type.ID or params.version != 19:
                raise ValueError(f"User {name} requires an Argon2id v19 hash")
            assigned = user["channels"]
            if (
                not isinstance(assigned, list)
                or not assigned
                or any(not isinstance(item, str) or item not in channels for item in assigned)
            ):
                raise ValueError(f"User {name} references an unknown channel")
            users[name] = User(password_hash, tuple(dict.fromkeys(assigned)))
        return cls(
            origin, networks("trusted_proxies"), networks("plugin_sources"), dict(channels), users
        )
