from pathlib import Path

import pytest
from argon2 import PasswordHasher

ROOT = Path(__file__).resolve().parents[1]


def test_container_deployment_is_included():
    assert (ROOT / "Dockerfile").is_file(), "Docker deployment is missing"


def test_password_hash_cli_uses_argon2id():
    from frp_ip_auth.hash_password import hash_password

    encoded = hash_password("test-only-password")
    assert encoded.startswith("$argon2id$")
    assert PasswordHasher().verify(encoded, "test-only-password")
    with pytest.raises(ValueError):
        hash_password("short")


def test_example_config_valid_after_setting_password():
    import tomllib

    from frp_ip_auth.config import Settings

    data = tomllib.loads((ROOT / "config.example.toml").read_text())
    data["users"]["admin"]["password_hash"] = PasswordHasher().hash("test-only-password")
    settings = Settings.from_dict(data)
    assert settings.users["admin"].channels == ("ssh", "rdp")
