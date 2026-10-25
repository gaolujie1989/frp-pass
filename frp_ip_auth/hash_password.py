"""Generate an Argon2id hash without putting a password in shell history."""

from getpass import getpass

from argon2 import PasswordHasher


def hash_password(password):
    if not 12 <= len(password.encode("utf-8")) <= 1024:
        raise ValueError("Password must contain 12–1024 UTF-8 bytes")
    return PasswordHasher().hash(password)


def main():
    try:
        password = getpass("Password: ")
        if password != getpass("Confirm password: "):
            raise ValueError("Passwords do not match")
        print(hash_password(password))
        return 0
    except (ValueError, EOFError, KeyboardInterrupt) as exc:
        import sys

        print(str(exc) or "Cancelled", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
