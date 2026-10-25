# Validation — plain HTTP service

- Python 3.12: 44 tests pass, including plain HTTP login with no configured domain or Origin.
- Trusted proxy IP handling, direct-client spoof rejection and FRP callback source checks remain covered.
- Ruff lint/format checks and real FRP 0.71.1 TCP integration pass.
- Domain binding, HTTPS enforcement, Caddy and certificate configuration have been removed.
- CI checks Python 3.12/3.14, Python packaging, Docker build, Compose and HTTP password login in a non-root read-only container.
