# Validation — 2026-10-25

- Python 3.12.14: 44 tests pass.
- Ruff lint and formatting checks pass.
- Python wheel and sdist build; login template included in wheel.
- Caddy 2.11.7 validates deploy/Caddyfile.
- Official FRP 0.71.1 binaries: TCP denied before login; password login grants access; TCP succeeds afterward.
- Independent code review: no Critical/Important findings. A minor nonstandard JSON acceptance was reproduced, rejected and covered by three regression cases.
- Docker Engine is unavailable in the authoring environment. Image build and container smoke test are included in GitHub Actions but have not been executed here.
- Live DNS, public certificates and the user's actual PVE/NAT network are deployment-time checks.
