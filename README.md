# frp-pass

用户名密码登录后，给当前 IP 授权五分钟，允许连接指定的 FRP 通道。
Python + Gunicorn + 原生 WSGI，无 Web 应用框架、OTP、数据库或登录会话。

**项目只提供 HTTP 服务，域名、HTTPS 和证书由前置 WAF 负责。**

## Docker 部署

```bash
cp config.example.toml config.toml
docker compose build
docker compose run --rm --no-deps auth python -m frp_ip_auth.hash_password
```

输入密码并确认，将生成的完整 Argon2id 哈希填入 config.toml 的
users.admin.password_hash。配置文件需能被容器 UID/GID 10001:10001 读取。

```bash
docker compose up -d
```

服务默认监听宿主机 `127.0.0.1:9000`，登录页为 `/login`，无需 .env 或域名配置。
WAF 在其他机器时，将 Compose 端口映射改为 `宿主机内网IP:9000:9000`，供 WAF 回源。

## 前置 WAF

- 将 `/` 和 `/login` 回源到本服务的 HTTP 9000 端口；`/handler`、`/health` 不对外转发。
- WAF 覆盖 `X-Forwarded-For`，只传递一个真实客户端 IP，不拼接客户端传来的地址链。
- `trusted_proxies` 填写应用实际看到的 WAF/反代来源 IP，只对这些来源读取转发头。
- `trusted_proxies = []` 表示使用连接对端 IP，并忽略所有转发头。
- 宿主机反代经过 Docker 映射端口访问时，来源通常是 Docker 网关 `172.30.55.1`，
  不一定是反代机器的 127.0.0.1；可以通过访问日志核对。

服务不校验外部域名、Origin 或 X-Forwarded-Proto，也不申请证书或执行 HTTPS 跳转。

## 配置

```toml
trusted_proxies = ["172.30.55.1/32"] # 按实际 WAF/反代来源修改
plugin_sources = ["127.0.0.1/32", "172.30.55.1/32", "172.30.55.4/32"]

[channels]
ssh = "tcp"
rdp = "tcp"

[users.admin]
password_hash = "生成的 Argon2id 哈希"
channels = ["ssh", "rdp"]
```

一次登录授权该账号配置的全部通道。通道名需与 FRPS 的完整 proxy_name 一致；
frpc 配置 user 时，名称可能包含用户前缀。修改配置后执行 `docker compose restart auth`。

旧版本升级：从配置中删除 public_origin，移除旧 Caddy 容器（可使用
`docker compose up -d --build --remove-orphans`）。原 .env 中的 AUTH_DOMAIN 已不再使用。

## 接入 FRPS

同宿主机的 FRPS，在原 frps.toml 中增加：

```toml
[[httpPlugins]]
name = "ip-auth"
addr = "127.0.0.1:9000"
path = "/handler"
ops = ["NewProxy", "NewUserConn"]
```

保留原有 FRPS token/OIDC 认证，重启 FRPS 即可。FRPC 示例见 deploy/frpc.example.toml。
`/handler` 只接受 plugin_sources 中的实际连接来源，不读取转发头。

如果还要通过 Compose 启动 FRPS：

```bash
cp deploy/frps.example.toml deploy/frps.toml
# 修改 deploy/frps.toml 的 auth.token。
docker compose -f compose.yaml -f compose.frps.yaml up -d --build
```

容器版 FRPS 通过 auth:9000 回调。默认对外端口为 7000、60022、63389。

## 运行约定

- 只运行一个 worker、一个容器实例；重启会清空临时授权。
- 五分钟后拒绝新建连接，已有连接继续使用；同一公网 IP 的设备共享对应通道的授权。
- 浏览器与 SSH/RDP 客户端需使用同一公网出口；PVE/路由转发也需保留来源 IP。
- 每个 IP 每 60 秒最多五次登录尝试；密码使用 Argon2id 哈希，日志不记录密码。
- 支持 TCP、STCP、HTTPS、TCPMUX 通道；FRP HTTP、UDP 通道无法通过此回调保护，故拒绝配置。
- Docker 子网 172.30.55.0/24 如有冲突，需同时修改 Compose 地址和配置中的来源 IP。

## 开发与验证

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python -m build
.venv/bin/python tests/integration_frp.py --frp-dir /path/to/unpacked/frp
```

CI 验证 Python 3.12/3.14、Docker 构建、Compose 配置和容器 HTTP 登录。
