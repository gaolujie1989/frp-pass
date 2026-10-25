# frp-pass

用户名密码登录后，给当前 IP 授权五分钟，允许连接指定的 FRP 通道。
Python + Gunicorn + 原生 WSGI，无 Web 应用框架、OTP、数据库或登录会话。

**项目只提供普通 HTTP 服务，默认端口 9000。**

## 使用已构建镜像

镜像：`ghcr.io/gaolujie1989/frp-pass:0.1.0`（`linux/amd64`），也提供 `latest`。
下载 Release 附件中的 `compose.yaml` 和 `config.example.toml`，放在同一目录：

```bash
cp config.example.toml config.toml
docker compose pull auth
docker compose run --rm --no-deps auth python -m frp_ip_auth.hash_password
# 将生成的哈希填入 config.toml 的 users.admin.password_hash。
docker compose up -d --no-build
```

如果镜像包设为私有，拉取前需要先登录 GHCR；公开镜像可以直接拉取。

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

服务默认监听宿主机 `127.0.0.1:9000`，直接访问 `http://127.0.0.1:9000/login`。
如需局域网访问，将 Compose 端口映射改为 `宿主机内网IP:9000:9000`。

## 配置

```toml
trusted_proxies = [] # 默认记录连接来源 IP
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

默认使用连接来源 IP；仅在配置 `trusted_proxies` 时读取可信代理传来的单个
`X-Forwarded-For` 地址。升级旧版本时请按最新配置模板调整，并执行
`docker compose up -d --build --remove-orphans`。

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

## 发布版本

同时修改 `pyproject.toml` 的版本号和 `compose.yaml` 的镜像版本后，在 GitHub Actions 中手动运行主分支的 CI。
检查通过后会推送 GHCR 镜像并创建对应 Release；已有 Release 不覆盖。
