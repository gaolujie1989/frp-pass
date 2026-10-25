# frp-pass

通过 HTTPS 页面输入用户名和密码，给当前公网 IP 授权五分钟，然后连接 FRP
提供的 SSH、RDP 等服务。Python + Gunicorn + 原生 WSGI，不使用 Web 应用框架、
OTP、数据库或持久登录会话。

登录成功后，自动授权该账号配置的全部通道。授权以 **通道名 + IP** 为单位：
五分钟到期后拒绝新建连接，已经建立的连接继续使用；再次登录可续期。

## Docker 快速部署

要求：Docker Engine + Compose v2、一个指向服务器的域名、可用的公网 80/443
端口。默认 Compose 启动授权服务和 Caddy，Caddy 自动申请 HTTPS 证书。
如果服务器已有 Nginx/Caddy，可只启动 `auth` 并使用下方的自定义反代配置。

```bash
cp .env.example .env
cp config.example.toml config.toml
# 修改 .env 中的 AUTH_DOMAIN，填写自己的域名。
docker compose build auth
docker compose run --rm --no-deps auth python -m frp_ip_auth.hash_password
```

按提示输入至少 12 字节的密码并确认，将输出的完整 `$argon2id$...` 哈希复制到
`config.toml` 的 `users.admin.password_hash`，保留 TOML 字符串引号。
**没有默认登录密码**；示例哈希占位符不能启动服务。配置文件只读挂载，
需能被容器 UID/GID `10001:10001` 读取。Linux 上可设置为所属组 10001、权限 640。

```bash
docker compose up -d
docker compose logs -f auth
```

打开 `https://你的域名/login`，输入用户名和密码。页面会显示实际获准的 IP
及通道列表。浏览器和 SSH/RDP 客户端必须使用同一个公网出口 IP。

## 接入已有 FRPS

如果 FRPS 运行在 **同一宿主机**，在现有 `frps.toml` 增加：

```toml
[[httpPlugins]]
name = "ip-auth"
addr = "127.0.0.1:9000"
path = "/handler"
ops = ["NewProxy", "NewUserConn"]
```

重启 FRPS。保留原有的 FRPS token/OIDC 认证；本项目不替代 frpc 到 frps 的认证。
无需在 frpc 中增加 OTP、密码或其他插件配置。

`config.toml` 中的通道名必须与 FRPS 回调中的完整 `proxy_name` 一致。如果 frpc
设置了 `user`，完整名称通常含用户前缀，也需同步修改授权配置。

FRPS 若在其他容器里，`127.0.0.1` 是该容器自身，不能直接使用上面的地址。
应将它接入同一 Docker 网络，通过 `auth:9000` 回调，并将它的固定源地址加入
`plugin_sources`。跨主机部署需要专用可信网络；不要直接公网发布 `/handler`。

## 同时用 Docker 部署 FRPS

```bash
cp deploy/frps.example.toml deploy/frps.toml
# 修改 deploy/frps.toml 的 auth.token，设置独立的长随机 token。
docker compose -f compose.yaml -f compose.frps.yaml up -d --build
```

可选配置使用 FRP 官方镜像 `fatedier/frps:v0.71.1`。默认映射 FRPS 控制端口 7000，
以及 SSH 示例端口 60022、RDP 示例端口 63389。
按 `deploy/frpc.example.toml` 配置自己的 frpc，替换服务器地址、token 和 Windows
局域网地址。FRPS token 和网页登录密码用途不同。

## 账号与通道

```toml
public_origin = "https://access.example.com"
trusted_proxies = ["172.30.55.2/32"]
plugin_sources = ["127.0.0.1/32", "172.30.55.1/32", "172.30.55.4/32"]

[channels]
ssh = "tcp"
rdp = "tcp"

[users.admin]
password_hash = "这里填生成的 Argon2id 哈希"
channels = ["ssh", "rdp"]

[users.operator]
password_hash = "另一个账号的 Argon2id 哈希"
channels = ["rdp"]
```

修改配置后执行 `docker compose restart auth`。Compose 通过 `PUBLIC_ORIGIN`
将 `.env` 的 `AUTH_DOMAIN` 作为外部域名；直接运行时使用 TOML 的 `public_origin`。
不接受未知配置项、空账号列表或未知通道，防止配置遗漏意外放行。

## 自己管理 HTTPS 反向代理

只启动 `docker compose up -d auth`，将服务接入现有 Nginx/Caddy。
按真实网络修改 `trusted_proxies`，只信任实际反代的准确 IP/CIDR。
宿主机反代通过映射端口访问服务时，容器通常看到 Docker 网关 `172.30.55.1`，
而非宿主机 `127.0.0.1`；请先核对日志中的源地址。

Nginx 示例，放入你已有的 HTTPS `server` 中：

```nginx
client_max_body_size 4k;

location = /login {
    proxy_pass http://127.0.0.1:9000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_read_timeout 10s;
}
location = / {
    proxy_pass http://127.0.0.1:9000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_read_timeout 10s;
}
location / { return 404; }
```

代理必须**覆盖** `X-Forwarded-For` 为一个真实地址，不要拼接客户端提交的链。
本项目不接受多地址转发链。登录 POST 的 `Origin` 必须匹配 `public_origin`。
`/handler` 只允许 `plugin_sources` 中的实际网络对端；它不读取转发头。

## 安全边界与运行方式

- FRP 的 `NewUserConn` 支持 TCP、STCP、HTTPS、TCPMUX；本项目拒绝配置 HTTP、UDP，
  并在代理注册时检查类型。HTTPS 登录页面不代表 FRP 的 HTTP 通道也受到保护。
- 此机制在 FRPS 接到连接后做判断，不是防火墙封端口。端口扫描、SYN 洪泛等需要
  网络层处理；内部服务也应保留自己的认证。
- IP 授权会覆盖同一公网 NAT 出口下的其他设备，且仅限账号允许的通道。
  浏览器走代理、IPv6 而客户端走其他出口时，会因 IP 不一致而无法使用。
- 只运行 **一个 Gunicorn worker、一个容器实例**。八个线程共享内存并使用锁保护。
  不要通过 `--workers` 或 Compose scale 增加进程，否则各进程授权状态不一致。
- 容器或工作进程重启会清空临时授权。配置变更后需重新登录。
- 每个 IP 每 60 秒最多五次登录尝试，成功也计数；不撤销已经获得的授权。
  密码验证最多两个并发，避免占用全部工作线程。公网入口可额外配置限流。
- 授权与登录计数表各有 10000 条上限，满时拒绝新增；授权表按 `(通道, IP)` 计数。
  过期授权在查询/写入时清理，完全不依赖后台定时器。
- 密码只存 Argon2id 哈希，日志不记录密码、请求体或哈希。
- 默认 Docker 子网为 `172.30.55.0/24`。如与现有网络冲突，需一起修改 Compose 固定
  地址和 `config.toml` 的可信来源，不能只改其中一处。
- PVE/路由器转发业务端口时应保留来源 IP。DNAT 通常可以保留；如果还做 SNAT，
  FRPS 可能只看到网关 IP，无法与网页登录的公网 IP 匹配。

## 本地开发与验证

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python -m build
```

本地运行前也需配置真实哈希及 HTTPS 反代。纯 HTTP 的登录请求默认拒绝；
可按 `tests/test_app.py` 在进程内验证业务，避免通过关闭 HTTPS 校验进行测试。

CI 包含测试、代码检查、Python 包构建、Docker 镜像构建与容器启动冒烟测试。
`tests/integration_frp.py` 可配合官方 FRP 二进制验证真实 TCP 连接。

协议参考：[FRP 服务端插件](https://gofrp.org/en/docs/features/common/server-plugin/)。
