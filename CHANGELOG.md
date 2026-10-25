# v0.1.0

首个版本：通过普通 HTTP 页面输入用户名密码，为当前 IP 授权五分钟，允许新建指定 FRP 通道的连接。

- Python、Gunicorn、原生 WSGI；无需 Web 应用框架、数据库或 OTP。
- Argon2id 密码哈希、账号通道范围、登录限流和临时授权。
- 提供 Docker Compose、配置模板和 FRPS/FRPC 接入示例。
- 44 项测试通过，Docker 非 root、只读容器 HTTP 登录检查通过。
- 单进程内存授权，重启清空；授权到期不主动断开已建立连接。

镜像：`ghcr.io/gaolujie1989/frp-pass:0.1.0`，同时提供 `latest` 标签，架构为 `linux/amd64`。

Release 附件包含 `compose.yaml`、`config.example.toml` 和 `SHA256SUMS`。
首次使用需生成密码哈希并填写配置；具体步骤见 README。
