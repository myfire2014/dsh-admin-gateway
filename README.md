# dsh-admin-gateway

DeepSeek Harness (dsh) 管理员验证网关插件。

## 核心优势

- **零成本公网暴露**：只需一个绑定在 Cloudflare 的域名，无需公网 IP、无需开防火墙端口、无需购买服务器，一条 Cloudflare Tunnel 即可让 dsh web 安全上线公网（HTTPS / DDoS 防护全由 Cloudflare 提供）
- **开箱即用的安全防线**：管理员密码登录 + 会话 Cookie + 防暴力破解限速 + 防 DNS rebinding，未认证流量永远到不了 dsh 本体
- **即插即用**：npm 安装 → 配置密码 → 绑定域名，三步完成，无需改 dsh 一行代码

## 它解决什么问题

dsh 的 HTTP 服务器（`ctx.webServer`）没有请求级中间件钩子，`host` 默认绑定 `127.0.0.1`，无 TLS / 认证 / origin 策略。本插件自起一个**独立的 node:http 网关**，先做管理员验证，通过后反向代理到 dsh web 本体，并正确改写 Host / Origin / Referer 头以满足 dsh Connection 信任检查（`isTrustedApiRequest`）。

配合 Cloudflare Tunnel 使用时，隧道只把流量送到网关端口，**未认证请求永远到不了 dsh 本体**。

## 功能特性

- 管理员密码登录（scrypt 哈希 + `timingSafeEqual` 时序安全比较）
- HttpOnly + SameSite=Strict 会话 Cookie，服务端内存会话，TTL 可配
- 登录失败按 IP 限速锁定（防暴力破解）
- Host 头白名单校验（防 DNS rebinding）
- 请求体大小上限（防超大报文攻击）
- 可选 per-IP 请求速率限制
- 安全响应头（X-Frame-Options / X-Content-Type-Options / Referrer-Policy）
- `/api` 未认证返回 401 JSON；浏览器页面未认证 302 跳转登录页
- 反向代理时改写 Host / Origin / Referer，满足 dsh 信任检查
- WebSocket / SSE 升级代理（dsh web UI 依赖事件流）

## 安装

```sh
npm install dsh-admin-gateway
```

作为 dsh 插件（bundle）安装到 profile：

```sh
# 在插件目录的父目录执行（不要在插件目录内写 ./dsh-admin-gateway）
cd /path/to/parent && dsh plugin --profile web add ./dsh-admin-gateway
# 或通过 npm 安装包名引用
dsh plugin --profile web add dsh-admin-gateway
```

确认插件已生效：

```sh
dsh --profile web --dump-config | grep -A3 'admin-gateway'
# 看到 "# == dsh-admin-gateway" 层 = 成功
```

## 配置

插件通过 `cordis.patch.yml`（或 profile 的配置层）注入，示例：

```yaml
- insert:
    - id: admin-gateway
      name: dsh-admin-gateway
      config:
        port: 3081
        upstream: 'http://127.0.0.1:3080'
        allowedHosts:
          - dsh.example.com
        sessionTtlMs: 43200000
        maxBodyBytes: 5242880
```

### 配置项

| 字段 | 默认值 | 说明 |
|---|---|---|
| `port` | `3081` | 网关监听端口 |
| `host` | `127.0.0.1` | 网关监听地址，只应绑定回环（由 cloudflared 从本机连入） |
| `upstream` | `http://127.0.0.1:3080` | 上游 dsh web 地址 |
| `adminPassword` | `''` | 管理员密码；**优先取环境变量 `DSH_ADMIN_PASSWORD`**，其次取此值。两者都为空时插件启动报错 |
| `sessionTtlMs` | `43200000` (12h) | 会话有效期（毫秒） |
| `cookieName` | `dsh_admin_session` | 会话 Cookie 名称 |
| `loginMaxAttempts` | `5` | 登录失败限速：窗口内允许的最大失败次数 |
| `loginWindowMs` | `600000` (10min) | 登录失败限速窗口（毫秒） |
| `loginLockMs` | `600000` (10min) | 锁定时间（毫秒），超过 maxAttempts 后锁定该 IP |
| `maxBodyBytes` | `5242880` (5MB) | 请求体大小上限（字节） |
| `reqLimitPerMin` | `0` | 可选：每 IP 每分钟最大请求数，0 表示不限制 |
| `allowedHosts` | `[]` | Host 白名单（防 DNS rebinding）；留空接受任意 Host |
| `allowedIps` | `[]` | 可选：IP 白名单，留空不限制来源 IP |

## 使用步骤

1. **设置管理员密码**（推荐环境变量方式，避免明文进配置）：

   ```sh
   # 写入 600 权限的 env 文件，例如 /etc/dsh/admin-gateway.env
   echo 'DSH_ADMIN_PASSWORD=你的强密码' > /etc/dsh/admin-gateway.env
   chmod 600 /etc/dsh/admin-gateway.env
   ```

2. **配置 dsh 启动**（systemd 用户服务示例）：

   ```ini
   # ~/.config/systemd/user/dsh.service
   [Service]
   Type=simple
   EnvironmentFile=/etc/dsh/admin-gateway.env
   Environment=PATH=/path/to/npm-global/bin:/usr/local/bin:/usr/bin:/bin
   ExecStart=/path/to/dsh web
   Restart=always
   RestartSec=3
   ```

   ```sh
   loginctl enable-linger $USER   # 关键！否则用户服务不随开机启动
   systemctl --user daemon-reload && systemctl --user enable --now dsh.service
   ```

3. **Cloudflare Tunnel 只指向网关端口**（示例端口 3081），dsh 本体 3080 保持仅本机可访问。完整配置见下文「通过 Cloudflare Tunnel 暴露到公网」。

4. **访问**：浏览器打开外网域名 → 未认证跳转登录页 → 输入管理员密码 → 获得 HttpOnly 会话 Cookie → 正常使用 dsh web UI 与 API。

5. **改密码**：编辑 env 文件后重启 dsh 服务（`systemctl --user restart dsh.service`），旧会话 Cookie 到期前仍有效。

## 通过 Cloudflare Tunnel 暴露到公网

推荐用 Cloudflare Tunnel（cloudflared）把网关端口暴露到公网：不需要公网 IP、不用开防火墙端口，自带 HTTPS 和 DDoS 防护。**关键原则：隧道只指向网关端口（如 3081），dsh 本体（3080）保持仅本机监听。**

```
公网用户 → https://dsh.example.com → Cloudflare 边缘 → cloudflared 隧道 → 网关 127.0.0.1:3081 (鉴权) → dsh web 127.0.0.1:3080
```

### 1. 安装 cloudflared

```bash
# Ubuntu/Debian（apt 仓库）
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared focal main' | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update && sudo apt install -y cloudflared
```

### 2. 登录并授权域名

```bash
cloudflared tunnel login
```

会打印一个授权 URL，在**任意浏览器**打开（服务器无 GUI 时复制到本机浏览器打开），登录 Cloudflare 并选择要绑定的域名，授权完成后 `~/.cloudflared/cert.pem` 生成即成功。`cloudflared tunnel list` 报 `Cannot determine default origin certificate path` 说明登录没完成，重新执行。

### 3. 创建隧道

```bash
cloudflared tunnel create dsh-tunnel
# 输出：Tunnel credentials written to /home/<user>/.cloudflared/<UUID>.json
```

### 4. 编写 config.yml（指向网关端口！）

```yaml
# /etc/cloudflared/config.yml
tunnel: <UUID>                          # 上一步输出的 UUID
credentials-file: /etc/cloudflared/<UUID>.json
ingress:
  - hostname: dsh.example.com           # 你的外网域名
    service: http://localhost:3081      # ⚠️ 指向网关端口，不是 3080！
  - service: http_status:404            # catch-all 兜底规则，必须最后一行
```

注意：**写文件不要用 heredoc 管道过 sudo**（sudo 会吞掉 stdin 当密码导致文件没写成）。先写到 /tmp 再复制：`echo '<密码>' | sudo -S cp /tmp/config /etc/cloudflared/config.yml`。

### 5. 绑定 DNS

```bash
cloudflared tunnel route dns dsh-tunnel dsh.example.com
# 创建 CNAME：dsh.example.com → <UUID>.cfargotunnel.com
```

若报 `code: 1003 An A, AAAA, or CNAME record with that host already exists`，说明该域名已有 DNS 记录，需要先在 Cloudflare 控制台删除旧记录或用 API 更新。

### 6. 安装为 systemd 服务（开机自启）

```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

若提示 `service is already installed at cloudflared-update.service`（旧版本残留），先 `cloudflared service uninstall` 并删除 `/etc/systemd/system/cloudflared*.service` 再重装。建议确认 unit 里是 `--config /etc/cloudflared/config.yml` 的 config 模式（token 模式会忽略你的 config.yml）。

### 7. 验证

```bash
cloudflared tunnel info dsh-tunnel      # 看到 ≥1 条 active edge connection 即正常
sudo systemctl status cloudflared       # active (running)
sudo journalctl -u cloudflared -n 50    # 出现 INF Registered tunnel connection ... protocol=quic 即成功
```

外网测试（浏览器 UA，否则可能被 Cloudflare Bot 防护拦 403）：

```bash
curl -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0' -I https://dsh.example.com/
# 返回 302 跳转登录页 = 隧道 + 网关都正常
```

### Cloudflare Tunnel 常见坑

| 症状 | 原因 | 修复 |
|---|---|---|
| `curl` 返回 403 Attention Required | Cloudflare Bot 防护拦截 curl 默认 UA | 加浏览器 UA 头重试 |
| 隧道起了但外网访问旧站点 | 本地 DNS 缓存了旧解析（CDN 泛解析影子） | `sudo resolvectl flush-caches`，用 `dig @1.1.1.1 dsh.example.com` 验证返回 CF 边缘 IP（104.21.x / 172.67.x） |
| 服务重启后隧道不回来 | 原 unit 是 `Restart=on-failure`，干净退出不重启 | `sudo sed -i 's/Restart=on-failure/Restart=always/' /etc/systemd/system/cloudflared.service` 后 `daemon-reload` |
| `route dns` 报 code 1003 | 域名已有 DNS 记录，route 只创建不覆盖 | Cloudflare 控制台删除旧记录后重试，或用 API 更新 CNAME |
| 隧道指到 3080 后 API 403 | 请求绕过了网关直连 dsh，触发信任检查 | 确保 ingress 指向网关端口 3081 |

## 测试

项目自带无依赖 smoke test（mock ctx 加载插件 + 真实 HTTP 断言）：

```sh
node smoke-test.mjs
```

覆盖：未认证页面 302、未认证 /api 401 JSON、错误密码 401、正确密码 302+Set-Cookie（HttpOnly/SameSite=Strict）、伪造 Cookie 拒绝、恶意 Host 403（DNS rebinding）、登录限速 429、安全头、WebSocket upgrade 101（未认证 401）、SSE 长连接透传。

## 注意事项 / 已知坑

- **dsh 信任检查**：dsh 对 `/api` 请求有 `isTrustedApiRequest()` 检查——Host 必须为 loopback；带 Origin 头时 `origin.host` 必须 `=== host.host`，否则 403 "forbidden"。本插件已自动改写 Host/Origin/Referer（普通请求 + WebSocket upgrade 都处理），**无需额外配置**；若自行实现反代请务必同步改写这三个头。
- **WebSocket 事件流**：dsh web UI 依赖 `/api/events.mux` 与 `/api/events.host`。这两个路径 GET 返回 `426 upgrade required` 是**正常**现象（信任检查已通过，要求升级 WebSocket）；返回 403 才是信任检查失败。
- **RPC 调用格式**：`POST /api/<namespace>/<method>`，body 需带完整 `client-request` 结构（`{"type":"client-request","rpcId":"...","method":"<namespace>/<method>","payload":{}}`），`method` 字段必须与 endpoint 用斜杠形式一致。
- **密码来源优先级**：`DSH_ADMIN_PASSWORD` 环境变量 > `config.adminPassword`；两者都未设置时插件启动直接抛错。
- **会话存储**：会话表在内存中，重启 dsh 后所有会话失效（需重新登录）。
- **多实例**：网关无共享状态，多个 dsh 实例各自起网关时注意端口冲突。
- **上游地址**：`upstream` 只能指向本机或可信内网地址（网关本身不校验上游，配错会代理到意外目标）。

## License

MIT
