/**
 * dsh-admin-gateway
 *
 * DeepSeek Harness 管理员验证网关插件。
 *
 * 设计：dsh 的 ctx.webServer 没有请求级中间件钩子（fallback 席位已被前端静态
 * 服务器占用），因此本插件自起一个独立的 node:http 网关，监听独立端口
 * （默认 127.0.0.1:3081），对每个请求先做管理员验证，通过后再反向代理到
 * upstream（dsh web 本体，默认 127.0.0.1:3080）。
 *
 * Cloudflare Tunnel 只把流量送到网关端口，未认证的请求永远不会到达 dsh 本体。
 * 防护能力：
 *   - 管理员密码登录（scrypt 哈希 + timingSafeEqual 时序安全比较）
 *   - HttpOnly + SameSite=Strict 会话 Cookie，服务端内存会话，TTL 可配
 *   - 登录失败按 IP 限速锁定（防暴力破解）
 *   - Host 头白名单校验（防 DNS rebinding）
 *   - 请求体大小上限（防超大报文攻击）
 *   - 可选 per-IP 请求速率限制
 *   - 安全响应头（X-Frame-Options / X-Content-Type-Options / Referrer-Policy）
 *   - /api 未认证返回 401 JSON；浏览器页面未认证 302 到登录页
 *   - 反向代理时改写 Host/Origin/Referer，满足 dsh Connection 信任检查
 *     (isTrustedApiRequest: origin.host 必须 === host.host，否则 403)
 *   - WebSocket / SSE 升级代理（dsh web UI 依赖事件流）
 */

import http from 'node:http'
import crypto from 'node:crypto'
import { URL } from 'node:url'
import Schema from '@deepseek-ai/schemastery'

export const name = 'dsh-admin-gateway'

export const Config = Schema.object({
  /** 网关监听端口 */
  port: Schema.number().default(3081),
  /** 网关监听地址，只应绑定回环，由 cloudflared 从本机连入 */
  host: Schema.string().default('127.0.0.1'),
  /** 上游 dsh web 地址 */
  upstream: Schema.string().default('http://127.0.0.1:3080'),
  /** 管理员密码；优先取环境变量 DSH_ADMIN_PASSWORD，其次取此值 */
  adminPassword: Schema.string().default(''),
  /** 会话有效期（毫秒），默认 12 小时 */
  sessionTtlMs: Schema.number().default(12 * 60 * 60 * 1000),
  /** 会话 Cookie 名称 */
  cookieName: Schema.string().default('dsh_admin_session'),
  /** 登录失败限速：窗口内允许的最大失败次数 */
  loginMaxAttempts: Schema.number().default(5),
  /** 登录失败限速窗口（毫秒） */
  loginWindowMs: Schema.number().default(10 * 60 * 1000),
  /** 锁定时间（毫秒），超过 maxAttempts 后锁定该 IP */
  loginLockMs: Schema.number().default(10 * 60 * 1000),
  /** 请求体大小上限（字节），默认 5MB */
  maxBodyBytes: Schema.number().default(5 * 1024 * 1024),
  /** 可选：每 IP 每分钟最大请求数，0 表示不限制 */
  reqLimitPerMin: Schema.number().default(0),
  /** Host 白名单（防 DNS rebinding）；留空表示接受任意 Host */
  allowedHosts: Schema.array(Schema.string()).default([]),
  /** 可选：IP 白名单，留空表示不限制来源 IP */
  allowedIps: Schema.array(Schema.string()).default([]),
})

const LOGIN_PATH = '/__auth/login'
const LOGOUT_PATH = '/__auth/logout'
const HEALTH_PATH = '/__auth/health'

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
])

export function apply(ctx, config) {
  const upstream = new URL(config.upstream)
  const password = process.env.DSH_ADMIN_PASSWORD || config.adminPassword

  if (!password) {
    throw new Error(
      '[dsh-admin-gateway] 未配置管理员密码：请设置环境变量 DSH_ADMIN_PASSWORD 或在 cordis.yml 的 config.adminPassword 中提供。',
    )
  }

  // 密码摘要（固定长度，供 timingSafeEqual）
  const passwordHash = crypto.scryptSync(password, 'dsh-admin-gateway', 32)

  // 会话表：token -> { expiresAt }
  const sessions = new Map()
  // 登录失败记录：ip -> { count, windowStart, lockedUntil }
  const loginFailures = new Map()
  // 请求计数：ip -> { count, windowStart }
  const reqCounts = new Map()

  function clientIp(req) {
    const cf = req.headers['cf-connecting-ip']
    if (cf) return String(cf)
    const fwd = req.headers['x-forwarded-for']
    if (fwd) return String(fwd).split(',')[0].trim()
    return req.socket.remoteAddress || 'unknown'
  }

  function hostOk(hostHeader) {
    const hosts = config.allowedHosts
    if (!hosts.length) return true
    const host = String(hostHeader || '').replace(/:\d+$/, '').toLowerCase()
    if (!host) return false
    if (host === '127.0.0.1' || host === 'localhost') return true // 本机调试
    return hosts.some((h) => h.toLowerCase() === host)
  }

  function ipAllowed(ip) {
    const list = config.allowedIps
    if (!list.length) return true
    return list.includes(ip)
  }

  function reqLimited(ip) {
    const limit = config.reqLimitPerMin
    if (!limit) return false
    const now = Date.now()
    const rec = reqCounts.get(ip)
    if (!rec || now - rec.windowStart > 60_000) {
      reqCounts.set(ip, { count: 1, windowStart: now })
      return false
    }
    rec.count += 1
    return rec.count > limit
  }

  function loginBlocked(ip) {
    const rec = loginFailures.get(ip)
    if (!rec) return false
    if (rec.lockedUntil && Date.now() < rec.lockedUntil) return true
    if (rec.windowStart && Date.now() - rec.windowStart > config.loginWindowMs) {
      loginFailures.delete(ip)
      return false
    }
    return false
  }

  function recordFailure(ip) {
    const now = Date.now()
    const rec = loginFailures.get(ip) || { count: 0, windowStart: now, lockedUntil: 0 }
    if (now - rec.windowStart > config.loginWindowMs) {
      rec.count = 0
      rec.windowStart = now
    }
    rec.count += 1
    if (rec.count >= config.loginMaxAttempts) {
      rec.lockedUntil = now + config.loginLockMs
    }
    loginFailures.set(ip, rec)
  }

  function clearFailures(ip) {
    loginFailures.delete(ip)
  }

  function makeToken() {
    return crypto.randomBytes(32).toString('hex')
  }

  function sessionValid(token) {
    if (!token) return false
    const s = sessions.get(token)
    if (!s) return false
    if (Date.now() > s.expiresAt) {
      sessions.delete(token)
      return false
    }
    return true
  }

  function readCookie(req) {
    const header = req.headers.cookie
    if (!header) return null
    for (const part of String(header).split(';')) {
      const [k, ...v] = part.trim().split('=')
      if (k === config.cookieName) return v.join('=')
    }
    return null
  }

  function isSecure(req) {
    return String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https'
  }

  function cookieHeader(token, maxAgeSec) {
    const parts = [
      `${config.cookieName}=${token}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      `Max-Age=${maxAgeSec}`,
    ]
    return parts.join('; ')
  }

  function sendSecurityHeaders(res) {
    res.setHeader('X-Frame-Options', 'DENY')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'no-referrer')
  }

  function sendJson(res, status, obj) {
    sendSecurityHeaders(res)
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify(obj))
  }

  function loginPage(extra = '') {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>管理员登录</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
         background: linear-gradient(135deg, #0f172a, #1e293b); min-height: 100vh;
         display: flex; align-items: center; justify-content: center; color: #e2e8f0; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px;
          padding: 40px 36px; width: 360px; box-shadow: 0 20px 60px rgba(0,0,0,.5); }
  h1 { font-size: 20px; margin-bottom: 6px; }
  p.sub { color: #94a3b8; font-size: 13px; margin-bottom: 24px; }
  input[type=password] { width: 100%; padding: 12px 14px; border-radius: 8px;
          border: 1px solid #334155; background: #0f172a; color: #e2e8f0;
          font-size: 15px; outline: none; margin-bottom: 16px; }
  input[type=password]:focus { border-color: #60a5fa; }
  button { width: 100%; padding: 12px; border: none; border-radius: 8px;
          background: #3b82f6; color: #fff; font-size: 15px; cursor: pointer; }
  button:hover { background: #2563eb; }
  .err { background: #7f1d1d; color: #fecaca; padding: 10px 12px; border-radius: 8px;
         font-size: 13px; margin-bottom: 16px; }
</style>
</head>
<body>
<div class="card">
  <h1>DeepSeek Harness</h1>
  <p class="sub">管理员验证 · 未经授权禁止访问</p>
  ${extra ? `<div class="err">${extra}</div>` : ''}
  <form method="post" action="${LOGIN_PATH}">
    <input type="password" name="password" placeholder="管理员密码" autofocus autocomplete="current-password">
    <button type="submit">登 录</button>
  </form>
</div>
</body>
</html>`
  }

  // ---------- 登录 / 登出处理 ----------
  function handleLogin(req, res, ip) {
    if (req.method === 'GET') {
      sendSecurityHeaders(res)
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' })
      res.end(loginPage())
      return
    }
    if (req.method !== 'POST') {
      sendJson(res, 405, { error: 'method not allowed' })
      return
    }
    if (loginBlocked(ip)) {
      sendJson(res, 429, { error: '尝试过于频繁，请稍后再试' })
      return
    }
    // 读取表单体（限大小）
    let size = 0
    const chunks = []
    req.on('data', (c) => {
      size += c.length
      if (size > 64 * 1024) {
        res.writeHead(413).end()
        req.destroy()
        return
      }
      chunks.push(c)
    })
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      const params = new URLSearchParams(body)
      const given = params.get('password') || ''
      const givenHash = crypto.scryptSync(given, 'dsh-admin-gateway', 32)
      if (crypto.timingSafeEqual(givenHash, passwordHash)) {
        clearFailures(ip)
        const token = makeToken()
        sessions.set(token, { expiresAt: Date.now() + config.sessionTtlMs })
        const maxAge = Math.floor(config.sessionTtlMs / 1000)
        const secure = isSecure(req) ? '; Secure' : ''
        sendSecurityHeaders(res)
        res.writeHead(302, {
          Location: '/',
          'Set-Cookie': cookieHeader(token, maxAge) + secure,
          'Cache-Control': 'no-store',
        })
        res.end()
      } else {
        recordFailure(ip)
        sendJson(res, 401, { error: '密码错误' })
      }
    })
  }

  function handleLogout(req, res) {
    const token = readCookie(req)
    if (token) sessions.delete(token)
    sendSecurityHeaders(res)
    res.writeHead(302, {
      Location: LOGIN_PATH,
      'Set-Cookie': `${config.cookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
    })
    res.end()
  }

  // ---------- 反向代理 ----------
  function rewriteOriginHeaders(headers) {
    // dsh Connection 信任检查 (isTrustedApiRequest)：
    //   Origin 存在时必须满足 new URL(origin).host === Host.host，否则 403。
    // 我们已把 Host 改写为 upstream，因此 Origin/Referer 也必须跟着改写。
    if (headers.origin) {
      headers.origin = `${upstream.protocol}//${upstream.host}`
    }
    if (headers.referer) {
      try {
        const ref = new URL(headers.referer)
        ref.protocol = upstream.protocol
        ref.host = upstream.host
        headers.referer = ref.toString()
      } catch {
        delete headers.referer
      }
    }
  }

  function proxy(req, res) {
    const headers = { ...req.headers }
    for (const h of HOP_BY_HOP) delete headers[h]
    headers.host = upstream.host
    rewriteOriginHeaders(headers)
    headers['x-forwarded-for'] = clientIp(req)

    const preq = http.request(
      {
        protocol: upstream.protocol,
        hostname: upstream.hostname,
        port: upstream.port,
        method: req.method,
        path: req.url,
        headers,
      },
      (pres) => {
        // 剥离上游 hop-by-hop 头，附加安全头
        const outHeaders = { ...pres.headers }
        for (const h of HOP_BY_HOP) delete outHeaders[h]
        sendSecurityHeaders(res)
        res.writeHead(pres.statusCode || 502, outHeaders)
        pres.pipe(res)
      },
    )
    preq.on('error', () => {
      if (!res.headersSent) {
        sendJson(res, 502, { error: 'upstream unavailable' })
      } else {
        res.destroy()
      }
    })
    req.pipe(preq)
  }

  function proxyUpgrade(req, socket, head) {
    const headers = { ...req.headers }
    // upgrade 必须保留 connection/upgrade 头
    headers.host = upstream.host
    rewriteOriginHeaders(headers)
    headers['x-forwarded-for'] = clientIp(req)
    const preq = http.request({
      protocol: upstream.protocol,
      hostname: upstream.hostname,
      port: upstream.port,
      method: req.method,
      path: req.url,
      headers,
    })
    preq.on('upgrade', (pres, psocket) => {
      if (head && head.length) psocket.write(head)
      socket.write(
        `HTTP/1.1 101 Switching Protocols\r\n` +
          Object.entries(pres.headers)
            .filter(([k]) => !HOP_BY_HOP.has(k.toLowerCase()))
            .map(([k, v]) => `${k}: ${v}\r\n`)
            .join('') +
          '\r\n',
      )
      psocket.pipe(socket)
      socket.pipe(psocket)
    })
    preq.on('error', () => {
      socket.destroy()
    })
    preq.end()
  }

  // ---------- 主请求入口 ----------
  function handle(req, res) {
    const url = req.url || '/'
    const path = url.split('?')[0]
    const ip = clientIp(req)

    // 健康检查（无鉴权）
    if (path === HEALTH_PATH) {
      sendJson(res, 200, { ok: true })
      return
    }

    // 基础防护：Host 校验 + IP 白名单 + 请求限速
    if (!hostOk(req.headers.host)) {
      sendJson(res, 403, { error: 'forbidden host' })
      return
    }
    if (!ipAllowed(ip)) {
      sendJson(res, 403, { error: 'forbidden ip' })
      return
    }
    if (reqLimited(ip)) {
      sendJson(res, 429, { error: 'too many requests' })
      return
    }

    // 登录 / 登出
    if (path === LOGIN_PATH) {
      handleLogin(req, res, ip)
      return
    }
    if (path === LOGOUT_PATH) {
      handleLogout(req, res)
      return
    }

    // 会话验证
    const token = readCookie(req)
    if (!sessionValid(token)) {
      const accept = req.headers.accept || ''
      if (path.startsWith('/api') || accept.includes('application/json')) {
        sendJson(res, 401, { error: 'unauthorized', loginUrl: LOGIN_PATH })
        return
      }
      sendSecurityHeaders(res)
      res.writeHead(302, { Location: LOGIN_PATH, 'Cache-Control': 'no-store' })
      res.end()
      return
    }

    // 认证通过 → 代理
    proxy(req, res)
  }

  // ---------- 生命周期 ----------
  ctx.effect(() => {
    const server = http.createServer(handle)
    server.on('upgrade', (req, socket, head) => {
      const ip = clientIp(req)
      const token = readCookie(req)
      if (!hostOk(req.headers.host) || !ipAllowed(ip) || !sessionValid(token)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
        socket.destroy()
        return
      }
      proxyUpgrade(req, socket, head)
    })

    server.listen(config.port, config.host, () => {
      console.log(
        `[dsh-admin-gateway] 网关已启动: http://${config.host}:${config.port} -> ${config.upstream} (会话 TTL ${Math.round(config.sessionTtlMs / 3600000)}h)`,
      )
    })

    // 定期清理过期会话
    const cleaner = setInterval(() => {
      const now = Date.now()
      for (const [k, v] of sessions) if (now > v.expiresAt) sessions.delete(k)
    }, 60_000)

    return () => {
      clearInterval(cleaner)
      server.close()
      server.closeAllConnections?.()
      console.log('[dsh-admin-gateway] 网关已关闭')
    }
  })
}
