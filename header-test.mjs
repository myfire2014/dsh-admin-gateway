// 验证网关转发给上游的请求头（Host/Origin/Referer 等）
import http from 'node:http'

const ECHO_PORT = 8091
const GATEWAY_PORT = 3084
const PASSWORD = 'header-test'

const echo = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({ host: req.headers.host, origin: req.headers.origin || null, referer: req.headers.referer || null, xff: req.headers['x-forwarded-for'] || null, url: req.url }))
})
await new Promise((r) => echo.listen(ECHO_PORT, '127.0.0.1', r))

const { apply } = await import('./index.js')
let cleanup = null
const ctx = { effect(fn) { cleanup = fn() } }
apply(ctx, {
  port: GATEWAY_PORT, host: '127.0.0.1',
  upstream: `http://127.0.0.1:${ECHO_PORT}`,
  adminPassword: PASSWORD, sessionTtlMs: 3600000,
  loginMaxAttempts: 5, loginWindowMs: 60000, loginLockMs: 60000,
  maxBodyBytes: 1048576, reqLimitPerMin: 0,
  allowedHosts: ['dsh.example.com'], allowedIps: [], cookieName: 'dsh_admin_session',
})
await new Promise((r) => setTimeout(r, 500))

// 登录
const cookie = await new Promise((resolve) => {
  const r = http.request({ host: '127.0.0.1', port: GATEWAY_PORT, path: '/__auth/login', method: 'POST', headers: { host: 'dsh.example.com', 'Content-Type': 'application/x-www-form-urlencoded' } }, (res) => resolve(res.headers['set-cookie'][0].split(';')[0]))
  r.write(`password=${PASSWORD}`)
  r.end()
})

// 模拟浏览器：Host: dsh.example.com, Origin: https://dsh.example.com
const result = await new Promise((resolve, reject) => {
  const r = http.request({
    host: '127.0.0.1', port: GATEWAY_PORT, path: '/api/host.describe', method: 'POST',
    headers: { host: 'dsh.example.com', origin: 'https://dsh.example.com', referer: 'https://dsh.example.com/', cookie, 'content-type': 'application/json' },
  }, (res) => {
    let d = ''
    res.on('data', (c) => (d += c))
    res.on('end', () => resolve({ status: res.statusCode, body: d }))
  })
  r.on('error', reject)
  r.end('{"args":{}}')
})

console.log('网关响应:', result.status, result.body)
if (cleanup) cleanup()
await new Promise((r) => echo.close(r))
