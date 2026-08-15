// 验证网关的 WebSocket upgrade 代理 + SSE 长连接转发
import http from 'node:http'
import net from 'node:net'

const UPSTREAM_PORT = 8090
const GATEWAY_PORT = 3083
const PASSWORD = 'ws-test-pass'

// mock 上游：支持 upgrade 和 SSE
const upstream = http.createServer((req, res) => {
  if (req.url === '/sse') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' })
    res.write('data: hello\n\n')
    const t = setInterval(() => res.write(`data: tick ${Date.now()}\n\n`), 200)
    req.on('close', () => clearInterval(t))
    return
  }
  res.writeHead(404)
  res.end()
})
upstream.on('upgrade', (req, socket) => {
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
  socket.write('WS-ECHO:')
  socket.pipe(socket)
})

await new Promise((r) => upstream.listen(UPSTREAM_PORT, '127.0.0.1', r))

const { apply } = await import('./index.js')
let cleanup = null
const ctx = { effect(fn) { cleanup = fn() } }
apply(ctx, {
  port: GATEWAY_PORT, host: '127.0.0.1',
  upstream: `http://127.0.0.1:${UPSTREAM_PORT}`,
  adminPassword: PASSWORD, sessionTtlMs: 3600000,
  loginMaxAttempts: 5, loginWindowMs: 60000, loginLockMs: 60000,
  maxBodyBytes: 1048576, reqLimitPerMin: 0,
  allowedHosts: ['dsh.example.com'], allowedIps: [], cookieName: 'dsh_admin_session',
})
await new Promise((r) => setTimeout(r, 500))

let passed = 0, failed = 0
const assert = (n, c, e = '') => { c ? (passed++, console.log(`  PASS  ${n}`)) : (failed++, console.log(`  FAIL  ${n} ${e}`)) }

// 登录拿 cookie
function login() {
  return new Promise((resolve) => {
    const r = http.request({ host: '127.0.0.1', port: GATEWAY_PORT, path: '/__auth/login', method: 'POST', headers: { host: 'dsh.example.com', 'Content-Type': 'application/x-www-form-urlencoded' } }, (res) => {
      resolve(res.headers['set-cookie'][0].split(';')[0])
    })
    r.write(`password=${PASSWORD}`)
    r.end()
  })
}
const cookie = await login()

// 测试1: SSE 长连接（认证后）
console.log('\n[1] SSE 长连接代理')
await new Promise((resolve) => {
  const r = http.request({ host: '127.0.0.1', port: GATEWAY_PORT, path: '/sse', headers: { host: 'dsh.example.com', Cookie: cookie } }, (res) => {
    assert('SSE 200', res.statusCode === 200)
    assert('SSE content-type', (res.headers['content-type'] || '').includes('text/event-stream'))
    let got = ''
    res.on('data', (c) => { got += c; if (got.includes('tick')) { assert('SSE 流式数据', got.includes('data: hello'), got); res.destroy(); resolve() } })
  })
  r.end()
})

// 测试2: WebSocket upgrade（认证后）
console.log('\n[2] WebSocket upgrade 代理')
await new Promise((resolve) => {
  const socket = net.connect(GATEWAY_PORT, '127.0.0.1', () => {
    socket.write(
      `GET /ws HTTP/1.1\r\nHost: dsh.example.com\r\nCookie: ${cookie}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`,
    )
  })
  let buf = ''
  socket.on('data', (d) => {
    buf += d.toString()
    if (buf.includes('101 Switching Protocols')) {
      assert('WS 101 升级成功', buf.includes('101 Switching Protocols'))
      socket.destroy()
      resolve()
    }
  })
  socket.on('error', (e) => { assert('WS 无错误', false, e.message); resolve() })
})

// 测试3: 未认证 upgrade 被拒绝
console.log('\n[3] 未认证 WebSocket 被拒绝')
await new Promise((resolve) => {
  const socket = net.connect(GATEWAY_PORT, '127.0.0.1', () => {
    socket.write(`GET /ws HTTP/1.1\r\nHost: dsh.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`)
  })
  let buf = ''
  socket.on('data', (d) => {
    buf += d.toString()
    if (buf.includes('401')) { assert('WS 401 拒绝', true); socket.destroy(); resolve() }
  })
  socket.on('close', () => { if (!buf.includes('401')) { assert('WS 401 拒绝', false, 'no 401'); } resolve() })
})

if (cleanup) cleanup()
await new Promise((r) => upstream.close(r))
console.log(`\n======== 结果: ${passed} passed, ${failed} failed ========`)
process.exit(failed ? 1 : 0)
