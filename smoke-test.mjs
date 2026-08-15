// 冒烟测试：独立验证 dsh-admin-gateway 插件的鉴权 + 代理逻辑
// 用法：先起一个上游 mock 服务器（8089），再加载插件（监听 3082），然后跑断言
import http from 'node:http'
import { execSync } from 'node:child_process'

const UPSTREAM_PORT = 8089
const GATEWAY_PORT = 3082
const PASSWORD = 'test-admin-pass-123'

// 1. 起 mock 上游（模拟 dsh web）
const upstream = http.createServer((req, res) => {
  if (req.url === '/api/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: true, from: 'upstream' }))
    return
  }
  res.writeHead(200, { 'Content-Type': 'text/html' })
  res.end('<html><body>DSH WEB UI</body></html>')
})

await new Promise((r) => upstream.listen(UPSTREAM_PORT, '127.0.0.1', r))

// 2. 用一个 mock ctx 加载插件
const { apply } = await import('./index.js')
let cleanup = null
const ctx = {
  effect(fn) {
    cleanup = fn()
  },
}

apply(ctx, {
  port: GATEWAY_PORT,
  host: '127.0.0.1',
  upstream: `http://127.0.0.1:${UPSTREAM_PORT}`,
  adminPassword: PASSWORD,
  sessionTtlMs: 3600000,
  loginMaxAttempts: 3,
  loginWindowMs: 60000,
  loginLockMs: 60000,
  maxBodyBytes: 1024 * 1024,
  reqLimitPerMin: 0,
  allowedHosts: ['dsh.example.com'],
  allowedIps: [],
  cookieName: 'dsh_admin_session',
})

// 等待网关启动
await new Promise((r) => setTimeout(r, 500))

function req(path, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request({
      host: '127.0.0.1',
      port: GATEWAY_PORT,
      path,
      method,
      headers: { host: 'dsh.example.com', ...headers },
    }, (res) => {
      let data = ''
      res.on('data', (c) => (data += c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }))
    })
    r.on('error', reject)
    if (body) r.write(body)
    r.end()
  })
}

let passed = 0
let failed = 0
function assert(name, cond, extra = '') {
  if (cond) {
    passed++
    console.log(`  PASS  ${name}`)
  } else {
    failed++
    console.log(`  FAIL  ${name} ${extra}`)
  }
}

// 3. 测试用例
console.log('\n[1] 未认证访问页面 -> 302 到登录页')
let r = await req('/')
assert('302 redirect', r.status === 302, `got ${r.status}`)
assert('Location = /__auth/login', r.headers.location === '/__auth/login', r.headers.location)

console.log('\n[2] 未认证访问 /api -> 401 JSON')
r = await req('/api/health')
assert('401 status', r.status === 401, `got ${r.status}`)
assert('json body', r.body.includes('unauthorized'), r.body)

console.log('\n[3] GET 登录页 -> 200 HTML 表单')
r = await req('/__auth/login')
assert('200 status', r.status === 200, `got ${r.status}`)
assert('has form', r.body.includes('<form') && r.body.includes('password'), 'no form')

console.log('\n[4] 错误密码 -> 401')
r = await req('/__auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: 'password=wrong-pass',
})
assert('401 status', r.status === 401, `got ${r.status}`)

console.log('\n[5] 正确密码 -> 302 + Set-Cookie')
r = await req('/__auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: `password=${encodeURIComponent(PASSWORD)}`,
})
assert('302 status', r.status === 302, `got ${r.status}`)
const setCookie = r.headers['set-cookie']
assert('Set-Cookie present', !!setCookie, JSON.stringify(setCookie))
const cookie = setCookie ? setCookie[0].split(';')[0] : ''
assert('HttpOnly', setCookie && setCookie[0].includes('HttpOnly'))
assert('SameSite=Strict', setCookie && setCookie[0].includes('SameSite=Strict'))

console.log('\n[6] 带 Cookie 访问页面 -> 200 代理到上游')
r = await req('/', { headers: { Cookie: cookie } })
assert('200 status', r.status === 200, `got ${r.status}`)
assert('upstream body', r.body.includes('DSH WEB UI'), r.body)

console.log('\n[7] 带 Cookie 访问 /api -> 200 代理')
r = await req('/api/health', { headers: { Cookie: cookie } })
assert('200 status', r.status === 200, `got ${r.status}`)
assert('upstream json', r.body.includes('"from":"upstream"'), r.body)

console.log('\n[8] 伪造 Cookie 访问 /api -> 401')
r = await req('/api/health', { headers: { Cookie: 'dsh_admin_session=forged-token' } })
assert('401 status', r.status === 401, `got ${r.status}`)

console.log('\n[8b] 伪造 Cookie 访问页面 -> 302 登录页')
r = await req('/', { headers: { Cookie: 'dsh_admin_session=forged-token' } })
assert('302 status', r.status === 302, `got ${r.status}`)

console.log('\n[9] 恶意 Host 头（DNS rebinding）-> 403')
r = await req('/', { headers: { host: 'evil.example.com', Cookie: cookie } })
assert('403 status', r.status === 403, `got ${r.status}`)

console.log('\n[10] 安全响应头')
r = await req('/', { headers: { Cookie: cookie } })
assert('X-Frame-Options DENY', r.headers['x-frame-options'] === 'DENY')
assert('X-Content-Type-Options nosniff', r.headers['x-content-type-options'] === 'nosniff')

console.log('\n[11] 连续错误密码 -> 锁定 429')
for (let i = 0; i < 3; i++) {
  await req('/__auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'password=nope',
  })
}
r = await req('/__auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: `password=${encodeURIComponent(PASSWORD)}`,
})
assert('429 locked', r.status === 429, `got ${r.status}`)

console.log('\n[12] 健康检查无需鉴权')
r = await req('/__auth/health')
assert('200 ok', r.status === 200 && r.body.includes('"ok":true'), `got ${r.status} ${r.body}`)

console.log('\n[13] 登出 -> 302 + Cookie 清除')
r = await req('/__auth/logout', { headers: { Cookie: cookie } })
assert('302 status', r.status === 302)
assert('max-age=0', r.headers['set-cookie'] && r.headers['set-cookie'][0].includes('Max-Age=0'))

console.log('\n[14] 登出后原 Cookie 失效 -> 302 登录页')
r = await req('/', { headers: { Cookie: cookie } })
assert('302 status', r.status === 302, `got ${r.status}`)
assert('Location login', r.headers.location === '/__auth/login')

// 4. 清理
if (cleanup) cleanup()
await new Promise((r) => upstream.close(r))

console.log(`\n======== 结果: ${passed} passed, ${failed} failed ========`)
process.exit(failed ? 1 : 0)
