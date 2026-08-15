// 真实 WebSocket 事件流握手验证：登录 → WS 连接 /api/events.mux
import http from 'node:http'
import net from 'node:net'
import crypto from 'node:crypto'

const GATEWAY_PORT = 3081
const PASSWORD = 'HJHeURNz1vXZ1Q7ZFBaIagSI'

// 1. 登录拿 cookie
const cookie = await new Promise((resolve, reject) => {
  const r = http.request({
    host: '127.0.0.1', port: GATEWAY_PORT, path: '/__auth/login', method: 'POST',
    headers: { host: 'dsh.example.com', 'Content-Type': 'application/x-www-form-urlencoded' },
  }, (res) => {
    const sc = res.headers['set-cookie']
    resolve(sc ? sc[0].split(';')[0] : null)
  })
  r.on('error', reject)
  r.write(`password=${PASSWORD}`)
  r.end()
})
console.log('cookie:', cookie ? 'OK' : 'FAIL')

// 2. 发起 WS 握手（带浏览器头 + Origin）
const key = crypto.randomBytes(16).toString('base64')
const socket = net.connect(GATEWAY_PORT, '127.0.0.1', () => {
  socket.write(
    `GET /api/events.mux HTTP/1.1\r\n` +
    `Host: dsh.example.com\r\n` +
    `Origin: https://dsh.example.com\r\n` +
    `Cookie: ${cookie}\r\n` +
    `Upgrade: websocket\r\n` +
    `Connection: Upgrade\r\n` +
    `Sec-WebSocket-Key: ${key}\r\n` +
    `Sec-WebSocket-Version: 13\r\n` +
    `Sec-Fetch-Site: same-origin\r\n` +
    `\r\n`,
  )
})

let buf = ''
const timeout = setTimeout(() => { console.log('TIMEOUT'); socket.destroy(); process.exit(1) }, 8000)
socket.on('data', (d) => {
  buf += d.toString()
  if (buf.includes('\r\n\r\n')) {
    const head = buf.split('\r\n\r\n')[0]
    const statusLine = head.split('\r\n')[0]
    console.log('WS 握手响应:', statusLine)
    const accept = head.split('\r\n').find((l) => l.toLowerCase().startsWith('sec-websocket-accept'))
    const expect = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
    console.log('Sec-WebSocket-Accept:', accept ? '正确 (' + (accept.includes(expect) ? 'MATCH' : 'MISMATCH') + ')' : '缺失')
    console.log(accept.includes(expect) && statusLine.includes('101') ? 'RESULT: WS PASS' : 'RESULT: WS FAIL')
    clearTimeout(timeout)
    socket.destroy()
    process.exit(accept.includes(expect) && statusLine.includes('101') ? 0 : 1)
  }
})
socket.on('error', (e) => { console.log('socket error:', e.message); process.exit(1) })
