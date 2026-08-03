import { Hono } from 'hono'
import { sign, verify } from 'hono/jwt'
import { cors } from 'hono/cors'

const app = new Hono().basePath('/api')
app.use('*', cors())

// ==========================================================
// ХЕЛПЕРЫ
// ==========================================================

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16)
  return bytes
}
function bytesToBase64(bytes) {
  let binary = ''
  bytes.forEach(b => binary += String.fromCharCode(b))
  return btoa(binary)
}
function base64ToBytes(b64) {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

// PBKDF2 хеширование пароля (Web Crypto API)
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder()
  const saltBytes = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16))
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  )
  return { hash: bytesToHex(new Uint8Array(bits)), salt: bytesToHex(saltBytes) }
}
async function verifyPassword(password, saltHex, hashHex) {
  const { hash } = await hashPassword(password, saltHex)
  return hash === hashHex
}

// AES-GCM шифрование IP-адреса
async function encryptIp(ip, keyB64) {
  const keyBytes = base64ToBytes(keyB64)
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(ip))
  return bytesToBase64(iv) + ':' + bytesToBase64(new Uint8Array(cipher))
}
async function decryptIp(encrypted, keyB64) {
  if (!encrypted) return null
  try {
    const [ivB64, cipherB64] = encrypted.split(':')
    const keyBytes = base64ToBytes(keyB64)
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt'])
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(ivB64) }, key, base64ToBytes(cipherB64)
    )
    return new TextDecoder().decode(plain)
  } catch {
    return null
  }
}

function escapeHtml(str) {
  if (!str) return str
  return str.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
}

const ALLOWED_TYPES = {
  'image/png': 'image', 'image/jpeg': 'image', 'image/gif': 'image', 'image/webp': 'image',
  'video/mp4': 'video', 'video/webm': 'video'
}
const MAX_FILE_SIZE = 20 * 1024 * 1024 // 20MB

// ==========================================================
// MIDDLEWARE
// ==========================================================

async function authMiddleware(c, next) {
  const authHeader = c.req.header('Authorization')
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Не авторизован' }, 401)
  }
  const token = authHeader.slice(7)
  try {
    const payload = await verify(token, c.env.JWT_SECRET)
    // всегда сверяем актуальные данные из базы (бан/роль/префикс могли измениться)
    const user = await c.env.DB.prepare('SELECT id, username, role, prefix, banned, avatar_url FROM users WHERE id = ?')
      .bind(payload.sub).first()
    if (!user) return c.json({ error: 'Пользователь не найден' }, 401)
    if (user.banned) return c.json({ error: 'Вы заблокированы' }, 403)
    c.set('user', user)
    await next()
  } catch {
    return c.json({ error: 'Невалидный токен' }, 401)
  }
}

async function adminMiddleware(c, next) {
  const user = c.get('user')
  if (user.role !== 'admin') return c.json({ error: 'Доступ только для админа' }, 403)
  await next()
}

// ==========================================================
// AUTH
// ==========================================================

app.post('/register', async (c) => {
  const { username, password } = await c.req.json()
  if (!username || !password || username.length < 3 || password.length < 4) {
    return c.json({ error: 'Ник от 3 символов, пароль от 4 символов' }, 400)
  }
  if (username.length > 24) return c.json({ error: 'Слишком длинный ник' }, 400)

  const existing = await c.env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first()
  if (existing) return c.json({ error: 'Ник уже занят' }, 409)

  const { hash, salt } = await hashPassword(password)
  const result = await c.env.DB.prepare(
    'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)'
  ).bind(username, hash, salt).run()

  const userId = result.meta.last_row_id
  const token = await sign({ sub: userId, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7 }, c.env.JWT_SECRET)
  return c.json({
    token,
    user: { id: userId, username, role: 'user', prefix: '', avatar_url: null }
  })
})

app.post('/login', async (c) => {
  const { username, password } = await c.req.json()
  if (!username || !password) return c.json({ error: 'Заполните все поля' }, 400)

  const user = await c.env.DB.prepare(
    'SELECT id, username, password_hash, salt, role, prefix, banned, avatar_url FROM users WHERE username = ?'
  ).bind(username).first()
  if (!user) return c.json({ error: 'Неверный ник или пароль' }, 401)

  const ok = await verifyPassword(password, user.salt, user.password_hash)
  if (!ok) return c.json({ error: 'Неверный ник или пароль' }, 401)
  if (user.banned) return c.json({ error: 'Вы заблокированы' }, 403)

  const token = await sign({ sub: user.id, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7 }, c.env.JWT_SECRET)
  return c.json({
    token,
    user: { id: user.id, username: user.username, role: user.role, prefix: user.prefix, avatar_url: user.avatar_url }
  })
})

app.get('/me', authMiddleware, async (c) => {
  return c.json({ user: c.get('user') })
})

// ==========================================================
// ПРОФИЛЬ
// ==========================================================

app.patch('/profile', authMiddleware, async (c) => {
  const user = c.get('user')
  const { username } = await c.req.json()
  if (!username || username.length < 3 || username.length > 24) {
    return c.json({ error: 'Ник от 3 до 24 символов' }, 400)
  }
  const existing = await c.env.DB.prepare('SELECT id FROM users WHERE username = ? AND id != ?')
    .bind(username, user.id).first()
  if (existing) return c.json({ error: 'Ник уже занят' }, 409)

  await c.env.DB.prepare('UPDATE users SET username = ? WHERE id = ?').bind(username, user.id).run()
  return c.json({ ok: true, username })
})

app.post('/profile/avatar', authMiddleware, async (c) => {
  const user = c.get('user')
  const form = await c.req.formData()
  const file = form.get('file')
  if (!file) return c.json({ error: 'Файл не передан' }, 400)
  if (!ALLOWED_TYPES[file.type] || ALLOWED_TYPES[file.type] !== 'image') {
    return c.json({ error: 'Аватар должен быть изображением' }, 400)
  }
  if (file.size > MAX_FILE_SIZE) return c.json({ error: 'Файл слишком большой' }, 400)

  const ext = file.type.split('/')[1]
  const key = `avatars/${user.id}-${crypto.randomUUID()}.${ext}`
  await c.env.BUCKET.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: file.type } })
  const url = `${c.env.R2_PUBLIC_URL}/${key}`

  await c.env.DB.prepare('UPDATE users SET avatar_url = ? WHERE id = ?').bind(url, user.id).run()
  return c.json({ ok: true, avatar_url: url })
})

// ==========================================================
// КОМНАТЫ
// ==========================================================

app.get('/rooms', authMiddleware, async (c) => {
  const { results } = await c.env.DB.prepare('SELECT id, name, description FROM rooms ORDER BY id').all()
  return c.json({ rooms: results })
})

app.post('/admin/rooms', authMiddleware, adminMiddleware, async (c) => {
  const { name, description } = await c.req.json()
  if (!name || name.length < 2) return c.json({ error: 'Название от 2 символов' }, 400)
  const result = await c.env.DB.prepare('INSERT INTO rooms (name, description) VALUES (?, ?)')
    .bind(name, description || '').run()
  return c.json({ ok: true, id: result.meta.last_row_id })
})

app.delete('/admin/rooms/:id', authMiddleware, adminMiddleware, async (c) => {
  const id = c.req.param('id')
  await c.env.DB.prepare('DELETE FROM rooms WHERE id = ?').bind(id).run()
  return c.json({ ok: true })
})

// ==========================================================
// СООБЩЕНИЯ
// ==========================================================

app.get('/rooms/:id/messages', authMiddleware, async (c) => {
  const user = c.get('user')
  const roomId = c.req.param('id')
  const sinceId = c.req.query('since_id') || 0

  const { results } = await c.env.DB.prepare(`
    SELECT m.id, m.text, m.attachment_url, m.attachment_type, m.user_ip_encrypted, m.created_at,
           u.id as user_id, u.username, u.prefix, u.avatar_url
    FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.room_id = ? AND m.id > ?
    ORDER BY m.id ASC LIMIT 200
  `).bind(roomId, sinceId).all()

  const messages = []
  for (const m of results) {
    const msg = {
      id: m.id,
      text: escapeHtml(m.text),
      attachment_url: m.attachment_url,
      attachment_type: m.attachment_type,
      created_at: m.created_at,
      user: { id: m.user_id, username: escapeHtml(m.username), prefix: escapeHtml(m.prefix), avatar_url: m.avatar_url }
    }
    if (user.role === 'admin') {
      msg.ip = await decryptIp(m.user_ip_encrypted, c.env.IP_ENCRYPTION_KEY)
    }
    messages.push(msg)
  }
  return c.json({ messages })
})

app.post('/rooms/:id/messages', authMiddleware, async (c) => {
  const user = c.get('user')
  const roomId = c.req.param('id')
  const body = await c.req.json()
  const text = (body.text || '').trim()
  const attachment_url = body.attachment_url || null
  const attachment_type = body.attachment_type || null

  if (!text && !attachment_url) return c.json({ error: 'Пустое сообщение' }, 400)
  if (text.length > 2000) return c.json({ error: 'Сообщение слишком длинное' }, 400)

  // rate limit — 1 сообщение раз в 3 сек
  const dbUser = await c.env.DB.prepare('SELECT last_message_at FROM users WHERE id = ?').bind(user.id).first()
  const now = Date.now()
  if (now - (dbUser.last_message_at || 0) < 3000) {
    return c.json({ error: 'Слишком часто, подождите немного' }, 429)
  }

  const ip = c.req.header('CF-Connecting-IP') || 'unknown'
  const encryptedIp = await encryptIp(ip, c.env.IP_ENCRYPTION_KEY)

  const result = await c.env.DB.prepare(`
    INSERT INTO messages (room_id, user_id, text, attachment_url, attachment_type, user_ip_encrypted)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(roomId, user.id, text, attachment_url, attachment_type, encryptedIp).run()

  await c.env.DB.prepare('UPDATE users SET last_message_at = ? WHERE id = ?').bind(now, user.id).run()

  return c.json({ ok: true, id: result.meta.last_row_id })
})

app.post('/upload/attachment', authMiddleware, async (c) => {
  const form = await c.req.formData()
  const file = form.get('file')
  if (!file) return c.json({ error: 'Файл не передан' }, 400)
  const kind = ALLOWED_TYPES[file.type]
  if (!kind) return c.json({ error: 'Разрешены только изображения и видео' }, 400)
  if (file.size > MAX_FILE_SIZE) return c.json({ error: 'Файл больше 20MB' }, 400)

  const ext = file.type.split('/')[1]
  const key = `attachments/${crypto.randomUUID()}.${ext}`
  await c.env.BUCKET.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: file.type } })
  const url = `${c.env.R2_PUBLIC_URL}/${key}`

  return c.json({ ok: true, url, type: kind })
})

// ==========================================================
// АДМИНКА: пользователи
// ==========================================================

app.get('/admin/users', authMiddleware, adminMiddleware, async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT id, username, role, prefix, banned, avatar_url, created_at FROM users ORDER BY id DESC'
  ).all()
  return c.json({ users: results })
})

app.post('/admin/users/:id/ban', authMiddleware, adminMiddleware, async (c) => {
  await c.env.DB.prepare('UPDATE users SET banned = 1 WHERE id = ?').bind(c.req.param('id')).run()
  return c.json({ ok: true })
})

app.post('/admin/users/:id/unban', authMiddleware, adminMiddleware, async (c) => {
  await c.env.DB.prepare('UPDATE users SET banned = 0 WHERE id = ?').bind(c.req.param('id')).run()
  return c.json({ ok: true })
})

app.post('/admin/users/:id/prefix', authMiddleware, adminMiddleware, async (c) => {
  const { prefix } = await c.req.json()
  await c.env.DB.prepare('UPDATE users SET prefix = ? WHERE id = ?').bind(prefix || '', c.req.param('id')).run()
  return c.json({ ok: true })
})

export default app
