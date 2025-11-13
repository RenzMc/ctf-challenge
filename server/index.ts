import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import cookieSession from 'cookie-session'
import cookieParser from 'cookie-parser'
import crypto from 'crypto'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
app.set('trust proxy', 1)

const PORT = process.env.PORT || 3001

const users = {
  Renz: {
    password: crypto.createHash('sha256').update('KONTOLKEJEPITMEMEK').digest('hex')
  }
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}))

app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? (process.env.FRONTEND_URL || true) : true,
  credentials: true
}))

app.use(express.json({ limit: '10kb' }))
app.use(cookieParser())

app.use(cookieSession({
  name: 'session',
  keys: [process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex')],
  maxAge: 60 * 60 * 1000,
  secure: process.env.NODE_ENV === 'production',
  httpOnly: true,
  sameSite: 'lax'
}))

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Terlalu banyak percobaan. Coba lagi nanti.' },
  standardHeaders: true,
  legacyHeaders: false,
})

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Terlalu banyak percobaan login. Coba lagi dalam 15 menit.' },
  skipSuccessfulRequests: true
})

app.get('/api/csrf-token', (req, res) => {
  const token = crypto.randomBytes(32).toString('hex')
  ;(req as any).session = (req as any).session || {}
  ;(req as any).session.csrfToken = token
  ;(req as any).session.csrfTokenExpires = Date.now() + 60 * 60 * 1000
  res.json({ csrfToken: token })
})

app.use(limiter)

const validateInput = (input: string): boolean => {
  return /^[a-zA-Z0-9_]+$/.test(input) && input.length > 0 && input.length <= 50
}

app.post('/api/login', authLimiter, (req, res) => {
  const { username, password } = req.body
  const tokenHeader = (req.headers['x-csrf-token'] || req.headers['X-CSRF-Token'] || '') as string
  const session = (req as any).session || {}

  if (!tokenHeader || !session.csrfToken || tokenHeader !== session.csrfToken || Date.now() > (session.csrfTokenExpires || 0)) {
    return res.status(403).json({ error: 'CSRF token tidak valid' })
  }

  if (!validateInput(username) || !password || password.length > 100) {
    return res.status(400).json({ error: 'Input tidak valid' })
  }

  const user = users[username as keyof typeof users]
  const hashedPassword = crypto.createHash('sha256').update(password).digest('hex')

  if (!user || user.password !== hashedPassword) {
    const delay = Math.random() * 2000 + 1000
    setTimeout(() => {
      res.status(401).json({ error: 'Username atau password salah' })
    }, delay)
    return
  }

  session.authenticated = true
  session.username = username
  session.csrfToken = crypto.randomBytes(32).toString('hex')
  session.csrfTokenExpires = Date.now() + 60 * 60 * 1000
  ;(req as any).session = session

  res.json({ success: true })
})

app.get('/api/check-auth', (req, res) => {
  const session = (req as any).session || {}
  if (session.authenticated) {
    res.json({ authenticated: true, username: session.username })
  } else {
    res.status(401).json({ authenticated: false })
  }
})

app.post('/api/logout', (req, res) => {
  ;(req as any).session = {}
  res.clearCookie('session')
  res.json({ success: true })
})

app.use(express.static(path.join(__dirname, '../dist')))

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'))
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
