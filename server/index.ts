import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import session from 'express-session'
import cookieParser from 'cookie-parser'
import crypto from 'crypto'
import path from 'path'
import { fileURLToPath } from 'url'

import 'express-session'
declare module 'express-session' {
  interface SessionData {
    authenticated?: boolean
    username?: string
  }
}

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
app.set('trust proxy', true)

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

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Terlalu banyak percobaan. Coba lagi nanti.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const xff = req.headers['x-forwarded-for']
    if (typeof xff === 'string') return xff.split(',')[0].trim()
    return req.ip
  }
})

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { error: 'Terlalu banyak percobaan login. Coba lagi dalam 15 menit.' },
  skipSuccessfulRequests: true
})

app.use(limiter)
app.use(express.json({ limit: '10kb' }))
app.use(cookieParser())
app.use(session({
  secret: crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 60 * 60 * 1000,
    sameSite: 'lax'
  }
}))

const generateCSRFToken = (): string => {
  return crypto.randomBytes(32).toString('hex')
}

const validateInput = (input: string): boolean => {
  return /^[a-zA-Z0-9_]+$/.test(input) && input.length > 0 && input.length <= 50
}

app.get('/api/csrf-token', (req, res) => {
  const token = generateCSRFToken()
  res.cookie('XSRF-TOKEN', token, {
    maxAge: 60 * 60 * 1000,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    httpOnly: false
  })
  res.json({ csrfToken: token })
})

app.post('/api/login', authLimiter, (req, res) => {
  const { username, password } = req.body
  const cookieToken = (req as any).cookies?.['XSRF-TOKEN']
  const headerToken = req.headers['x-csrf-token']
  if (!headerToken || !cookieToken || headerToken !== cookieToken) {
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

  ;(req.session as any).authenticated = true
  ;(req.session as any).username = username

  res.json({ success: true })
})

app.get('/api/check-auth', (req, res) => {
  if ((req.session as any).authenticated) {
    res.json({ authenticated: true, username: (req.session as any).username })
  } else {
    res.status(401).json({ authenticated: false })
  }
})

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Gagal logout' })
    }
    res.clearCookie('connect.sid')
    res.json({ success: true })
  })
})

app.use(express.static(path.join(__dirname, '../dist')))

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'))
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
