import { useState, useEffect } from 'react'
import './App.css'

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [csrfToken, setCsrfToken] = useState('')

  useEffect(() => {
    getCsrfToken()
    checkAuth()
  }, [])

  const getCsrfToken = async () => {
    try {
      const response = await fetch('/api/csrf-token')
      const data = await response.json()
      setCsrfToken(data.csrfToken)
    } catch (error) {
      console.error('Error getting CSRF token:', error)
    }
  }

  const checkAuth = async () => {
    try {
      const response = await fetch('/api/check-auth')
      if (response.ok) {
        setIsLoggedIn(true)
      }
    } catch (error) {
      console.error('Error checking auth:', error)
    }
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        credentials: 'include',
        body: JSON.stringify({ username, password })
      })

      if (response.ok) {
        setIsLoggedIn(true)
        setError('')
      } else {
        const data = await response.json()
        setError(data.error || 'Login gagal')
      }
    } catch (error) {
      setError('Terjadi kesalahan. Coba lagi.')
    }
  }

  const handleLogout = async () => {
    try {
      await fetch('/api/logout', {
        method: 'POST',
        credentials: 'include'
      })
      setIsLoggedIn(false)
      setUsername('')
      setPassword('')
    } catch (error) {
      console.error('Error during logout:', error)
    }
  }

  if (isLoggedIn) {
    return (
      <div className="success-container">
        <h1 className="success-title">Selamat Datang!</h1>
        <p className="success-message">
          Anda berhasil masuk ke sistem. Ini adalah halaman sukses yang tersembunyi.
          Selamat menikmati akses Anda ke area khusus ini.
        </p>
        <button className="logout-btn" onClick={handleLogout}>
          Keluar
        </button>
      </div>
    )
  }

  return (
    <div className="login-container">
      <h1 className="title">Yang Bisa bobol pasti bjorwi - Renz</h1>
      <form className="login-form" onSubmit={handleLogin}>
        <div className="input-group">
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>
        <div className="input-group">
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <button type="submit" className="login-btn">
          Masuk
        </button>
        {error && <p className="error-message">{error}</p>}
      </form>
    </div>
  )
}

export default App