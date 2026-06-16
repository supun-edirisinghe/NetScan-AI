import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff, Loader2 } from 'lucide-react'
import { api } from '../utils/api'
import './Login.css'

export default function Login() {
  const navigate = useNavigate()
  const [tab, setTab] = useState('login')
  const [showPw, setShowPw] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [form, setForm] = useState({ username: '', password: '', email: '', full_name: '' })

  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }))

  const submit = async (e) => {
    e.preventDefault()
    setLoading(true); setError('')
    try {
      if (tab === 'login') {
        const data = await api.login(form.username, form.password)
        localStorage.setItem('token', data.access_token)
        localStorage.setItem('username', data.username)
        navigate('/dashboard')
      } else {
        await api.register(form)
        setTab('login')
        setError('')
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-bg">
        {[...Array(20)].map((_, i) => (
          <div key={i} className="grid-dot" style={{
            left: `${(i % 5) * 25}%`, top: `${Math.floor(i / 5) * 25}%`
          }} />
        ))}
      </div>

      <div className="login-card">
        <div className="login-logo">
          <Shield size={32} />
          <h1>NetScan<span>AI</span></h1>
        </div>
        <p className="login-subtitle">Network Security Intelligence Platform</p>

        <div className="login-tabs">
          <button className={tab === 'login' ? 'active' : ''} onClick={() => setTab('login')}>Login</button>
          <button className={tab === 'register' ? 'active' : ''} onClick={() => setTab('register')}>Register</button>
        </div>

        <form onSubmit={submit}>
          {tab === 'register' && (
            <>
              <div className="form-group">
                <label className="form-label">Full Name</label>
                <input className="form-input" placeholder="Jane Smith" value={form.full_name} onChange={set('full_name')} />
              </div>
              <div className="form-group">
                <label className="form-label">Email</label>
                <input className="form-input" type="email" placeholder="jane@company.com" value={form.email} onChange={set('email')} required />
              </div>
            </>
          )}
          <div className="form-group">
            <label className="form-label">Username</label>
            <input className="form-input" placeholder="username" value={form.username} onChange={set('username')} required />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <div className="pw-wrapper">
              <input
                className="form-input"
                type={showPw ? 'text' : 'password'}
                placeholder="••••••••"
                value={form.password}
                onChange={set('password')}
                required
              />
              <button type="button" className="pw-toggle" onClick={() => setShowPw(!showPw)}>
                {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {error && <div className="login-error">{error}</div>}

          <button type="submit" className="btn btn-primary login-submit" disabled={loading}>
            {loading ? <Loader2 size={16} className="spin" /> : null}
            {tab === 'login' ? 'Sign In' : 'Create Account'}
          </button>
        </form>
      </div>
    </div>
  )
}
