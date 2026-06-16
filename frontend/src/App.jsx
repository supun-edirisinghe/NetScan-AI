import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useState } from 'react'
import {
  LayoutDashboard, Radar, Plus, LogOut, Shield,
  ChevronLeft, ChevronRight, User, Clock
} from 'lucide-react'
import './App.css'

const NAV = [
  { to: '/dashboard',  icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scans',      icon: Radar,           label: 'Scans' },
  { to: '/scans/new',  icon: Plus,            label: 'New Scan' },
  { to: '/scheduled',  icon: Clock,           label: 'Scheduled' },
]

export default function App() {
  const [collapsed, setCollapsed] = useState(false)
  const navigate = useNavigate()
  const username = localStorage.getItem('username') || 'User'

  const logout = () => {
    localStorage.clear()
    navigate('/login')
  }

  return (
    <div className={`app-shell ${collapsed ? 'collapsed' : ''}`}>
      <aside className="sidebar">
        <div className="sidebar-logo">
          <Shield size={24} className="logo-icon" />
          {!collapsed && <span className="logo-text">NetScan<span className="logo-ai">AI</span></span>}
        </div>

        <nav className="sidebar-nav">
          {NAV.map(({ to, icon: Icon, label }) => (
            <NavLink key={to} to={to} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
              <Icon size={18} />
              {!collapsed && <span>{label}</span>}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="user-info">
            <div className="user-avatar"><User size={14} /></div>
            {!collapsed && <span className="username">{username}</span>}
          </div>
          <button onClick={logout} className="logout-btn" title="Logout">
            <LogOut size={16} />
            {!collapsed && <span>Logout</span>}
          </button>
        </div>

        <button className="collapse-btn" onClick={() => setCollapsed(!collapsed)}>
          {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        </button>
      </aside>

      <main className="main-content">
        <div className="scan-line" />
        <Outlet />
      </main>
    </div>
  )
}