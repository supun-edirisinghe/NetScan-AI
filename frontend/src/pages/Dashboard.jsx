import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, CartesianGrid, Legend,
} from 'recharts'
import {
  Activity, Shield, AlertTriangle, Globe,
  TrendingUp, Clock, ChevronRight, Plus, Loader2
} from 'lucide-react'
import { api } from '../utils/api'
import './Dashboard.css'

const RISK_COLORS = {
  critical: '#ff4757', high: '#ff6b35', medium: '#ffa502', low: '#2ed573', unknown: '#8b949e'
}

function StatCard({ icon: Icon, label, value, sub, color = 'accent', trend }) {
  return (
    <div className={`stat-card stat-${color}`}>
      <div className="stat-icon-wrap">
        <Icon size={20} />
      </div>
      <div className="stat-body">
        <div className="stat-value">{value ?? '—'}</div>
        <div className="stat-label">{label}</div>
        {sub && <div className="stat-sub">{sub}</div>}
      </div>
    </div>
  )
}

const CUSTOM_TOOLTIP_STYLE = {
  background: '#111820', border: '1px solid #1e2d3d', borderRadius: 8,
  color: '#e6edf3', fontSize: 12, padding: '8px 12px',
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    api.dashboardStats()
      .then(setStats)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="page loading-center">
      <Loader2 size={32} className="spin" style={{ color: 'var(--accent)' }} />
    </div>
  )

  const riskPieData = Object.entries(stats?.risk_distribution || {}).map(([k, v]) => ({
    name: k.toUpperCase(), value: v, color: RISK_COLORS[k]
  }))

  const portBarData = (stats?.top_open_ports || []).map(p => ({
    port: p.port, count: p.count,
  }))

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">Network security overview & analytics</p>
        </div>
        <button className="btn btn-primary" onClick={() => navigate('/scans/new')}>
          <Plus size={16} /> New Scan
        </button>
      </div>

      {/* Stat cards */}
      <div className="grid-4" style={{ marginBottom: 24 }}>
        <StatCard icon={Activity} label="Total Scans" value={stats?.total_scans} sub={`${stats?.completed_scans} completed`} color="accent" />
        <StatCard icon={Globe} label="Hosts Scanned" value={stats?.total_hosts_scanned} sub={`${stats?.total_hosts_up} online`} color="info" />
        <StatCard icon={Shield} label="Open Ports" value={stats?.total_open_ports} color="warning" />
        <StatCard icon={AlertTriangle} label="High Risk Hosts" value={stats?.total_high_risk_hosts} sub={`Avg risk: ${stats?.avg_risk_score}/100`} color="danger" />
      </div>

      {/* Charts row */}
      <div className="grid-2" style={{ marginBottom: 24 }}>
        {/* Port distribution */}
        <div className="card">
          <h3 className="chart-title">Top Open Ports</h3>
          {portBarData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={portBarData} margin={{ top: 5, right: 5, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2d3d" />
                <XAxis dataKey="port" tick={{ fill: '#8b949e', fontSize: 11 }} />
                <YAxis tick={{ fill: '#8b949e', fontSize: 11 }} />
                <Tooltip contentStyle={CUSTOM_TOOLTIP_STYLE} />
                <Bar dataKey="count" fill="#00d4aa" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : <EmptyChart label="No scan data yet" />}
        </div>

        {/* Risk distribution pie */}
        <div className="card">
          <h3 className="chart-title">Risk Distribution</h3>
          {riskPieData.length > 0 ? (
            <div className="pie-wrap">
              <ResponsiveContainer width="60%" height={220}>
                <PieChart>
                  <Pie data={riskPieData} cx="50%" cy="50%" innerRadius={55} outerRadius={80} paddingAngle={3} dataKey="value">
                    {riskPieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={CUSTOM_TOOLTIP_STYLE} />
                </PieChart>
              </ResponsiveContainer>
              <div className="pie-legend">
                {riskPieData.map(d => (
                  <div key={d.name} className="legend-item">
                    <span className="legend-dot" style={{ background: d.color }} />
                    <span>{d.name}</span>
                    <span className="legend-val">{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : <EmptyChart label="Run scans to see risk distribution" />}
        </div>
      </div>

      {/* Scan activity + recent scans */}
      <div className="grid-2">
        <div className="card">
          <h3 className="chart-title">Scan Activity (30 days)</h3>
          {stats?.scan_activity?.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={stats.scan_activity} margin={{ top: 5, right: 5, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2d3d" />
                <XAxis dataKey="date" tick={{ fill: '#8b949e', fontSize: 10 }}
                  tickFormatter={d => d.slice(5)} />
                <YAxis tick={{ fill: '#8b949e', fontSize: 11 }} />
                <Tooltip contentStyle={CUSTOM_TOOLTIP_STYLE} />
                <Line type="monotone" dataKey="count" stroke="#00d4aa" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          ) : <EmptyChart label="No activity data yet" />}
        </div>

        {/* Recent scans */}
        <div className="card">
          <div className="chart-title-row">
            <h3 className="chart-title">Recent Scans</h3>
            <button className="btn-text" onClick={() => navigate('/scans')}>
              View all <ChevronRight size={14} />
            </button>
          </div>
          <div className="recent-list">
            {stats?.recent_scans?.length > 0 ? stats.recent_scans.map(s => (
              <div key={s.id} className="recent-item" onClick={() => navigate(`/scans/${s.id}`)}>
                <div>
                  <div className="recent-name">{s.name}</div>
                  <div className="recent-target mono">{s.target}</div>
                </div>
                <div className="recent-right">
                  <span className={`badge badge-${s.risk_level}`}>{s.risk_level}</span>
                  <span className="recent-score">{s.risk_score?.toFixed(0)}</span>
                </div>
              </div>
            )) : (
              <div className="empty-list">No scans yet. <button className="btn-text" onClick={() => navigate('/scans/new')}>Start your first scan →</button></div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function EmptyChart({ label }) {
  return (
    <div className="empty-chart">
      <Activity size={24} style={{ color: 'var(--text-dim)' }} />
      <span>{label}</span>
    </div>
  )
}
