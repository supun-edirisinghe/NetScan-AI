import { useEffect, useState, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell,
} from 'recharts'
import {
  ArrowLeft, Download, RefreshCw, Server, Loader2,
} from 'lucide-react'
import { api } from '../utils/api'
import './ScanDetail.css'
import NetworkMap from '../components/NetworkMap'
import CVELookup from '../components/CVELookup'
import ScanProgress from '../components/ScanProgress'

const CUSTOM_TOOLTIP = {
  background: '#111820', border: '1px solid #1e2d3d',
  borderRadius: 8, color: '#e6edf3', fontSize: 12, padding: '8px 12px',
}

export default function ScanDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)
  const [downloading, setDownloading] = useState(false)
  const pollRef = useRef(null)

  const load = async () => {
    try {
      const data = await api.getScan(id)
      setScan(data)
      if (data.status === 'running' || data.status === 'pending') {
        pollRef.current = setTimeout(load, 3000)
      }
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load(); return () => clearTimeout(pollRef.current) }, [id])

  const downloadPDF = async () => {
    setDownloading(true)
    try { await api.downloadPDF(id) }
    catch (err) { alert(err.message) }
    finally { setDownloading(false) }
  }

  if (loading) return (
    <div className="page loading-center">
      <Loader2 size={32} className="spin" style={{ color: 'var(--accent)' }} />
    </div>
  )

  if (!scan) return <div className="page"><p>Scan not found.</p></div>

  const isRunning = scan.status === 'running' || scan.status === 'pending'
  const portData = Object.entries(scan.port_distribution || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)
    .map(([port, count]) => ({ port, count }))

  const hosts = scan.scan_results?.hosts || []

  return (
    <div className="page">
      <div className="page-header">
        <div className="header-left">
          <button className="btn btn-ghost btn-sm" onClick={() => navigate('/scans')}>
            <ArrowLeft size={14} /> Back
          </button>
          <div>
            <h1 className="page-title">{scan.name}</h1>
            <div className="scan-meta">
              <span className="mono text-muted">{scan.target}</span>
              <span className="meta-sep">|</span>
              <span className={`badge badge-${scan.status}`}>{scan.status}</span>
              <span className="meta-sep">|</span>
              <span className="text-muted">{scan.created_at?.slice(0, 16).replace('T', ' ')}</span>
              {scan.duration_seconds && (
                <><span className="meta-sep">|</span>
                <span className="text-muted">{scan.duration_seconds.toFixed(1)}s</span></>
              )}
            </div>
          </div>
        </div>
        <div className="header-actions">
          {isRunning && (
            <button className="btn btn-ghost" onClick={load}>
              <RefreshCw size={14} /> Refresh
            </button>
          )}
          {scan.status === 'completed' && (
            <button className="btn btn-primary" onClick={downloadPDF} disabled={downloading}>
              {downloading ? <Loader2 size={14} className="spin" /> : <Download size={14} />}
              Export PDF
            </button>
          )}
        </div>
      </div>

      <ScanProgress scanId={id} status={scan.status} />

      {isRunning && (
        <div className="scan-running-banner">
          <Loader2 size={16} className="spin" />
          <span>Scanning in progress... Results will appear automatically.</span>
        </div>
      )}

      <div className="grid-4" style={{ marginBottom: 24 }}>
        <div className="stat-mini"><span className="stat-mini-val">{scan.total_hosts}</span><span className="stat-mini-label">Total Hosts</span></div>
        <div className="stat-mini"><span className="stat-mini-val">{scan.hosts_up}</span><span className="stat-mini-label">Hosts Online</span></div>
        <div className="stat-mini"><span className="stat-mini-val">{scan.total_open_ports}</span><span className="stat-mini-label">Open Ports</span></div>
        <div className="stat-mini danger"><span className="stat-mini-val">{scan.high_risk_hosts}</span><span className="stat-mini-label">High Risk Hosts</span></div>
      </div>

      <div className="detail-grid" style={{ marginBottom: 24 }}>
        <div className="card risk-gauge-card">
          <h3 className="chart-title">AI Risk Assessment</h3>
          <div className="risk-gauge">
            <div className="gauge-circle">
              <svg viewBox="0 0 120 120" className="gauge-svg">
                <circle cx="60" cy="60" r="50" fill="none" stroke="#1e2d3d" strokeWidth="10" />
                <circle
                  cx="60" cy="60" r="50" fill="none"
                  stroke={riskColor(scan.risk_score)}
                  strokeWidth="10"
                  strokeDasharray={`${(scan.risk_score / 100) * 314} 314`}
                  strokeLinecap="round"
                  transform="rotate(-90 60 60)"
                />
              </svg>
              <div className="gauge-text">
                <span className="gauge-score" style={{ color: riskColor(scan.risk_score) }}>
                  {scan.risk_score?.toFixed(0)}
                </span>
                <span className="gauge-label">/ 100</span>
              </div>
            </div>
            <div className={`risk-badge-large badge-${scan.risk_level}`}>
              {scan.risk_level?.toUpperCase()}
            </div>
          </div>
        </div>

        <div className="card" style={{ flex: 2 }}>
          <h3 className="chart-title">Open Port Distribution</h3>
          {portData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={portData} margin={{ top: 5, right: 5, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2d3d" />
                <XAxis dataKey="port" tick={{ fill: '#8b949e', fontSize: 10 }} />
                <YAxis tick={{ fill: '#8b949e', fontSize: 11 }} />
                <Tooltip contentStyle={CUSTOM_TOOLTIP} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {portData.map((entry, i) => (
                    <Cell key={i} fill={portBarColor(entry.port)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-dim)', fontSize: 13 }}>
              {isRunning ? 'Collecting port data...' : 'No open ports found'}
            </div>
          )}
        </div>
      </div>

      {scan.ai_recommendations?.length > 0 && (
        <div className="card" style={{ marginBottom: 24 }}>
          <h3 className="chart-title">
            AI Security Recommendations
            <span className="rec-count">{scan.ai_recommendations.length}</span>
          </h3>
          <div className="recommendations">
            {scan.ai_recommendations.map(rec => (
              <div key={rec.id} className={`rec-item severity-${rec.severity}`}>
                <div className="rec-header">
                  <span className={`badge badge-${rec.severity}`}>{rec.severity}</span>
                  <span className="rec-title">{rec.title}</span>
                  {rec.affected_port && <span className="mono port-tag">:{rec.affected_port}</span>}
                </div>
                <p className="rec-desc">{rec.description}</p>
                <div className="rec-action">
                  <span>{rec.recommendation}</span>
                </div>
                {rec.cve_refs?.length > 0 && (
                  <div className="cve-refs">
                    {rec.cve_refs.map(c => <span key={c} className="cve-badge">{c}</span>)}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {hosts.length > 0 && scan.status === 'completed' && (
        <div className="card" style={{ marginBottom: 24 }}>
          <h3 className="chart-title">Network Topology Map</h3>
          <NetworkMap hosts={hosts} target={scan.target} />
        </div>
      )}

      {scan.status === 'completed' && (
        <div className="card" style={{ marginBottom: 24 }}>
          <h3 className="chart-title">CVE Vulnerability Lookup</h3>
          <CVELookup scanId={id} />
        </div>
      )}

      {hosts.length > 0 && (
        <div className="card">
          <h3 className="chart-title">Host Results ({hosts.length})</h3>
          <div className="hosts-list">
            {hosts.map((host, i) => (
              <HostRow key={i} host={host} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function HostRow({ host }) {
  const [expanded, setExpanded] = useState(false)
  const openPorts = host.open_ports || []

  return (
    <div className={`host-row ${expanded ? 'expanded' : ''}`}>
      <div className="host-summary" onClick={() => setExpanded(!expanded)}>
        <div className="host-ip-wrap">
          <Server size={14} style={{ color: 'var(--accent)' }} />
          <span className="mono">{host.ip || host.host}</span>
          {host.hostname && host.hostname !== host.ip && (
            <span className="hostname">({host.hostname})</span>
          )}
        </div>
        <div className="host-stats">
          <span className="host-ports-count">{openPorts.length} open ports</span>
          {host.risk_level && <span className={`badge badge-${host.risk_level}`}>{host.risk_level}</span>}
          {host.risk_score !== undefined && (
            <span style={{ color: riskColor(host.risk_score), fontFamily: 'var(--font-mono)', fontSize: 13 }}>
              {host.risk_score?.toFixed(0)}
            </span>
          )}
          <span className="expand-icon">{expanded ? 'v' : '>'}</span>
        </div>
      </div>

      {expanded && openPorts.length > 0 && (
        <div className="host-ports">
          <table className="port-table">
            <thead>
              <tr><th>Port</th><th>Service</th><th>Risk</th></tr>
            </thead>
            <tbody>
              {openPorts.map(p => (
                <tr key={p.port}>
                  <td className="mono">{p.port}/tcp</td>
                  <td>{p.service || 'unknown'}</td>
                  <td>
                    <div className="risk-bar-wrap">
                      <div
                        className="risk-bar"
                        style={{
                          width: `${(p.risk_weight || 0.2) * 100}%`,
                          background: riskWeightColor(p.risk_weight || 0.2)
                        }}
                      />
                      <span>{((p.risk_weight || 0.2) * 100).toFixed(0)}%</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function riskColor(score) {
  if (score >= 70) return 'var(--danger)'
  if (score >= 50) return '#ff6b35'
  if (score >= 25) return 'var(--warning)'
  return 'var(--success)'
}

function riskWeightColor(w) {
  if (w >= 0.7) return 'var(--danger)'
  if (w >= 0.4) return 'var(--warning)'
  return 'var(--success)'
}

const HIGH_RISK_PORTS = new Set([23, 445, 4444, 6379, 27017, 21, 3389])
function portBarColor(port) {
  const n = parseInt(port)
  if (HIGH_RISK_PORTS.has(n)) return '#ff4757'
  if ([135, 139, 5900, 1433, 9200].includes(n)) return '#ffa502'
  return '#00d4aa'
}
