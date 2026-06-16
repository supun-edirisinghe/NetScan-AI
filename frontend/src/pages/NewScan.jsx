import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Radar, Play, Info, Loader2 } from 'lucide-react'
import { api } from '../utils/api'
import './NewScan.css'

const PRESETS = [
  { label: 'Quick (Top 100)', range: '1-100,443,8080,8443,3306,5432,6379,27017,3389' },
  { label: 'Standard (1–1024)', range: '1-1024' },
  { label: 'Extended (1–10000)', range: '1-10000' },
  { label: 'Web Services', range: '80,443,8080,8443,8888,3000,4000,5000' },
  { label: 'Database Ports', range: '1433,1521,3306,5432,6379,27017,9200,5984' },
  { label: 'Full Scan', range: '1-65535' },
]

export default function NewScan() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [form, setForm] = useState({
    name: '',
    target: '',
    port_range: '1-1024',
    scan_type: 'tcp',
    notes: '',
  })

  const set = k => e => setForm(f => ({ ...f, [k]: e.target.value }))

  const applyPreset = (range) => setForm(f => ({ ...f, port_range: range }))

  const submit = async (e) => {
    e.preventDefault()
    setLoading(true); setError('')
    try {
      const scan = await api.createScan(form)
      navigate(`/scans/${scan.id}`)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">New Scan</h1>
          <p className="page-subtitle">Configure and launch a network security scan</p>
        </div>
      </div>

      <div className="new-scan-layout">
        <form onSubmit={submit} className="scan-form card">
          <div className="form-group">
            <label className="form-label">Scan Name *</label>
            <input
              className="form-input"
              placeholder="e.g. Production Network Q2 2025"
              value={form.name}
              onChange={set('name')}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">Target *</label>
            <input
              className="form-input mono"
              placeholder="192.168.1.1 | 192.168.1.0/24 | scanme.nmap.org"
              value={form.target}
              onChange={set('target')}
              required
            />
            <span className="form-hint">Single IP, CIDR range, or hostname</span>
          </div>

          <div className="form-group">
            <label className="form-label">Port Range</label>
            <input
              className="form-input mono"
              placeholder="1-1024"
              value={form.port_range}
              onChange={set('port_range')}
            />
            <div className="preset-row">
              {PRESETS.map(p => (
                <button
                  key={p.label}
                  type="button"
                  className={`preset-btn ${form.port_range === p.range ? 'active' : ''}`}
                  onClick={() => applyPreset(p.range)}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Scan Type</label>
            <select className="form-input" value={form.scan_type} onChange={set('scan_type')}>
              <option value="tcp">TCP Connect Scan</option>
              <option value="syn">SYN Scan (requires root)</option>
              <option value="udp">UDP Scan (slower)</option>
            </select>
          </div>

          <div className="form-group">
            <label className="form-label">Notes</label>
            <textarea
              className="form-input"
              placeholder="Optional notes about this scan..."
              value={form.notes}
              onChange={set('notes')}
            />
          </div>

          {error && <div className="scan-error">{error}</div>}

          <button type="submit" className="btn btn-primary launch-btn" disabled={loading}>
            {loading
              ? <><Loader2 size={16} className="spin" /> Launching...</>
              : <><Play size={16} /> Launch Scan</>
            }
          </button>
        </form>

        {/* Info panel */}
        <div className="scan-info">
          <div className="card info-card">
            <div className="info-header">
              <Info size={16} />
              <span>Scanner Info</span>
            </div>
            <ul className="info-list">
              <li><span className="info-dot accent" />Async TCP scanning via Python asyncio</li>
              <li><span className="info-dot accent" />AI risk analysis with Scikit-learn</li>
              <li><span className="info-dot accent" />Optional Nmap deep service detection</li>
              <li><span className="info-dot accent" />Exportable PDF reports</li>
              <li><span className="info-dot warning" />Only scan networks you own or have permission to test</li>
            </ul>
          </div>

          <div className="card info-card">
            <div className="info-header">
              <Radar size={16} />
              <span>High Risk Ports</span>
            </div>
            <div className="port-chips">
              {[
                { p: 23, n: 'Telnet', r: 'critical' },
                { p: 445, n: 'SMB', r: 'critical' },
                { p: 21, n: 'FTP', r: 'high' },
                { p: 3389, n: 'RDP', r: 'high' },
                { p: 6379, n: 'Redis', r: 'critical' },
                { p: 27017, n: 'MongoDB', r: 'critical' },
                { p: 9200, n: 'ES', r: 'high' },
                { p: 5900, n: 'VNC', r: 'high' },
              ].map(({ p, n, r }) => (
                <span key={p} className={`port-chip badge-${r}`}>{p}/{n}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
