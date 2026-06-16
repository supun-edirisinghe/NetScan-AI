import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Trash2, ExternalLink, Search, Loader2 } from 'lucide-react'
import { api } from '../utils/api'
import './Scans.css'

export default function Scans() {
  const navigate = useNavigate()
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')
  const [deleting, setDeleting] = useState(null)

  const load = () => {
    api.listScans()
      .then(setScans)
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const deleteScan = async (id, e) => {
    e.stopPropagation()
    if (!confirm('Delete this scan?')) return
    setDeleting(id)
    try {
      await api.deleteScan(id)
      setScans(s => s.filter(x => x.id !== id))
    } catch (err) {
      alert(err.message)
    } finally {
      setDeleting(null)
    }
  }

  const filtered = scans.filter(s =>
    s.name.toLowerCase().includes(filter.toLowerCase()) ||
    s.target.toLowerCase().includes(filter.toLowerCase())
  )

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Scan History</h1>
          <p className="page-subtitle">{scans.length} total scans</p>
        </div>
        <button className="btn btn-primary" onClick={() => navigate('/scans/new')}>
          <Plus size={16} /> New Scan
        </button>
      </div>

      <div className="scans-toolbar">
        <div className="search-wrap">
          <Search size={14} className="search-icon" />
          <input
            className="form-input search-input"
            placeholder="Filter scans..."
            value={filter}
            onChange={e => setFilter(e.target.value)}
          />
        </div>
      </div>

      {loading ? (
        <div className="loading-center" style={{ height: 300 }}>
          <Loader2 size={28} className="spin" style={{ color: 'var(--accent)' }} />
        </div>
      ) : filtered.length === 0 ? (
        <div className="empty-scans">
          <p>No scans found.</p>
          <button className="btn btn-primary" onClick={() => navigate('/scans/new')}>
            <Plus size={16} /> Launch your first scan
          </button>
        </div>
      ) : (
        <div className="scans-table card">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Target</th>
                <th>Status</th>
                <th>Hosts</th>
                <th>Open Ports</th>
                <th>Risk</th>
                <th>Score</th>
                <th>Date</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(s => (
                <tr key={s.id} onClick={() => navigate(`/scans/${s.id}`)}>
                  <td><span className="scan-name">{s.name}</span></td>
                  <td><span className="mono text-muted">{s.target}</span></td>
                  <td><span className={`badge badge-${s.status}`}>{s.status}</span></td>
                  <td className="mono">{s.hosts_up}/{s.total_hosts}</td>
                  <td className="mono">{s.total_open_ports}</td>
                  <td><span className={`badge badge-${s.risk_level}`}>{s.risk_level}</span></td>
                  <td>
                    <span className="risk-score" style={{ color: riskColor(s.risk_score) }}>
                      {s.risk_score?.toFixed(0)}
                    </span>
                  </td>
                  <td className="text-muted date-cell">{s.created_at?.slice(0, 10)}</td>
                  <td>
                    <div className="row-actions" onClick={e => e.stopPropagation()}>
                      <button className="icon-btn" onClick={() => navigate(`/scans/${s.id}`)} title="View">
                        <ExternalLink size={14} />
                      </button>
                      <button
                        className="icon-btn danger"
                        onClick={(e) => deleteScan(s.id, e)}
                        disabled={deleting === s.id}
                        title="Delete"
                      >
                        {deleting === s.id ? <Loader2 size={14} className="spin" /> : <Trash2 size={14} />}
                      </button>
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
