import { useEffect, useState } from 'react'
import { Clock, Plus, Trash2, ToggleLeft, ToggleRight, Loader2, Calendar } from 'lucide-react'
import { api } from '../utils/api'
import './ScheduledScans.css'

const DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']
const HOURS = Array.from({ length: 24 }, (_, i) => i)

export default function ScheduledScans() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [form, setForm] = useState({
    name: '',
    target: '',
    port_range: '1-1024',
    scan_type: 'tcp',
    schedule_type: 'daily',
    schedule_hour: 2,
    schedule_minute: 0,
    schedule_day: 'mon',
  })

  const setField = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }))

  const load = async () => {
    try {
      const data = await api.listScheduledScans()
      setScans(data)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const submit = async (e) => {
    e.preventDefault()
    setSaving(true)
    setError('')
    try {
      await api.createScheduledScan({
        ...form,
        schedule_hour: parseInt(form.schedule_hour),
        schedule_minute: parseInt(form.schedule_minute),
      })
      setShowForm(false)
      setForm({
        name: '', target: '', port_range: '1-1024',
        scan_type: 'tcp', schedule_type: 'daily',
        schedule_hour: 2, schedule_minute: 0, schedule_day: 'mon',
      })
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  const toggle = async (id) => {
    try {
      await api.toggleScheduledScan(id)
      await load()
    } catch (err) {
      alert(err.message)
    }
  }

  const remove = async (id) => {
    if (!confirm('Delete this scheduled scan?')) return
    try {
      await api.deleteScheduledScan(id)
      setScans((s) => s.filter((x) => x.id !== id))
    } catch (err) {
      alert(err.message)
    }
  }

  const scheduleLabel = (s) => {
    const hh = String(s.schedule_hour).padStart(2, '0')
    const mm = String(s.schedule_minute).padStart(2, '0')
    const time = `${hh}:${mm}`
    if (s.schedule_type === 'daily') return `Daily at ${time}`
    if (s.schedule_type === 'weekly') return `Weekly on ${s.schedule_day.toUpperCase()} at ${time}`
    if (s.schedule_type === 'monthly') return `Monthly on 1st at ${time}`
    return s.schedule_type
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Scheduled Scans</h1>
          <p className="page-subtitle">Automatically run scans on a schedule</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          <Plus size={16} />
          New Schedule
        </button>
      </div>

      {showForm && (
        <div className="card schedule-form-card">
          <h3 className="chart-title">Create New Scheduled Scan</h3>
          <form onSubmit={submit}>
            <div className="grid-2">
              <div className="form-group">
                <label className="form-label">Schedule Name</label>
                <input
                  className="form-input"
                  placeholder="e.g. Daily Production Scan"
                  value={form.name}
                  onChange={setField('name')}
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label">Target</label>
                <input
                  className="form-input mono"
                  placeholder="192.168.1.0/24"
                  value={form.target}
                  onChange={setField('target')}
                  required
                />
              </div>
            </div>

            <div className="grid-2">
              <div className="form-group">
                <label className="form-label">Port Range</label>
                <input
                  className="form-input mono"
                  placeholder="1-1024"
                  value={form.port_range}
                  onChange={setField('port_range')}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Schedule Type</label>
                <select
                  className="form-input"
                  value={form.schedule_type}
                  onChange={setField('schedule_type')}
                >
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>
            </div>

            <div className="grid-2">
              <div className="form-group">
                <label className="form-label">Hour (0-23)</label>
                <select
                  className="form-input"
                  value={form.schedule_hour}
                  onChange={setField('schedule_hour')}
                >
                  {HOURS.map((h) => (
                    <option key={h} value={h}>
                      {String(h).padStart(2, '0')}:00
                    </option>
                  ))}
                </select>
              </div>
              {form.schedule_type === 'weekly' && (
                <div className="form-group">
                  <label className="form-label">Day of Week</label>
                  <select
                    className="form-input"
                    value={form.schedule_day}
                    onChange={setField('schedule_day')}
                  >
                    {DAYS.map((d) => (
                      <option key={d} value={d}>
                        {d.toUpperCase()}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            {error && <div className="scan-error">{error}</div>}

            <div className="form-actions">
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => setShowForm(false)}
              >
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving
                  ? <Loader2 size={14} className="spin" />
                  : <Clock size={14} />}
                Create Schedule
              </button>
            </div>
          </form>
        </div>
      )}

      {loading ? (
        <div className="loading-center" style={{ height: 300 }}>
          <Loader2 size={28} className="spin" style={{ color: 'var(--accent)' }} />
        </div>
      ) : scans.length === 0 ? (
        <div className="empty-scans">
          <Calendar size={40} style={{ color: 'var(--text-dim)' }} />
          <p>No scheduled scans yet.</p>
          <button className="btn btn-primary" onClick={() => setShowForm(true)}>
            <Plus size={16} />
            Create your first schedule
          </button>
        </div>
      ) : (
        <div className="scheduled-list">
          {scans.map((s) => (
            <div key={s.id} className={`scheduled-card card ${!s.is_active ? 'inactive' : ''}`}>
              <div className="scheduled-header">
                <div className="scheduled-info">
                  <div className="scheduled-name">{s.name}</div>
                  <div className="scheduled-target mono">{s.target}</div>
                </div>
                <div className="scheduled-actions">
                  <button
                    className={`toggle-btn ${s.is_active ? 'active' : ''}`}
                    onClick={() => toggle(s.id)}
                    title={s.is_active ? 'Disable' : 'Enable'}
                  >
                    {s.is_active
                      ? <ToggleRight size={28} />
                      : <ToggleLeft size={28} />}
                  </button>
                  <button className="icon-btn danger" onClick={() => remove(s.id)}>
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
              <div className="scheduled-meta">
                <div className="meta-item">
                  <Clock size={13} />
                  <span>{scheduleLabel(s)}</span>
                </div>
                <div className="meta-item">
                  <span className={`badge ${s.is_active ? 'badge-completed' : 'badge-pending'}`}>
                    {s.is_active ? 'Active' : 'Paused'}
                  </span>
                </div>
                <div className="meta-item">
                  <span>Runs: <strong>{s.total_runs}</strong></span>
                </div>
                {s.last_run && (
                  <div className="meta-item">
                    <span>Last run: <strong>{s.last_run.slice(0, 16).replace('T', ' ')}</strong></span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}