import { useEffect, useState } from 'react'
import { Loader2, ChevronDown, ChevronUp } from 'lucide-react'
import { api } from '../utils/api'
import './CVELookup.css'

const SEV = { CRITICAL:'#ff4757', HIGH:'#ff6b35', MEDIUM:'#ffa502', LOW:'#2ed573', UNKNOWN:'#8b949e' }

function CVEItem({ cve }) {
  const color = SEV[cve.severity] || '#8b949e'
  return (
    <div className='cve-item'>
      <div className='cve-item-header'>
        <span className='cve-severity' style={{color}}>{cve.severity}</span>
        <span className='cve-id mono'>{cve.id}</span>
        <span className='cve-score' style={{color}}>{cve.score ? cve.score.toFixed(1) : '0.0'}</span>
        <a href={'https://nvd.nist.gov/vuln/detail/' + cve.id} target='_blank' rel='noreferrer' className='cve-link'>NVD</a>
      </div>
      <p className='cve-desc'>{cve.description}</p>
    </div>
  )
}

function PortSection({ portInfo }) {
  const cves = portInfo.cves || []
  if (!cves.length) return null
  return (
    <div className='cve-port-section'>
      <div className='cve-port-header'>
        <span className='mono port-num'>{portInfo.port}</span>
        <span className='port-service'>{portInfo.service || 'unknown'}</span>
        <span className='cve-count-badge'>{cves.length} CVEs</span>
      </div>
      {cves.map(cve => <CVEItem key={cve.id} cve={cve} />)}
    </div>
  )
}

function HostCard({ host }) {
  const [open, setOpen] = useState(false)
  const ip = host.ip || host.host
  const ports = (host.open_ports || []).filter(p => p.cves && p.cves.length > 0)
  if (!ports.length) return null
  const total = ports.reduce((a, p) => a + p.cves.length, 0)
  return (
    <div className='cve-host-card'>
      <div className='cve-host-header' onClick={() => setOpen(!open)}>
        <div className='cve-host-info'>
          <span className='mono'>{ip}</span>
          <span className='cve-badge'>{total} CVEs</span>
        </div>
        {open ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
      </div>
      {open && (
        <div className='cve-port-list'>
          {ports.map(p => <PortSection key={p.port} portInfo={p} />)}
        </div>
      )}
    </div>
  )
}

export default function CVELookup({ scanId }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!scanId) return
    api.getScanCVEs(scanId)
      .then(setData)
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [scanId])

  if (loading) return (
    <div className='cve-loading'>
      <Loader2 size={20} className='spin' style={{ color: 'var(--accent)' }} />
      <span>Fetching CVE data...</span>
    </div>
  )
  if (error) return <div className='cve-error'>Error: {error}</div>
  if (!data || !data.hosts || !data.hosts.length) return <div className='cve-empty'>No CVE data.</div>

  let total = 0, critical = 0
  data.hosts.forEach(h => (h.open_ports || []).forEach(p => {
    total += (p.cves || []).length
    critical += (p.cves || []).filter(c => c.severity === 'CRITICAL').length
  }))

  return (
    <div className='cve-wrap'>
      <div className='cve-summary'>
        <div className='cve-stat'><span className='cve-stat-val'>{total}</span><span className='cve-stat-label'>Total CVEs</span></div>
        <div className='cve-stat critical'><span className='cve-stat-val'>{critical}</span><span className='cve-stat-label'>Critical</span></div>
        <div className='cve-stat'><span className='cve-stat-val'>{data.hosts.length}</span><span className='cve-stat-label'>Hosts</span></div>
      </div>
      {data.hosts.map(h => <HostCard key={h.ip || h.host} host={h} />)}
    </div>
  )
}