import { useEffect, useState, useRef } from 'react'
import { Loader2, CheckCircle } from 'lucide-react'
import './ScanProgress.css'

export default function ScanProgress({ scanId, status }) {
  const [progress, setProgress] = useState(0)
  const [message, setMessage] = useState('Connecting...')
  const [currentHost, setCurrentHost] = useState('')
  const [done, setDone] = useState(false)
  const wsRef = useRef(null)

  useEffect(() => {
    if (status !== 'running' && status !== 'pending') return

    const WS_URL = 'ws://localhost:8000/ws/scan/' + scanId
    wsRef.current = new WebSocket(WS_URL)

    wsRef.current.onopen = () => {
      setMessage('Scan in progress...')
    }

    wsRef.current.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        if (data.type === 'progress') {
          setProgress(data.percent || 0)
          setCurrentHost(data.current_host || '')
          setMessage('Scanning hosts... ' + data.completed + '/' + data.total)
        } else if (data.type === 'completed') {
          setProgress(100)
          setMessage('Scan completed!')
          setDone(true)
        } else if (data.type === 'started') {
          setProgress(0)
          setMessage('Scan started...')
        }
      } catch (err) {
        console.error('WS parse error:', err)
      }
    }

    wsRef.current.onerror = () => {
      setMessage('Scanning in progress...')
    }

    return () => {
      if (wsRef.current) wsRef.current.close()
    }
  }, [scanId, status])

  if (status === 'completed' || status === 'failed') return null

  return (
    <div className="progress-banner">
      <div className="progress-header">
        {done ? (
          <CheckCircle size={16} style={{ color: 'var(--accent)' }} />
        ) : (
          <Loader2 size={16} className="spin" style={{ color: 'var(--info)' }} />
        )}
        <span className="progress-message">{message}</span>
        {currentHost && (
          <span className="progress-host mono">arrow {currentHost}</span>
        )}
        <span className="progress-pct">{progress}%</span>
      </div>
      <div className="progress-bar-track">
        <div
          className="progress-bar-fill"
          style={{ width: progress + '%' }}
        />
      </div>
    </div>
  )
}
