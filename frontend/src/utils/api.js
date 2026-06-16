const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

async function request(path, options = {}) {
  const token = localStorage.getItem('token')
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  }
  const res = await fetch(BASE_URL + path, { ...options, headers })
  if (res.status === 401) {
    localStorage.clear()
    window.location.href = '/login'
    throw new Error('Unauthorized')
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Request failed')
  }
  if (res.status === 204) return null
  return res.json()
}

export const api = {
  login: (username, password) => {
    const form = new URLSearchParams({ username, password })
    return fetch(BASE_URL + '/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
    }).then(r => r.ok ? r.json() : r.json().then(e => Promise.reject(new Error(e.detail))))
  },
  register: (data) => request('/auth/register', { method: 'POST', body: JSON.stringify(data) }),
  me: () => request('/auth/me'),
  dashboardStats: () => request('/dashboard/stats'),
  createScan: (data) => request('/scans/', { method: 'POST', body: JSON.stringify(data) }),
  listScans: () => request('/scans/'),
  getScan: (id) => request('/scans/' + id),
  deleteScan: (id) => request('/scans/' + id, { method: 'DELETE' }),
  downloadPDF: async (id) => {
    const token = localStorage.getItem('token')
    const res = await fetch(BASE_URL + '/reports/' + id + '/pdf', {
      headers: { Authorization: 'Bearer ' + token },
    })
    if (!res.ok) throw new Error('PDF generation failed')
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'netscan_report_' + id.slice(0,8) + '.pdf'
    a.click()
    URL.revokeObjectURL(url)
  },
  listScheduledScans: () => request('/scheduled-scans/'),
  createScheduledScan: (data) => request('/scheduled-scans/', { method: 'POST', body: JSON.stringify(data) }),
  deleteScheduledScan: (id) => request('/scheduled-scans/' + id, { method: 'DELETE' }),
  toggleScheduledScan: (id) => request('/scheduled-scans/' + id + '/toggle', { method: 'PATCH' }),
  getScanCVEs: (scanId) => request('/cve/scan/' + scanId),
  getPortCVEs: (port, service) => request('/cve/port/' + port + '?service=' + service),
}
