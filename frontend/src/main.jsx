import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import App from './App'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'
import NewScan from './pages/NewScan'
import ScheduledScans from './pages/ScheduledScans'
import './index.css'

const PrivateRoute = ({ children }) => {
  const token = localStorage.getItem('token')
  return token ? children : <Navigate to="/login" />
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<PrivateRoute><App /></PrivateRoute>}>
          <Route index element={<Navigate to="/dashboard" />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="scans" element={<Scans />} />
          <Route path="scans/:id" element={<ScanDetail />} />
          <Route path="scans/new" element={<NewScan />} />
          <Route path="scheduled" element={<ScheduledScans />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
)