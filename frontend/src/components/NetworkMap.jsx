import { useEffect, useRef } from 'react'
import * as d3 from 'd3'
import './NetworkMap.css'

const RISK_COLORS = {
  critical: '#ff4757',
  high: '#ff6b35',
  medium: '#ffa502',
  low: '#2ed573',
  unknown: '#8b949e',
}

export default function NetworkMap({ hosts, target }) {
  const svgRef = useRef(null)

  useEffect(() => {
    if (!hosts || hosts.length === 0) return

    const container = svgRef.current.parentElement
    const width = container.clientWidth || 800
    const height = 450

    // Clear previous render
    d3.select(svgRef.current).selectAll('*').remove()

    const svg = d3.select(svgRef.current)
      .attr('width', width)
      .attr('height', height)

    // Zoom support
    const g = svg.append('g')
    svg.call(
      d3.zoom()
        .scaleExtent([0.3, 3])
        .on('zoom', (event) => g.attr('transform', event.transform))
    )

    // Build nodes and links
    const centerNode = {
      id: 'router',
      label: target || 'Network',
      type: 'router',
      risk_level: 'low',
      open_ports: [],
    }

    const hostNodes = hosts
      .filter(h => h.status !== 'error' && h.open_ports?.length > 0)
      .map(h => ({
        id: h.ip || h.host,
        label: h.ip || h.host,
        type: 'host',
        risk_level: h.risk_level || 'low',
        risk_score: h.risk_score || 0,
        open_ports: h.open_ports || [],
      }))

    const nodes = [centerNode, ...hostNodes]
    const links = hostNodes.map(h => ({
      source: 'router',
      target: h.id,
    }))

    // Force simulation
    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(120))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(50))

    // Draw links
    const link = g.append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', '#1e2d3d')
      .attr('stroke-width', 2)
      .attr('stroke-dasharray', '4,4')

    // Draw nodes
    const node = g.append('g')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .attr('cursor', 'pointer')
      .call(
        d3.drag()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart()
            d.fx = d.x; d.fy = d.y
          })
          .on('drag', (event, d) => {
            d.fx = event.x; d.fy = event.y
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0)
            d.fx = null; d.fy = null
          })
      )

    // Node circles
    node.append('circle')
      .attr('r', d => d.type === 'router' ? 28 : 22)
      .attr('fill', d => d.type === 'router'
        ? '#00d4aa22'
        : `${RISK_COLORS[d.risk_level] || '#8b949e'}22`
      )
      .attr('stroke', d => d.type === 'router'
        ? '#00d4aa'
        : RISK_COLORS[d.risk_level] || '#8b949e'
      )
      .attr('stroke-width', 2)

    // Node icons (text)
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'middle')
      .attr('font-size', d => d.type === 'router' ? '18px' : '14px')
      .text(d => d.type === 'router' ? '🌐' : '💻')

    // Node labels
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('y', d => d.type === 'router' ? 40 : 34)
      .attr('fill', '#e6edf3')
      .attr('font-size', '11px')
      .attr('font-family', 'monospace')
      .text(d => d.label)

    // Port count badge
    node.filter(d => d.type === 'host' && d.open_ports.length > 0)
      .append('text')
      .attr('x', 16)
      .attr('y', -16)
      .attr('text-anchor', 'middle')
      .attr('fill', d => RISK_COLORS[d.risk_level] || '#8b949e')
      .attr('font-size', '10px')
      .attr('font-weight', 'bold')
      .attr('font-family', 'monospace')
      .text(d => `${d.open_ports.length}p`)

    // Tooltip
    const tooltip = d3.select('body').append('div')
      .attr('class', 'topology-tooltip')
      .style('opacity', 0)

    node.on('mouseover', (event, d) => {
      if (d.type === 'router') return
      tooltip.style('opacity', 1)
        .html(`
          <div class="tt-title">${d.label}</div>
          <div class="tt-row">Risk: <span style="color:${RISK_COLORS[d.risk_level]}">${(d.risk_level || 'low').toUpperCase()}</span></div>
          <div class="tt-row">Score: <span>${d.risk_score?.toFixed(0) || 0}/100</span></div>
          <div class="tt-row">Open Ports: <span>${d.open_ports.length}</span></div>
          ${d.open_ports.slice(0, 5).map(p =>
            `<div class="tt-port">${p.port} — ${p.service || 'unknown'}</div>`
          ).join('')}
          ${d.open_ports.length > 5 ? `<div class="tt-port">+${d.open_ports.length - 5} more...</div>` : ''}
        `)
        .style('left', `${event.pageX + 12}px`)
        .style('top', `${event.pageY - 28}px`)
    })
    .on('mousemove', (event) => {
      tooltip
        .style('left', `${event.pageX + 12}px`)
        .style('top', `${event.pageY - 28}px`)
    })
    .on('mouseout', () => {
      tooltip.style('opacity', 0)
    })

    // Simulation tick
    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y)

      node.attr('transform', d => `translate(${d.x},${d.y})`)
    })

    return () => {
      simulation.stop()
      d3.select('.topology-tooltip').remove()
    }
  }, [hosts, target])

  const onlineHosts = hosts?.filter(h => h.open_ports?.length > 0) || []

  if (onlineHosts.length === 0) {
    return (
      <div className="map-empty">
        <span>🗺️</span>
        <p>No hosts with open ports to display</p>
      </div>
    )
  }

  return (
    <div className="network-map-wrap">
      <div className="map-legend">
        {Object.entries(RISK_COLORS).map(([level, color]) => (
          <div key={level} className="legend-item">
            <span className="legend-dot" style={{ background: color }} />
            <span>{level}</span>
          </div>
        ))}
        <span className="map-hint">Drag nodes • Scroll to zoom • Hover for details</span>
      </div>
      <svg ref={svgRef} className="topology-svg" />
    </div>
  )
}