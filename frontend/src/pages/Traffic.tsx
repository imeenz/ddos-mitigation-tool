import { useEffect, useMemo, useState } from "react"
import {
  Activity,
  BarChart3,
  Network,
  Target,
} from "lucide-react"
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"

import { getDdosState } from "../services/ddos"
import type { DdosState } from "../services/ddos"

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B/s`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB/s`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB/s`
}

function Traffic() {
  const [state, setState] = useState<DdosState | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function loadState() {
    try {
      const data = await getDdosState()
      setState(data)
      setError(null)
    } catch {
      setError("Unable to reach the DDoS mitigation engine.")
    }
  }

  useEffect(() => {
    loadState()

    const interval = window.setInterval(loadState, 2000)

    return () => window.clearInterval(interval)
  }, [])

  const chartData = useMemo(() => {
    if (!state) return []

    return state.traffic_history.map((sample) => ({
      time: new Date(sample.timestamp * 1000).toLocaleTimeString([], {
        minute: "2-digit",
        second: "2-digit",
      }),
      pps: sample.packets_per_second,
      bps: sample.bytes_per_second,
    }))
  }, [state])

  if (!state) {
    return (
      <div className="table-message error">
        {error ?? "Loading traffic data..."}
      </div>
    )
  }

  const totalProtocolPackets =
    state.tcp_packets + state.udp_packets + state.icmp_packets

  const tcpPercent =
    totalProtocolPackets > 0
      ? (state.tcp_packets / totalProtocolPackets) * 100
      : 0

  const udpPercent =
    totalProtocolPackets > 0
      ? (state.udp_packets / totalProtocolPackets) * 100
      : 0

  const icmpPercent =
    totalProtocolPackets > 0
      ? (state.icmp_packets / totalProtocolPackets) * 100
      : 0

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Traffic Analysis</h1>
          <p>
            Live traffic volume, protocol activity, and traffic concentration.
          </p>
        </div>

        <div className="refresh-status">
          <div className="live-indicator">
            <span className="live-dot" />
            <span>LIVE</span>
          </div>

          <div>
            <strong>{state.capture_interface || "No interface"}</strong>
            <span>2-second refresh</span>
          </div>
        </div>
      </div>

      {error && <p className="table-message error">{error}</p>}

      <div className="severity-grid">
        <div className="severity-card low">
          <div className="severity-card-header">
            <span>PACKETS/SEC</span>
            <Activity size={18} />
          </div>
          <strong>{state.packets_per_second}</strong>
          <span className="severity-caption">Current inbound window</span>
        </div>

        <div className="severity-card low">
          <div className="severity-card-header">
            <span>BYTES/SEC</span>
            <BarChart3 size={18} />
          </div>
          <strong>{formatBytes(state.bytes_per_second)}</strong>
          <span className="severity-caption">Current inbound window</span>
        </div>

        <div className="severity-card medium">
          <div className="severity-card-header">
            <span>SOURCE CONCENTRATION</span>
            <Target size={18} />
          </div>
          <strong>{(state.source_concentration * 100).toFixed(1)}%</strong>
          <span className="severity-caption">Top source share</span>
        </div>

        <div className="severity-card medium">
          <div className="severity-card-header">
            <span>PORT CONCENTRATION</span>
            <Target size={18} />
          </div>
          <strong>
            {(state.destination_port_concentration * 100).toFixed(1)}%
          </strong>
          <span className="severity-caption">Top destination-port share</span>
        </div>
      </div>

      <div className="dashboard-analytics">
        <section className="dashboard-panel">
          <div className="panel-header">
            <div>
              <h2>Packets per Second</h2>
              <p>Rolling traffic history</p>
            </div>
            <Activity size={18} />
          </div>

          <div className="chart-container">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="pps"
                  name="Packets/sec"
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="dashboard-panel">
          <div className="panel-header">
            <div>
              <h2>Protocol Distribution</h2>
              <p>Current captured packet mix</p>
            </div>
            <Network size={18} />
          </div>

          <div className="status-badge">
            <span className="status-dot" />
            <div>
              <strong>TCP</strong>
              <span>
                {state.tcp_packets} packets · {tcpPercent.toFixed(1)}%
              </span>
            </div>
          </div>

          <div className="status-badge">
            <span className="status-dot" />
            <div>
              <strong>UDP</strong>
              <span>
                {state.udp_packets} packets · {udpPercent.toFixed(1)}%
              </span>
            </div>
          </div>

          <div className="status-badge">
            <span className="status-dot" />
            <div>
              <strong>ICMP</strong>
              <span>
                {state.icmp_packets} packets · {icmpPercent.toFixed(1)}%
              </span>
            </div>
          </div>
        </section>
      </div>

      <div className="dashboard-analytics">
        <section className="dashboard-panel">
          <div className="panel-header">
            <div>
              <h2>Top Source IPs</h2>
              <p>Highest inbound packet sources in the current window.</p>
            </div>
            <Target size={18} />
          </div>

          {state.top_source_ips.length === 0 ? (
            <div className="table-message">No source traffic yet.</div>
          ) : (
            state.top_source_ips.map((source, index) => (
              <div className="status-badge" key={source.ip}>
                <span className="status-dot" />
                <div>
                  <strong>
                    #{index + 1} · {source.ip}
                  </strong>
                  <span>{source.packets} packets</span>
                </div>
              </div>
            ))
          )}
        </section>

        <section className="dashboard-panel">
          <div className="panel-header">
            <div>
              <h2>Top Destination Ports</h2>
              <p>Most targeted destination ports in the current window.</p>
            </div>
            <Target size={18} />
          </div>

          {state.top_destination_ports.length === 0 ? (
            <div className="table-message">No destination-port traffic yet.</div>
          ) : (
            state.top_destination_ports.map((entry, index) => (
              <div className="status-badge" key={entry.port}>
                <span className="status-dot" />
                <div>
                  <strong>
                    #{index + 1} · Port {entry.port}
                  </strong>
                  <span>{entry.packets} packets</span>
                </div>
              </div>
            ))
          )}
        </section>
      </div>
    </>
  )
}

export default Traffic
