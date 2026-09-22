import { useEffect, useMemo, useState } from "react"
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ShieldCheck,
  XCircle,
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

function Dashboard() {
  const [state, setState] = useState<DdosState | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  async function loadState() {
    try {
      const data = await getDdosState()
      setState(data)
      setLastUpdated(new Date())
      setError(null)
    } catch {
      setError("Unable to reach the DDoS mitigation engine.")
    } finally {
      setLoading(false)
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
    }))
  }, [state])

  const recentSecurityEvents = useMemo(() => {
    if (!state) return []

    return state.recent_alerts
      .filter(
        (alert) =>
          alert.severity === "Critical" ||
          alert.severity === "High" ||
          alert.alert_type === "PotentialDDoS" ||
          alert.alert_type === "MitigationTriggered",
      )
      .slice(0, 6)
  }, [state])

  if (loading && !state) {
    return <div className="table-message">Loading DDoS engine...</div>
  }

  if (!state) {
    return (
      <div className="table-message error">
        {error ?? "No engine state available."}
      </div>
    )
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>DDoS Mitigation Overview</h1>
          <p>Live network protection and detection status.</p>
        </div>

        <div className="refresh-status">
          <div className="live-indicator">
            <span className="live-dot" />
            <span>LIVE</span>
          </div>

          <div>
            <strong>
              {state.engine_running ? "Engine online" : "Engine stopped"}
            </strong>
            <span>
              {lastUpdated
                ? `Updated ${lastUpdated.toLocaleTimeString()}`
                : "Waiting for update"}
            </span>
          </div>
        </div>
      </div>

      {error && <p className="table-message error">{error}</p>}

      <div className="severity-grid">
        <div className="severity-card low">
          <div className="severity-card-header">
            <span>ENGINE</span>
            {state.engine_running ? (
              <CheckCircle2 size={18} />
            ) : (
              <XCircle size={18} />
            )}
          </div>

          <strong>{state.engine_running ? "RUNNING" : "STOPPED"}</strong>

          <span className="severity-caption">
            Interface: {state.capture_interface || "N/A"}
          </span>
        </div>

        <div className="severity-card low">
          <div className="severity-card-header">
            <span>XDP</span>
            {state.xdp_enabled ? (
              <ShieldCheck size={18} />
            ) : (
              <XCircle size={18} />
            )}
          </div>

          <strong>{state.xdp_enabled ? "ACTIVE" : "OFFLINE"}</strong>

          <span className="severity-caption">
            {state.xdp_blocks} blocks recorded
          </span>
        </div>

        <div className="severity-card medium">
          <div className="severity-card-header">
            <span>ANOMALY SCORE</span>
            <AlertTriangle size={18} />
          </div>

          <strong>{state.anomaly_score.toFixed(2)}</strong>

          <span className="severity-caption">
            Z-score {state.z_score.toFixed(2)}
          </span>
        </div>

        <div className="severity-card critical">
          <div className="severity-card-header">
            <span>BLOCKED IPS</span>
            <ShieldCheck size={18} />
          </div>

          <strong>{state.active_blocked_ips}</strong>

          <span className="severity-caption">
            Currently mitigated
          </span>
        </div>
      </div>

      <div className="dashboard-analytics">
        <section className="dashboard-panel">
          <div className="panel-header">
            <div>
              <h2>Live Traffic</h2>
              <p>Packets per second · rolling 60-second history</p>
            </div>

            <Activity size={18} />
          </div>

          <div className="chart-container">
            <ResponsiveContainer width="100%" height={280}>
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
              <h2>Protection Status</h2>
              <p>Current enforcement state</p>
            </div>

            <ShieldCheck size={18} />
          </div>

          <div className="status-badge">
            <span className="status-dot" />

            <div>
              <strong>
                XDP {state.xdp_enabled ? "Active" : "Inactive"}
              </strong>

              <span>{state.xdp_blocks} XDP blocks</span>
            </div>
          </div>

          <div className="status-badge">
            <span className="status-dot" />

            <div>
              <strong>
                Firewall{" "}
                {state.firewall_enabled ? "Enabled" : "Disabled"}
              </strong>

              <span>{state.firewall_blocks} firewall blocks</span>
            </div>
          </div>

          <div className="status-badge">
            <span className="status-dot" />

            <div>
              <strong>Protected IPs</strong>

              <span>
                {state.protected_ips.length > 0
                  ? state.protected_ips.join(", ")
                  : "None configured"}
              </span>
            </div>
          </div>
        </section>
      </div>

      <section className="dashboard-panel">
        <div className="panel-header">
          <div>
            <h2>Recent Security Events</h2>
            <p>
              Latest high-priority detection and mitigation activity.
            </p>
          </div>

          <AlertTriangle size={18} />
        </div>

        {recentSecurityEvents.length === 0 ? (
          <div className="table-message">
            No recent high-priority security events.
          </div>
        ) : (
          <div className="security-event-list">
            {recentSecurityEvents.map((alert, index) => (
              <div
                className={`security-event security-event-${alert.severity.toLowerCase()}`}
                key={`${alert.source_ip}-${alert.alert_type}-${index}`}
              >
                <div className="security-event-indicator" />

                <div className="security-event-main">
                  <div className="security-event-title">
                    <strong>{alert.severity}</strong>
                    <span>{alert.alert_type}</span>
                  </div>

                  <div className="security-event-meta">
                    <span>{alert.source_ip ?? "Unknown source"}</span>
                    <span>{alert.packets_per_second.toFixed(0)} PPS</span>
                    <span>Score {alert.anomaly_score.toFixed(2)}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <div className="dashboard-analytics">
        <section className="dashboard-panel">
          <div className="panel-header">
            <div>
              <h2>Traffic Snapshot</h2>
              <p>Current one-second traffic window</p>
            </div>

            <Activity size={18} />
          </div>

          <div className="severity-grid">
            <div className="severity-card low">
              <div className="severity-card-header">
                <span>PACKETS/SEC</span>
              </div>
              <strong>{state.packets_per_second}</strong>
            </div>

            <div className="severity-card low">
              <div className="severity-card-header">
                <span>BYTES/SEC</span>
              </div>
              <strong>{formatBytes(state.bytes_per_second)}</strong>
            </div>

            <div className="severity-card low">
              <div className="severity-card-header">
                <span>TCP</span>
              </div>
              <strong>{state.tcp_packets}</strong>
            </div>

            <div className="severity-card low">
              <div className="severity-card-header">
                <span>UDP</span>
              </div>
              <strong>{state.udp_packets}</strong>
            </div>
          </div>
        </section>

        <section className="dashboard-panel">
          <div className="panel-header">
            <div>
              <h2>Alert Summary</h2>
              <p>Current alert distribution</p>
            </div>

            <AlertTriangle size={18} />
          </div>

          <div className="severity-grid">
            <div className="severity-card critical">
              <div className="severity-card-header">
                <span>CRITICAL</span>
              </div>
              <strong>{state.critical_alerts}</strong>
            </div>

            <div className="severity-card high">
              <div className="severity-card-header">
                <span>HIGH</span>
              </div>
              <strong>{state.high_alerts}</strong>
            </div>

            <div className="severity-card medium">
              <div className="severity-card-header">
                <span>MEDIUM</span>
              </div>
              <strong>{state.medium_alerts}</strong>
            </div>

            <div className="severity-card low">
              <div className="severity-card-header">
                <span>LOW</span>
              </div>
              <strong>{state.low_alerts}</strong>
            </div>
          </div>

          <div className="status-badge">
            <span className="status-dot" />

            <div>
              <strong>{state.total_alerts} total alerts</strong>
              <span>Full history will be available in Alerts.</span>
            </div>
          </div>
        </section>
      </div>
    </>
  )
}

export default Dashboard
