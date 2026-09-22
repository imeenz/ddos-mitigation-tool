import { useEffect, useMemo, useState } from "react"
import {
  Activity,
  AlertTriangle,
  Radar,
  ShieldAlert,
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

function Detection() {
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

  const detectionHistory = useMemo(() => {
    if (!state) return []

    return [...state.recent_alerts]
      .reverse()
      .map((alert, index) => ({
        event: index + 1,
        score: Number(alert.anomaly_score.toFixed(3)),
        pps: alert.packets_per_second,
      }))
  }, [state])

  const suspiciousSources = useMemo(() => {
    if (!state) return []

    const sources = new Map<string, number>()

    for (const alert of state.recent_alerts) {
      if (!alert.source_ip) continue
      sources.set(
        alert.source_ip,
        (sources.get(alert.source_ip) ?? 0) + 1,
      )
    }

    return Array.from(sources.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
  }, [state])

  const alertTypeCounts = useMemo(() => {
    if (!state) return []

    const counts = new Map<string, number>()

    for (const alert of state.recent_alerts) {
      counts.set(
        alert.alert_type,
        (counts.get(alert.alert_type) ?? 0) + 1,
      )
    }

    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1])
  }, [state])

  if (!state) {
    return (
      <div className="table-message error">
        {error ?? "Loading detection data..."}
      </div>
    )
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Detection & Threat Analysis</h1>
          <p>
            Live anomaly scoring, detection events, and suspicious activity.
          </p>
        </div>

        <div className="refresh-status">
          <div className="live-indicator">
            <span className="live-dot" />
            <span>LIVE</span>
          </div>

          <div>
            <strong>Detection engine</strong>
            <span>2-second refresh</span>
          </div>
        </div>
      </div>

      {error && <p className="table-message error">{error}</p>}

      <div className="severity-grid">
        <div className="severity-card medium">
          <div className="severity-card-header">
            <span>ANOMALY SCORE</span>
            <Radar size={18} />
          </div>
          <strong>{state.anomaly_score.toFixed(2)}</strong>
          <span className="severity-caption">Current detection score</span>
        </div>

        <div className="severity-card high">
          <div className="severity-card-header">
            <span>Z-SCORE</span>
            <Activity size={18} />
          </div>
          <strong>{state.z_score.toFixed(2)}</strong>
          <span className="severity-caption">Current normalized deviation</span>
        </div>

        <div className="severity-card critical">
          <div className="severity-card-header">
            <span>CRITICAL ALERTS</span>
            <ShieldAlert size={18} />
          </div>
          <strong>{state.critical_alerts}</strong>
          <span className="severity-caption">Stored alert history</span>
        </div>

        <div className="severity-card high">
          <div className="severity-card-header">
            <span>HIGH ALERTS</span>
            <AlertTriangle size={18} />
          </div>
          <strong>{state.high_alerts}</strong>
          <span className="severity-caption">Stored alert history</span>
        </div>
      </div>

      <div className="dashboard-analytics">
        <section className="dashboard-panel">
          <div className="panel-header">
            <div>
              <h2>Detection History</h2>
              <p>Recent anomaly scores from the live alert stream.</p>
            </div>
            <Radar size={18} />
          </div>

          <div className="chart-container">
            {detectionHistory.length === 0 ? (
              <div className="table-message">
                No detection events yet.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={detectionHistory}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="event" />
                  <YAxis domain={[0, 1]} />
                  <Tooltip />
                  <Line
                    type="monotone"
                    dataKey="score"
                    name="Anomaly Score"
                    strokeWidth={2}
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </section>

        <section className="dashboard-panel">
          <div className="panel-header">
            <div>
              <h2>Detection Summary</h2>
              <p>Current alert severity distribution.</p>
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
        </section>
      </div>

      <div className="dashboard-analytics">
        <section className="dashboard-panel">
          <div className="panel-header">
            <div>
              <h2>Most Suspicious Sources</h2>
              <p>Sources appearing most often in recent alerts.</p>
            </div>
            <ShieldAlert size={18} />
          </div>

          {suspiciousSources.length === 0 ? (
            <div className="table-message">
              No suspicious sources detected.
            </div>
          ) : (
            suspiciousSources.map(([ip, count], index) => (
              <div className="status-badge" key={ip}>
                <span className="status-dot" />
                <div>
                  <strong>
                    #{index + 1} · {ip}
                  </strong>
                  <span>{count} recent alert events</span>
                </div>
              </div>
            ))
          )}
        </section>

        <section className="dashboard-panel">
          <div className="panel-header">
            <div>
              <h2>Alert Types</h2>
              <p>Most common detection event types.</p>
            </div>
            <Radar size={18} />
          </div>

          {alertTypeCounts.length === 0 ? (
            <div className="table-message">
              No detection events yet.
            </div>
          ) : (
            alertTypeCounts.map(([type, count]) => (
              <div className="status-badge" key={type}>
                <span className="status-dot" />
                <div>
                  <strong>{type}</strong>
                  <span>{count} recent events</span>
                </div>
              </div>
            ))
          )}
        </section>
      </div>

      <section className="dashboard-panel">
        <div className="panel-header">
          <div>
            <h2>Recent Detection Events</h2>
            <p>Latest alerts generated by the Rust detection engine.</p>
          </div>
          <Activity size={18} />
        </div>

        {state.recent_alerts.length === 0 ? (
          <div className="table-message">
            No detection events yet.
          </div>
        ) : (
          <div className="alerts-page-panel">
            {state.recent_alerts.map((alert, index) => (
              <div className="status-badge" key={`${alert.source_ip}-${index}`}>
                <span className="status-dot" />

                <div>
                  <strong>
                    {alert.severity} · {alert.alert_type}
                  </strong>

                  <span>
                    {alert.source_ip ?? "Unknown source"} ·{" "}
                    {alert.packets_per_second.toFixed(0)} PPS · score{" "}
                    {alert.anomaly_score.toFixed(2)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </>
  )
}

export default Detection
