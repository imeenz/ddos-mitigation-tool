import { useEffect, useMemo, useState } from "react"
import {
  AlertTriangle,
  Search,
  ShieldAlert,
} from "lucide-react"

import { getDdosState } from "../services/ddos"
import type { DdosState } from "../services/ddos"

type Severity = "All" | "Low" | "Medium" | "High" | "Critical"

function Alerts() {
  const [state, setState] = useState<DdosState | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState("")
  const [severity, setSeverity] = useState<Severity>("All")

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

  const filteredAlerts = useMemo(() => {
    if (!state) return []

    const query = search.trim().toLowerCase()

    return state.recent_alerts.filter((alert) => {
      const matchesSeverity =
        severity === "All" || alert.severity === severity

      if (!matchesSeverity) return false

      if (!query) return true

      return [
        alert.severity,
        alert.alert_type,
        alert.source_ip ?? "",
        alert.message,
        String(alert.packets_per_second),
        String(alert.anomaly_score),
      ]
        .join(" ")
        .toLowerCase()
        .includes(query)
    })
  }, [state, search, severity])

  if (!state) {
    return (
      <div className="table-message error">
        {error ?? "Loading alert history..."}
      </div>
    )
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Alerts</h1>
          <p>
            Search and filter alerts retained by the DDoS detection engine.
          </p>
        </div>

        <div className="refresh-status">
          <div className="live-indicator">
            <span className="live-dot" />
            <span>LIVE</span>
          </div>

          <div>
            <strong>{state.total_alerts} retained alerts</strong>
            <span>2-second refresh</span>
          </div>
        </div>
      </div>

      {error && <p className="table-message error">{error}</p>}

      <div className="severity-grid">
        <div className="severity-card critical">
          <div className="severity-card-header">
            <span>CRITICAL</span>
            <ShieldAlert size={18} />
          </div>
          <strong>{state.critical_alerts}</strong>
          <span className="severity-caption">Retained alerts</span>
        </div>

        <div className="severity-card high">
          <div className="severity-card-header">
            <span>HIGH</span>
            <AlertTriangle size={18} />
          </div>
          <strong>{state.high_alerts}</strong>
          <span className="severity-caption">Retained alerts</span>
        </div>

        <div className="severity-card medium">
          <div className="severity-card-header">
            <span>MEDIUM</span>
          </div>
          <strong>{state.medium_alerts}</strong>
          <span className="severity-caption">Retained alerts</span>
        </div>

        <div className="severity-card low">
          <div className="severity-card-header">
            <span>LOW</span>
          </div>
          <strong>{state.low_alerts}</strong>
          <span className="severity-caption">Retained alerts</span>
        </div>
      </div>

      <section className="alerts-page-panel dashboard-panel">
        <div className="panel-header">
          <div>
            <h2>Alert History</h2>
            <p>
              Search by source, type, severity, message, PPS, or anomaly score.
            </p>
          </div>

          <AlertTriangle size={18} />
        </div>

        <div className="alert-controls">
          <div className="search-box">
            <Search size={17} />
            <input
              type="text"
              placeholder="Search alerts..."
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>

          <select
            value={severity}
            onChange={(event) =>
              setSeverity(event.target.value as Severity)
            }
            className="status-select"
          >
            <option value="All">All severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>

        {filteredAlerts.length === 0 ? (
          <div className="table-message">
            No alerts match the current filters.
          </div>
        ) : (
          <div className="alerts-table">
            <div className="alerts-table-header">
              <span>Severity</span>
              <span>Type</span>
              <span>Source IP</span>
              <span>PPS</span>
              <span>Score</span>
              <span>Message</span>
            </div>

            {filteredAlerts.map((alert, index) => (
              <div
                className="alerts-table-row"
                key={`${alert.source_ip}-${alert.alert_type}-${index}`}
              >
                <span>
                  <span
                    className={`severity-badge ${alert.severity.toLowerCase()}`}
                  >
                    {alert.severity}
                  </span>
                </span>

                <span>{alert.alert_type}</span>

                <span className="alert-source">
                  {alert.source_ip ?? "Unknown"}
                </span>

                <span>{alert.packets_per_second.toFixed(0)}</span>

                <span>{alert.anomaly_score.toFixed(2)}</span>

                <span>{alert.message}</span>
              </div>
            ))}
          </div>
        )}
      </section>
    </>
  )
}

export default Alerts
