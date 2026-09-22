import { useEffect, useState } from "react"
import {
  CheckCircle2,
  Clock3,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react"

import { getDdosState } from "../services/ddos"
import type { DdosState } from "../services/ddos"

function Mitigation() {
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

  if (!state) {
    return (
      <div className="table-message error">
        {error ?? "Loading mitigation state..."}
      </div>
    )
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Mitigation</h1>
          <p>
            Live enforcement status and currently mitigated source addresses.
          </p>
        </div>

        <div className="refresh-status">
          <div className="live-indicator">
            <span className="live-dot" />
            <span>LIVE</span>
          </div>

          <div>
            <strong>Mitigation engine</strong>
            <span>2-second refresh</span>
          </div>
        </div>
      </div>

      {error && <p className="table-message error">{error}</p>}

      <div className="severity-grid">
        <div className="severity-card low">
          <div className="severity-card-header">
            <span>XDP</span>
            {state.xdp_enabled ? (
              <CheckCircle2 size={18} />
            ) : (
              <XCircle size={18} />
            )}
          </div>

          <strong>{state.xdp_enabled ? "ACTIVE" : "OFFLINE"}</strong>

          <span className="severity-caption">
            {state.xdp_blocks} successful XDP blocks
          </span>
        </div>

        <div className="severity-card low">
          <div className="severity-card-header">
            <span>FIREWALL</span>
            {state.firewall_enabled ? (
              <CheckCircle2 size={18} />
            ) : (
              <XCircle size={18} />
            )}
          </div>

          <strong>
            {state.firewall_enabled ? "ENABLED" : "DISABLED"}
          </strong>

          <span className="severity-caption">
            {state.firewall_blocks} successful firewall blocks
          </span>
        </div>

        <div className="severity-card critical">
          <div className="severity-card-header">
            <span>ACTIVE BLOCKS</span>
            <ShieldAlert size={18} />
          </div>

          <strong>{state.active_blocked_ips}</strong>

          <span className="severity-caption">
            Currently mitigated sources
          </span>
        </div>

        <div className="severity-card medium">
          <div className="severity-card-header">
            <span>PROTECTED IPS</span>
            <ShieldCheck size={18} />
          </div>

          <strong>{state.protected_ips.length}</strong>

          <span className="severity-caption">
            Excluded from automatic mitigation
          </span>
        </div>
      </div>

      <div className="dashboard-analytics">
        <section className="dashboard-panel">
          <div className="panel-header">
            <div>
              <h2>Currently Blocked</h2>
              <p>
                Active source blocks managed by the mitigation engine.
              </p>
            </div>

            <ShieldAlert size={18} />
          </div>

          {state.blocked_ips.length === 0 ? (
            <div className="table-message">
              No IP addresses are currently blocked.
            </div>
          ) : (
            state.blocked_ips.map((entry) => (
              <div className="status-badge" key={entry.ip}>
                <span className="status-dot" />

                <div>
                  <strong>{entry.ip}</strong>

                  <span>
                    <Clock3
                      size={13}
                      style={{ verticalAlign: "middle", marginRight: 4 }}
                    />
                    {entry.remaining_seconds}s remaining
                  </span>
                </div>
              </div>
            ))
          )}
        </section>

        <section className="dashboard-panel">
          <div className="panel-header">
            <div>
              <h2>Protection Configuration</h2>
              <p>Runtime protection boundaries.</p>
            </div>

            <ShieldCheck size={18} />
          </div>

          <div className="status-badge">
            <span className="status-dot" />

            <div>
              <strong>Capture Interface</strong>
              <span>{state.capture_interface || "Not available"}</span>
            </div>
          </div>

          <div className="status-badge">
            <span className="status-dot" />

            <div>
              <strong>Protected Addresses</strong>
              <span>
                {state.protected_ips.length > 0
                  ? state.protected_ips.join(", ")
                  : "None configured"}
              </span>
            </div>
          </div>

          <div className="status-badge">
            <span
              className={
                state.xdp_enabled ? "status-dot" : "status-dot offline"
              }
            />

            <div>
              <strong>XDP Enforcement</strong>
              <span>
                {state.xdp_enabled ? "Kernel-level filtering active" : "Inactive"}
              </span>
            </div>
          </div>

          <div className="status-badge">
            <span
              className={
                state.firewall_enabled ? "status-dot" : "status-dot offline"
              }
            />

            <div>
              <strong>Firewall Enforcement</strong>
              <span>
                {state.firewall_enabled
                  ? "Firewall blocking enabled"
                  : "Firewall blocking disabled"}
              </span>
            </div>
          </div>
        </section>
      </div>

      <section className="dashboard-panel">
        <div className="panel-header">
          <div>
            <h2>Mitigation History</h2>
            <p>
              Recent mitigation actions recorded by the defense engine.
            </p>
          </div>

          <ShieldAlert size={18} />
        </div>

        {state.mitigation_history.length === 0 ? (
          <div className="table-message">
            No mitigation events have been recorded yet.
          </div>
        ) : (
          <div className="security-event-list">
            {state.mitigation_history.map((event, index) => (
              <div
                className="security-event"
                key={`${event.timestamp}-${event.source_ip}-${index}`}
              >
                <div className="security-event-indicator" />

                <div className="security-event-main">
                  <div className="security-event-title">
                    <strong>BLOCKED</strong>
                    <span>{event.source_ip}</span>
                  </div>

                  <div className="security-event-meta">
                    <span>
                      {new Date(event.timestamp * 1000).toLocaleString()}
                    </span>
                    <span>
                      Score {event.anomaly_score.toFixed(2)}
                    </span>
                    <span>
                      XDP {event.xdp_applied ? "Applied" : "Failed"}
                    </span>
                    <span>
                      Firewall{" "}
                      {event.firewall_applied ? "Applied" : "Failed"}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </>
  )
}

export default Mitigation
