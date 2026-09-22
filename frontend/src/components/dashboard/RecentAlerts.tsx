import type { Alert } from "../../types/alert"
import { Link } from "react-router-dom"

interface RecentAlertsProps {
  alerts: Alert[]
}

function RecentAlerts({ alerts }: RecentAlertsProps) {
  const recentAlerts = alerts.slice(0, 5)

  return (
    <section className="dashboard-panel recent-alerts-panel">
      <div className="panel-header">
        <div>
          <h2>Recent Alerts</h2>
          <p>Latest security alerts requiring attention</p>
        </div>

        <Link
        to="/alerts"
        className="view-all-button"
>
        View all
        </Link>
      </div>

      <div className="alerts-table-wrapper">
        <table className="alerts-table">
          <thead>
            <tr>
              <th>Alert</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Time</th>
            </tr>
          </thead>

          <tbody>
            {recentAlerts.map((alert) => (
              <tr key={alert.id}>
                <td className="alert-title">
                  {alert.title}
                </td>

                <td>
                  <span
                    className={`severity-badge ${alert.severity}`}
                  >
                    {alert.severity}
                  </span>
                </td>

                <td>
                  <span
                    className={`status-badge ${alert.status}`}
                  >
                    {alert.status}
                  </span>
                </td>

                <td className="alert-time">
                  {new Date(
                    alert.created_at,
                  ).toLocaleString()}
                </td>
              </tr>
            ))}

            {recentAlerts.length === 0 && (
              <tr>
                <td
                  colSpan={4}
                  className="table-message"
                >
                  No recent alerts.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}

export default RecentAlerts