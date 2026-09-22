import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts"

import type { Alert } from "../../types/alert"

interface SeverityDistributionProps {
  alerts: Alert[]
}

function SeverityDistribution({
  alerts,
}: SeverityDistributionProps) {
  const data = [
    {
      name: "Critical",
      value: alerts.filter(
        (alert) => alert.severity === "critical",
      ).length,
      color: "#ef4444",
    },
    {
      name: "High",
      value: alerts.filter(
        (alert) => alert.severity === "high",
      ).length,
      color: "#f97316",
    },
    {
      name: "Medium",
      value: alerts.filter(
        (alert) => alert.severity === "medium",
      ).length,
      color: "#eab308",
    },
    {
      name: "Low",
      value: alerts.filter(
        (alert) => alert.severity === "low",
      ).length,
      color: "#22c55e",
    },
  ]

  const total = data.reduce(
    (sum, item) => sum + item.value,
    0,
  )

  return (
    <section className="dashboard-panel severity-distribution-panel">
      <div className="panel-header">
        <div>
          <h2>Severity Distribution</h2>
          <p>Active alerts by severity</p>
        </div>
      </div>

      <div className="donut-wrapper">
        <div className="donut-chart">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={62}
                outerRadius={88}
                paddingAngle={3}
                stroke="none"
              >
                {data.map((item) => (
                  <Cell
                    key={item.name}
                    fill={item.color}
                  />
                ))}
              </Pie>

              <Tooltip
                contentStyle={{
                  background: "#111318",
                  border: "1px solid #292d35",
                  borderRadius: "8px",
                  color: "#ffffff",
                }}
              />
            </PieChart>
          </ResponsiveContainer>

          <div className="donut-center">
            <strong>{total}</strong>
            <span>Total Alerts</span>
          </div>
        </div>

        <div className="severity-legend">
          {data.map((item) => (
            <div
              key={item.name}
              className="legend-item"
            >
              <div className="legend-label">
                <span
                  className="legend-dot"
                  style={{ background: item.color }}
                />
                <span>{item.name}</span>
              </div>

              <strong>{item.value}</strong>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

export default SeverityDistribution