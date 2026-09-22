import {
  AlertTriangle,
  CircleAlert,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react"

import type { Alert } from "../../types/alert"

interface SeverityCardsProps {
  alerts: Alert[]
}

function SeverityCards({ alerts }: SeverityCardsProps) {
  const severityData = [
    {
      label: "Critical",
      value: alerts.filter(
        (alert) => alert.severity === "critical",
      ).length,
      icon: CircleAlert,
      className: "critical",
    },
    {
      label: "High",
      value: alerts.filter(
        (alert) => alert.severity === "high",
      ).length,
      icon: ShieldAlert,
      className: "high",
    },
    {
      label: "Medium",
      value: alerts.filter(
        (alert) => alert.severity === "medium",
      ).length,
      icon: AlertTriangle,
      className: "medium",
    },
    {
      label: "Low",
      value: alerts.filter(
        (alert) => alert.severity === "low",
      ).length,
      icon: ShieldCheck,
      className: "low",
    },
  ]

  return (
    <section className="severity-grid">
      {severityData.map((item) => {
        const Icon = item.icon

        return (
          <article
            key={item.label}
            className={`severity-card ${item.className}`}
          >
            <div className="severity-card-header">
              <span>{item.label}</span>
              <Icon size={18} />
            </div>

            <strong>{item.value}</strong>

            <span className="severity-caption">
              Active security alerts
            </span>
          </article>
        )
      })}
    </section>
  )
}

export default SeverityCards