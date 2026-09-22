import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"

import type { SecurityEvent } from "../../types/event"

interface ThreatActivityChartProps {
  events: SecurityEvent[]
}

function ThreatActivityChart({
  events,
}: ThreatActivityChartProps) {
  const hourlyCounts = Array.from(
    { length: 24 },
    (_, hour) => ({
      time: `${hour.toString().padStart(2, "0")}:00`,
      events: 0,
    }),
  )

  events.forEach((event) => {
    const date = new Date(event.created_at)
    const hour = date.getHours()

    hourlyCounts[hour].events += 1
  })

  return (
    <section className="dashboard-panel activity-panel">
      <div className="panel-header">
        <div>
          <h2>Security Event Activity</h2>
          <p>Event volume by hour</p>
        </div>

        <span className="live-indicator">
          <span className="live-dot" />
          LIVE
        </span>
      </div>

      <div className="chart-container">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={hourlyCounts}>
            <defs>
              <linearGradient
                id="eventGradient"
                x1="0"
                y1="0"
                x2="0"
                y2="1"
              >
                <stop
                  offset="5%"
                  stopColor="#ef4444"
                  stopOpacity={0.35}
                />
                <stop
                  offset="95%"
                  stopColor="#ef4444"
                  stopOpacity={0}
                />
              </linearGradient>
            </defs>

            <CartesianGrid
              stroke="#20232a"
              strokeDasharray="3 3"
              vertical={false}
            />

            <XAxis
              dataKey="time"
              stroke="#555b66"
              tick={{ fill: "#717782", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
              interval={3}
            />

            <YAxis
              allowDecimals={false}
              stroke="#555b66"
              tick={{ fill: "#717782", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />

            <Tooltip
              contentStyle={{
                background: "#111318",
                border: "1px solid #292d35",
                borderRadius: "8px",
                color: "#ffffff",
              }}
            />

            <Area
              type="monotone"
              dataKey="events"
              stroke="#ef4444"
              strokeWidth={2}
              fill="url(#eventGradient)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </section>
  )
}

export default ThreatActivityChart