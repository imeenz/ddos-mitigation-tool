import {
  Activity,
  Bell,
  LayoutDashboard,
  Radar,
  ShieldCheck,
} from "lucide-react"
import { NavLink } from "react-router-dom"

const navigation = [
  {
    name: "Overview",
    icon: LayoutDashboard,
    path: "/",
  },
  {
    name: "Traffic",
    icon: Activity,
    path: "/traffic",
  },
  {
    name: "Detection",
    icon: Radar,
    path: "/detection",
  },
  {
    name: "Mitigation",
    icon: ShieldCheck,
    path: "/mitigation",
  },
  {
    name: "Alerts",
    icon: Bell,
    path: "/alerts",
  },
]

function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-icon">
          <ShieldCheck size={22} />
        </div>

        <div>
          <h1>DDoS</h1>
          <span>MITIGATION</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <span className="nav-label">MONITORING</span>

        {navigation.map((item) => {
          const Icon = item.icon

          return (
            <NavLink
              key={item.name}
              to={item.path}
              end={item.path === "/"}
              className={({ isActive }) =>
                `nav-item ${isActive ? "active" : ""}`
              }
            >
              <Icon size={18} />
              <span>{item.name}</span>
            </NavLink>
          )
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="analyst-profile">
          <div className="analyst-avatar">D</div>

          <div className="analyst-info">
            <strong>Security Operator</strong>
            <span>DDoS Defense Console</span>
          </div>
        </div>

        <div className="system-status">
          <span className="status-dot" />

          <div>
            <strong>Protection Active</strong>
            <span>Monitoring engine online</span>
          </div>
        </div>
      </div>
    </aside>
  )
}

export default Sidebar
