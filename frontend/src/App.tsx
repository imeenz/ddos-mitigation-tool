import { Routes, Route } from "react-router-dom"

import Sidebar from "./components/layout/Sidebar"
import Dashboard from "./pages/Dashboard"
import Traffic from "./pages/Traffic"
import Detection from "./pages/Detection"
import Mitigation from "./pages/Mitigation"
import Alerts from "./pages/Alerts"

function App() {
  return (
    <div className="app-shell">
      <Sidebar />

      <main className="main-content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/traffic" element={<Traffic />} />
          <Route path="/detection" element={<Detection />} />
          <Route path="/mitigation" element={<Mitigation />} />
          <Route path="/alerts" element={<Alerts />} />
        </Routes>
      </main>
    </div>
  )
}

export default App
