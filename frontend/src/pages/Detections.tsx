import { useEffect, useState } from "react"
import { Search } from "lucide-react"

import { getDetections } from "../services/detections"
import type { Detection } from "../types/detection"

function Detections() {
  const [detections, setDetections] = useState<Detection[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState("")

  useEffect(() => {
    async function loadDetections() {
      try {
        const data = await getDetections()
        setDetections(data)
      } catch {
        setError("Failed to load detections")
      } finally {
        setLoading(false)
      }
    }

    loadDetections()
  }, [])

  const filteredDetections = detections.filter((detection) => {
    const searchValue = search.toLowerCase()

    return (
      detection.rule_name
        .toLowerCase()
        .includes(searchValue) ||
      detection.description
        .toLowerCase()
        .includes(searchValue)
    )
  })

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Detections</h1>
          <p>
            Review threats identified by detection rules.
          </p>
        </div>
      </div>

      <section className="dashboard-panel alerts-page-panel">
        <div className="alerts-toolbar">
          <div className="search-box">
            <Search size={16} />

            <input
              type="text"
              placeholder="Search detection rules..."
              value={search}
              onChange={(event) =>
                setSearch(event.target.value)
              }
            />
          </div>
        </div>

        {loading && (
          <p className="table-message">
            Loading detections...
          </p>
        )}

        {error && (
          <p className="table-message error">
            {error}
          </p>
        )}

        {!loading && !error && (
          <div className="alerts-table-wrapper">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Description</th>
                  <th>Severity</th>
                  <th>Event ID</th>
                  <th>Time</th>
                </tr>
              </thead>

              <tbody>
                {filteredDetections.map((detection) => (
                  <tr key={detection.id}>
                    <td className="alert-title">
                      {detection.rule_name}
                    </td>

                    <td>
                      {detection.description}
                    </td>

                    <td>
                      <span
                        className={`severity-badge ${detection.severity}`}
                      >
                        {detection.severity}
                      </span>
                    </td>

                    <td className="source-ip">
                      #{detection.event_id}
                    </td>

                    <td className="alert-time">
                      {new Date(
                        detection.created_at,
                      ).toLocaleString()}
                    </td>
                  </tr>
                ))}

                {filteredDetections.length === 0 && (
                  <tr>
                    <td
                      colSpan={5}
                      className="table-message"
                    >
                      No detections found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  )
}

export default Detections