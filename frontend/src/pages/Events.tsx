import { useEffect, useState } from "react"
import { Search } from "lucide-react"

import { getEvents } from "../services/events"
import type { SecurityEvent } from "../types/event"

function Events() {
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState("")

  useEffect(() => {
    async function loadEvents() {
      try {
        const data = await getEvents()
        setEvents(data)
      } catch {
        setError("Failed to load security events")
      } finally {
        setLoading(false)
      }
    }

    loadEvents()
  }, [])

  const filteredEvents = events.filter((event) => {
    const searchValue = search.toLowerCase()

    return (
      event.event_type
        .toLowerCase()
        .includes(searchValue) ||
      event.message
        .toLowerCase()
        .includes(searchValue) ||
      event.source_ip
        ?.toLowerCase()
        .includes(searchValue) ||
      event.destination_ip
        ?.toLowerCase()
        .includes(searchValue)
    )
  })

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Security Events</h1>
          <p>
            Explore normalized security events and logs.
          </p>
        </div>
      </div>

      <section className="dashboard-panel alerts-page-panel">
        <div className="alerts-toolbar">
          <div className="search-box">
            <Search size={16} />

            <input
              type="text"
              placeholder="Search events, IP addresses..."
              value={search}
              onChange={(event) =>
                setSearch(event.target.value)
              }
            />
          </div>
        </div>

        {loading && (
          <p className="table-message">
            Loading security events...
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
                  <th>Event Type</th>
                  <th>Severity</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Message</th>
                  <th>Time</th>
                </tr>
              </thead>

              <tbody>
                {filteredEvents.map((event) => (
                  <tr key={event.id}>
                    <td className="alert-title">
                      {event.event_type}
                    </td>

                    <td>
                      <span
                        className={`severity-badge ${event.severity}`}
                      >
                        {event.severity}
                      </span>
                    </td>

                    <td className="source-ip">
                      {event.source_ip ?? "—"}
                    </td>

                    <td className="source-ip">
                      {event.destination_ip ?? "—"}
                    </td>

                    <td>{event.message}</td>

                    <td className="alert-time">
                      {new Date(
                        event.created_at,
                      ).toLocaleString()}
                    </td>
                  </tr>
                ))}

                {filteredEvents.length === 0 && (
                  <tr>
                    <td
                      colSpan={6}
                      className="table-message"
                    >
                      No security events found.
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

export default Events