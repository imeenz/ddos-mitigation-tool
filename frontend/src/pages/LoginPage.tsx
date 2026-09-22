import { useState } from "react"
import type { FormEvent } from "react"

import { login, saveToken } from "../services/auth"

export default function Login() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    setError("")
    setLoading(true)

    try {
      const response = await login({
        email,
        password,
      })

      saveToken(response.access_token)

      window.location.href = "/"
    } catch {
      setError("Invalid email or password")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-brand">
          <div className="login-shield">◈</div>

          <div>
            <h1>SIEM</h1>
            <p>Security Operations</p>
          </div>
        </div>

        <div className="login-heading">
          <h2>Analyst Sign In</h2>
          <p>Sign in to access the security operations console.</p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          <label htmlFor="email">Email</label>

          <input
            id="email"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="analyst@example.com"
            required
          />

          <label htmlFor="password">Password</label>

          <input
            id="password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Enter your password"
            required
          />

          {error && (
            <div className="login-error">
              {error}
            </div>
          )}

          <button type="submit" disabled={loading}>
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  )
}