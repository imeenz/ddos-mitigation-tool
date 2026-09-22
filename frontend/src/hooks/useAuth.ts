import { useEffect, useState } from "react"

import {
  getCurrentUser,
  removeToken,
} from "../services/auth"

import type { CurrentUser } from "../services/auth"


export function useAuth() {
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function loadUser() {
      try {
        const currentUser = await getCurrentUser()
        setUser(currentUser)
      } catch {
        removeToken()
        setUser(null)
      } finally {
        setLoading(false)
      }
    }

    loadUser()
  }, [])

  function logout() {
    removeToken()
    setUser(null)
    window.location.href = "/login"
  }

  return {
    user,
    loading,
    logout,
    isAuthenticated: user !== null,
  }
}