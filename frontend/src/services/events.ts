import api from "./api"
import type { SecurityEvent } from "../types/event"

export async function getEvents(): Promise<SecurityEvent[]> {
  const response = await api.get<SecurityEvent[]>("/events")

  return response.data
}