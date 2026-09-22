import api from "./api"
import type { Alert } from "../types/alert"


export interface AlertFilters {
  status?: string
  severity?: string
}

export async function getAlerts(
  filters: AlertFilters = {},
): Promise<Alert[]> {
  const response = await api.get<Alert[]>("/alerts", {
    params: filters,
  })

  return response.data
}
export async function updateAlertStatus(
  alertId: number,
  status: string,
): Promise<Alert> {
  const response = await api.patch<Alert>(
    `/alerts/${alertId}/status`,
    {
      status,
    },
  )

  return response.data
}