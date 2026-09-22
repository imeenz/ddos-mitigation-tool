import api from "./api"
import type { Detection } from "../types/detection"


export async function getDetections(): Promise<Detection[]> {
  const response = await api.get<Detection[]>("/detections")

  return response.data
}