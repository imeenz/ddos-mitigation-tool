export interface SecurityEvent {
  id: number
  source: string
  event_type: string
  severity: string
  source_ip: string | null
  destination_ip: string | null
  message: string
  raw_log: string
  created_at: string
}