import { getToken } from "./auth";

export async function apiFetch(
  url: string,
  options: RequestInit = {},
): Promise<Response> {
  const token = getToken();

  const headers = new Headers(options.headers);

  headers.set("Content-Type", "application/json");

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  return fetch(url, {
    ...options,
    headers,
  });
}