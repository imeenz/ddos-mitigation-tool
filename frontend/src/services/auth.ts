const API_BASE_URL = "http://localhost:8000/api/v1";

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

export async function login(
  credentials: LoginCredentials,
): Promise<TokenResponse> {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(credentials),
  });

  if (!response.ok) {
    throw new Error("Invalid email or password");
  }

  return response.json();
}

export function saveToken(token: string): void {
  localStorage.setItem("access_token", token);
}

export function getToken(): string | null {
  return localStorage.getItem("access_token");
}

export function removeToken(): void {
  localStorage.removeItem("access_token");
}

export function isAuthenticated(): boolean {
  return getToken() !== null;
}
export interface CurrentUser {
  id: number
  email: string
  full_name: string
  is_active: boolean
}
export async function getCurrentUser(): Promise<CurrentUser> {
  const token = getToken()

  const response = await fetch(
    "http://localhost:8000/api/v1/auth/me",
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    },
  )

  if (!response.ok) {
    throw new Error("Unable to retrieve current user")
  }

  return response.json()
}