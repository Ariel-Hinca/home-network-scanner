export class ApiError extends Error {
  status: number;
  code?: string;

  constructor(status: number, message: string, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const base = import.meta.env.VITE_API_BASE_URL ?? "";

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  headers.set("X-HomeGuard-Request", "1");

  const response = await fetch(`${base}${path}`, {
    ...init,
    headers,
    credentials: "include",
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  const data = text ? (JSON.parse(text) as unknown) : null;
  if (!response.ok) {
    const detail = isRecord(data) ? data.detail : undefined;
    const message = detailMessage(detail) ?? response.statusText;
    const code = isRecord(detail) && typeof detail.code === "string" ? detail.code : undefined;
    throw new ApiError(response.status, message, code);
  }
  return data as T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function detailMessage(detail: unknown): string | undefined {
  if (typeof detail === "string") {
    return detail;
  }
  if (isRecord(detail) && typeof detail.message === "string") {
    return detail.message;
  }
  return undefined;
}
