import type { ApiError } from './types';

export class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    if (!response.ok) {
      const error: ApiError = await response.json().catch(() => ({
        detail: `HTTP ${response.status}: ${response.statusText}`,
      }));
      throw new Error(error.detail);
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return undefined as T;
    }

    return response.json();
  }

  async get<T>(path: string): Promise<T> {
    return this.request<T>(path);
  }

  async post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>(path, {
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  async postFormData<T>(path: string, formData: FormData): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const response = await fetch(url, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const error: ApiError = await response.json().catch(() => ({
        detail: `HTTP ${response.status}: ${response.statusText}`,
      }));
      throw new Error(error.detail);
    }

    return response.json();
  }

  async patch<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>(path, {
      method: 'PATCH',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  async delete(path: string): Promise<void> {
    return this.request<void>(path, { method: 'DELETE' });
  }

  async getText(path: string): Promise<string> {
    const url = `${this.baseUrl}${path}`;
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return response.text();
  }

  async postBlob(path: string, body?: unknown): Promise<Blob> {
    const url = `${this.baseUrl}${path}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const error: ApiError = await response.json().catch(() => ({
        detail: `HTTP ${response.status}: ${response.statusText}`,
      }));
      throw new Error(error.detail);
    }

    return response.blob();
  }
}

// Create API clients for server-side and client-side use
export function createTvsClient(isServer = false): ApiClient {
  const baseUrl = isServer
    ? (import.meta.env.TVS_API_URL || 'http://localhost:8081')
    : (import.meta.env.PUBLIC_TVS_API_URL || '/api/tvs');
  return new ApiClient(`${baseUrl}/api/v1`);
}

export function createCapfClient(isServer = false): ApiClient {
  const baseUrl = isServer
    ? (import.meta.env.CAPF_API_URL || 'http://localhost:8082')
    : (import.meta.env.PUBLIC_CAPF_API_URL || '/api/capf');
  return new ApiClient(`${baseUrl}/api/v1`);
}
