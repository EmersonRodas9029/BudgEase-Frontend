import { config } from './config';
import { forceLogout } from './session';

const authHeaders = (): Record<string, string> => {
  const token = localStorage.getItem('authToken');
  return token ? { Authorization: `Bearer ${token}` } : {};
};

const NO_RETRY_PATHS = ['/auth/login', '/auth/refresh', '/auth/logout'];

let refreshPromise: Promise<string | null> | null = null;

const refreshAccessToken = (): Promise<string | null> => {
  if (!refreshPromise) {
    refreshPromise = (async () => {
      const refreshToken = localStorage.getItem('refreshToken');
      if (!refreshToken) return null;
      try {
        const res = await fetch(`${config.apiUrl}/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refreshToken }),
        });
        if (!res.ok) return null;
        const data = (await res.json()) as { token: string; refreshToken: string };
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('refreshToken', data.refreshToken);
        return data.token;
      } catch {
        return null;
      } finally {
        refreshPromise = null;
      }
    })();
  }
  return refreshPromise;
};

export const apiFetch = async (
  path: string,
  options: RequestInit = {},
  isRetry = false,
): Promise<Response> => {
  const res = await fetch(`${config.apiUrl}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(),
      ...(options.headers as Record<string, string> | undefined),
    },
  });

  if (res.status === 401 && !isRetry && !NO_RETRY_PATHS.includes(path)) {
    const newToken = await refreshAccessToken();
    if (newToken) return apiFetch(path, options, true);
    forceLogout();
  }

  return res;
};

export const apiJson = async <T>(path: string, options?: RequestInit): Promise<T> => {
  const r = await apiFetch(path, options);
  if (!r.ok) {
    const body = (await r.json().catch(() => null)) as { message?: string } | null;
    throw new Error(body?.message || r.statusText);
  }
  if (r.status === 204) return undefined as T;
  const text = await r.text();
  return text ? (JSON.parse(text) as T) : (undefined as T);
};
