import { describe, it, expect, beforeEach, vi } from 'vitest';
import { apiFetch } from './api';

describe('apiFetch', () => {
  beforeEach(() => {
    localStorage.setItem('authToken', 'old-token');
    localStorage.setItem('refreshToken', 'old-refresh');
  });

  it('pasa de largo una respuesta 200 sin intentar refrescar', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal('fetch', fetchMock);

    await apiFetch('/gastos');

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('en un 401 de endpoint protegido, refresca y reintenta una vez', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: false, status: 401 })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ token: 'new-token', refreshToken: 'new-refresh' }),
      })
      .mockResolvedValueOnce({ ok: true, status: 200 });
    vi.stubGlobal('fetch', fetchMock);

    const res = await apiFetch('/gastos');

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[1][0]).toContain('/auth/refresh');
    expect(localStorage.getItem('authToken')).toBe('new-token');
    expect(res.status).toBe(200);
  });

  it('en un 401 de /auth/login, NO intenta refrescar', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status: 401 });
    vi.stubGlobal('fetch', fetchMock);

    await apiFetch('/auth/login', { method: 'POST' });

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('si el refresh también falla, fuerza logout y no reintenta', async () => {
    // 2 llamadas esperadas (request original + refresh), ambas 401; forceLogout()
    // dispara además un fetch best-effort a /auth/logout (ver shared/utils.logout) que
    // no es el foco de este test, así que cualquier llamada extra recibe un 200 inocuo.
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: false, status: 401 })
      .mockResolvedValueOnce({ ok: false, status: 401 })
      .mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal('fetch', fetchMock);

    await apiFetch('/gastos');

    const calledPaths = fetchMock.mock.calls.map((call) => String(call[0]));
    expect(calledPaths.filter((p) => p.endsWith('/gastos'))).toHaveLength(1);
    expect(calledPaths.filter((p) => p.endsWith('/auth/refresh'))).toHaveLength(1);
    expect(localStorage.getItem('authToken')).toBeNull();
  });
});
