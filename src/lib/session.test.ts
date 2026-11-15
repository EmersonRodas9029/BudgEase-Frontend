import { describe, it, expect, beforeEach, vi } from 'vitest';
import { forceLogout } from './session';

describe('forceLogout', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));
    localStorage.setItem('isAuthenticated', 'true');
    localStorage.setItem('authToken', 'abc');
    localStorage.setItem('refreshToken', 'def');
    window.location.hash = '/home';
  });

  it('limpia la sesión y redirige a /login', () => {
    forceLogout();
    expect(localStorage.getItem('isAuthenticated')).toBeNull();
    expect(localStorage.getItem('authToken')).toBeNull();
    expect(window.location.hash).toBe('#/login');
  });
});
