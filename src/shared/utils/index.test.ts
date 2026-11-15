import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  formatCurrency,
  formatDate,
  isSameMonth,
  filterByPeriod,
  isStrongPassword,
  logout,
} from './index';

const NBSP = String.fromCharCode(0xa0);

describe('formatCurrency', () => {
  it('reemplaza el espacio no separable (NBSP) por uno normal, para permitir el wrap en mobile', () => {
    const result = formatCurrency(1234.5);
    expect(result).not.toContain(NBSP);
    expect(result).toContain('1234,50');
    expect(result).toContain('US$');
  });
});

describe('formatDate', () => {
  it('no se corre un dia atras para fechas YYYY-MM-DD', () => {
    expect(formatDate('2026-11-01')).toContain('1');
    expect(formatDate('2026-11-01')).not.toContain('31');
  });
});

describe('isSameMonth', () => {
  it('compara por string, sin desfases de zona horaria', () => {
    expect(isSameMonth('2026-11-01', 2026, 11)).toBe(true);
    expect(isSameMonth('2026-10-31', 2026, 11)).toBe(false);
    expect(isSameMonth(undefined, 2026, 11)).toBe(false);
  });
});

describe('filterByPeriod', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-14T12:00:00'));
  });
  afterEach(() => vi.useRealTimers());

  it('"todos" siempre es true', () => {
    expect(filterByPeriod('2020-01-01', 'todos')).toBe(true);
  });

  it('"este-mes" solo acepta el mes/anio actual', () => {
    expect(filterByPeriod('2026-11-05', 'este-mes')).toBe(true);
    expect(filterByPeriod('2026-10-05', 'este-mes')).toBe(false);
  });

  it('"este-ano" solo acepta el anio actual', () => {
    expect(filterByPeriod('2026-01-01', 'este-ano')).toBe(true);
    expect(filterByPeriod('2025-12-31', 'este-ano')).toBe(false);
  });
});

describe('isStrongPassword', () => {
  it('exige 8+ caracteres con letras y numeros', () => {
    expect(isStrongPassword('abc12345')).toBe(true);
    expect(isStrongPassword('abcdefgh')).toBe(false);
    expect(isStrongPassword('1234567')).toBe(false);
  });
});

describe('logout', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));
    localStorage.setItem('isAuthenticated', 'true');
    localStorage.setItem('authToken', 'abc');
    localStorage.setItem('refreshToken', 'def');
  });

  it('limpia todas las claves de sesion de localStorage', () => {
    logout();
    expect(localStorage.getItem('isAuthenticated')).toBeNull();
    expect(localStorage.getItem('authToken')).toBeNull();
    expect(localStorage.getItem('refreshToken')).toBeNull();
  });
});
