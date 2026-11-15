# Session Security, Tests & Branding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make BudgEase sellable to a third party by closing three gaps: JWT sessions that never expire gracefully, zero automated tests, and a hardcoded brand name.

**Architecture:** Add real refresh-token rotation to the Spring Boot backend (new `refresh_tokens` table, `/api/auth/refresh` + `/api/auth/logout`), consume it from the frontend via a transparent 401-retry-and-refresh wrapper around `apiFetch` (no polling/timers), add Vitest as the frontend test runner with tests on the fragile/critical logic (date filtering, currency formatting, the new session logic), and wire the already-half-built `config.appName` into the handful of hardcoded "BudgEase" strings plus a new default-color-scheme env var reusing the theming system that already exists.

**Tech Stack:** Spring Boot 3 / Java 17 / MySQL / Flyway (backend repo `../BudgEase-Backend`), React 19 + TypeScript + Vite + Vitest + React Testing Library (this repo).

**Spec:** No separate spec doc — this plan was scoped directly against the running codebase after reading the live auth flow, backend `AuthController`/`JwtUtil`, and the frontend's theming CSS. See conversation context; key facts baked into the tasks below:
- Backend today has only `POST /api/auth/login`; access tokens last `jwt.expiration` (default 24h) with no revocation and no refresh.
- `/api/auth/**` is already `permitAll()` in `SecurityConfig` — new auth endpoints need no security config change.
- `UnauthorizedException` already maps to HTTP 401 via `GlobalExceptionHandler`.
- Frontend's real routed login screen is `src/features/auth/pages/LoginPage.tsx` (NOT the files under `src/features/auth/components/LoginPage/` or `components/Login.tsx` — those are dead code, not imported anywhere, and are out of scope for this plan).
- `src/lib/config.ts` already exports `config.appName` (from `VITE_APP_NAME`) but nothing reads it — the 4 live hardcoded "BudgEase" strings never got wired to it.
- The app already has a full CSS-variable-driven color-scheme system (`data-color-scheme` on `<html>`, set in `src/app/main.tsx` from a stored user preference) — reuse it for a per-deployment default instead of building new theming infra.

## Global Constraints

- Backend: Java 17, Spring Boot 3.3.13, Lombok, JUnit 5 + Mockito (`spring-boot-starter-test`, already a dependency) — follow the existing test style in `src/test/java/.../service/UsuarioServiceImplTest.java` (`@ExtendWith(MockitoExtension.class)`, `@Mock` fields, no Spring context boot).
- Backend migrations: MySQL dialect, `snake_case` columns, `fecha_creacion`/`fecha_modificacion` TIMESTAMP convention, FK constraints named `fk_<table>_<ref>` — match `V1__create_table_usuarios.sql` style exactly.
- Frontend: TypeScript strict-ish (`strict: false` in `tsconfig.app.json` but no `any` please), React 19, no new runtime dependency beyond Vitest/RTL — no axios/jwt-decode library, use `fetch` and stdlib only.
- No new abstractions beyond what's listed — no generic "AuthProvider" context, no token-refresh timer/polling loop (401-triggered refresh is sufficient and simpler).
- Don't touch the dead-code auth components under `src/features/auth/components/` — not routed, not in scope.
- Don't change the 24h default access-token lifetime (`jwt.expiration`) — only additive.

---

### Task 1: Backend — refresh-token storage + `AuthService.refresh`/`logout`

**Files:**
- Create: `../BudgEase-Backend/src/main/resources/db/migration/V20__create_table_refresh_tokens.sql`
- Create: `../BudgEase-Backend/src/main/java/com/codepuppeteer/sistema_gastos_clientes/entity/RefreshToken.java`
- Create: `../BudgEase-Backend/src/main/java/com/codepuppeteer/sistema_gastos_clientes/repository/RefreshTokenRepository.java`
- Create: `../BudgEase-Backend/src/main/java/com/codepuppeteer/sistema_gastos_clientes/dto/auth/RefreshTokenRequest.java`
- Modify: `../BudgEase-Backend/src/main/java/com/codepuppeteer/sistema_gastos_clientes/dto/auth/LoginResponse.java`
- Modify: `../BudgEase-Backend/src/main/java/com/codepuppeteer/sistema_gastos_clientes/service/interfaces/AuthService.java`
- Modify: `../BudgEase-Backend/src/main/java/com/codepuppeteer/sistema_gastos_clientes/service/impl/AuthServiceImpl.java`
- Modify: `../BudgEase-Backend/src/main/resources/application.properties`
- Test: `../BudgEase-Backend/src/test/java/com/codepuppeteer/sistema_gastos_clientes/service/AuthServiceImplTest.java`

**Interfaces:**
- Produces: `AuthService.refresh(String rawRefreshToken): LoginResponse`, `AuthService.logout(String rawRefreshToken): void`, `LoginResponse.refreshToken` field. Task 2 (controller) calls these two methods directly with the raw (unhashed) token string from the request body.

- [ ] **Step 1: Write the failing tests**

```java
package com.codepuppeteer.sistema_gastos_clientes.service;

import com.codepuppeteer.sistema_gastos_clientes.dto.auth.LoginResponse;
import com.codepuppeteer.sistema_gastos_clientes.entity.RefreshToken;
import com.codepuppeteer.sistema_gastos_clientes.entity.Usuario;
import com.codepuppeteer.sistema_gastos_clientes.enums.Rol;
import com.codepuppeteer.sistema_gastos_clientes.exception.UnauthorizedException;
import com.codepuppeteer.sistema_gastos_clientes.repository.RefreshTokenRepository;
import com.codepuppeteer.sistema_gastos_clientes.repository.UsuarioRepository;
import com.codepuppeteer.sistema_gastos_clientes.service.impl.AuthServiceImpl;
import com.codepuppeteer.sistema_gastos_clientes.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock private AuthenticationManager authenticationManager;
    @Mock private UsuarioRepository usuarioRepository;
    @Mock private JwtUtil jwtUtil;
    @Mock private RefreshTokenRepository refreshTokenRepository;

    private AuthServiceImpl service;
    private Usuario usuario;

    @BeforeEach
    void setUp() {
        service = new AuthServiceImpl(authenticationManager, usuarioRepository, jwtUtil, refreshTokenRepository);
        ReflectionTestUtils.setField(service, "refreshExpiration", 1_209_600_000L);

        usuario = Usuario.builder()
                .id(1L).username("ana").email("ana@test.com").rol(Rol.CLIENTE)
                .activo(true).intentosFallidos(0)
                .build();

        lenient().when(jwtUtil.generateToken(anyString(), any())).thenReturn("mocked-jwt");
    }

    @Test
    void refresh_conTokenValido_revocaElViejoYDevuelveTokensNuevos() {
        RefreshToken stored = RefreshToken.builder()
                .id(10L).token("hash-no-importa").usuario(usuario)
                .expiryDate(LocalDateTime.now().plusDays(1)).revoked(false)
                .build();
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(stored));

        LoginResponse response = service.refresh("raw-refresh-token-cualquiera");

        assertEquals("mocked-jwt", response.getToken());
        assertNotNull(response.getRefreshToken());
        assertEquals("ana", response.getUsername());
        assertTrue(stored.getRevoked(), "el refresh token usado debe quedar revocado (rotación)");
        verify(refreshTokenRepository, times(2)).save(any());
    }

    @Test
    void refresh_conTokenRevocado_lanzaUnauthorized() {
        RefreshToken stored = RefreshToken.builder()
                .token("x").usuario(usuario)
                .expiryDate(LocalDateTime.now().plusDays(1)).revoked(true)
                .build();
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(stored));

        assertThrows(UnauthorizedException.class, () -> service.refresh("raw"));
    }

    @Test
    void refresh_conTokenExpirado_lanzaUnauthorized() {
        RefreshToken stored = RefreshToken.builder()
                .token("x").usuario(usuario)
                .expiryDate(LocalDateTime.now().minusMinutes(1)).revoked(false)
                .build();
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(stored));

        assertThrows(UnauthorizedException.class, () -> service.refresh("raw"));
    }

    @Test
    void refresh_conTokenInexistente_lanzaUnauthorized() {
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());

        assertThrows(UnauthorizedException.class, () -> service.refresh("raw"));
    }

    @Test
    void logout_marcaElRefreshTokenComoRevocado() {
        RefreshToken stored = RefreshToken.builder()
                .token("x").usuario(usuario)
                .expiryDate(LocalDateTime.now().plusDays(1)).revoked(false)
                .build();
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(stored));

        service.logout("raw");

        assertTrue(stored.getRevoked());
        verify(refreshTokenRepository).save(stored);
    }

    @Test
    void logout_conTokenQueNoExiste_noLanzaError() {
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());

        assertDoesNotThrow(() -> service.logout("raw"));
        verify(refreshTokenRepository, never()).save(any());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run (from `../BudgEase-Backend`): `mvn -q -Dtest=AuthServiceImplTest test`
Expected: compile error — `AuthServiceImpl` has no 4-arg constructor, no `refresh`/`logout` methods yet, `RefreshToken`/`RefreshTokenRepository` don't exist.

- [ ] **Step 3: Create the migration**

`../BudgEase-Backend/src/main/resources/db/migration/V20__create_table_refresh_tokens.sql`:

```sql
CREATE TABLE refresh_tokens (
                                 id BIGINT AUTO_INCREMENT PRIMARY KEY,
                                 token VARCHAR(255) NOT NULL UNIQUE,
                                 usuario_id BIGINT NOT NULL,
                                 expiry_date TIMESTAMP NOT NULL,
                                 revoked BOOLEAN NOT NULL DEFAULT FALSE,
                                 fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                 CONSTRAINT fk_refresh_tokens_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
                                 INDEX idx_refresh_tokens_usuario (usuario_id)
);
```

- [ ] **Step 4: Create the entity**

`../BudgEase-Backend/src/main/java/com/codepuppeteer/sistema_gastos_clientes/entity/RefreshToken.java`:

```java
package com.codepuppeteer.sistema_gastos_clientes.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 255)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "usuario_id", nullable = false, foreignKey = @ForeignKey(name = "fk_refresh_tokens_usuario"))
    private Usuario usuario;

    @Column(nullable = false)
    private LocalDateTime expiryDate;

    @Column(nullable = false)
    @Builder.Default
    private Boolean revoked = false;

    @Column(nullable = false, updatable = false)
    @Builder.Default
    private LocalDateTime fechaCreacion = LocalDateTime.now();
}
```

- [ ] **Step 5: Create the repository**

`../BudgEase-Backend/src/main/java/com/codepuppeteer/sistema_gastos_clientes/repository/RefreshTokenRepository.java`:

```java
package com.codepuppeteer.sistema_gastos_clientes.repository;

import com.codepuppeteer.sistema_gastos_clientes.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
}
```

- [ ] **Step 6: Create the request DTO and extend the response DTO**

`../BudgEase-Backend/src/main/java/com/codepuppeteer/sistema_gastos_clientes/dto/auth/RefreshTokenRequest.java`:

```java
package com.codepuppeteer.sistema_gastos_clientes.dto.auth;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RefreshTokenRequest {

    @NotBlank(message = "El refresh token es obligatorio")
    private String refreshToken;
}
```

In `LoginResponse.java`, add one field:

```java
    private String refreshToken;
```

(keep everything else in that file as-is — `@Data @Builder` already generates the getter/builder method for the new field).

- [ ] **Step 7: Add the refresh-token expiration property**

In `../BudgEase-Backend/src/main/resources/application.properties`, right after the existing `jwt.expiration` line:

```properties
jwt.refresh-expiration=${JWT_REFRESH_EXPIRATION:1209600000}
```

(14 days in ms — independent of the 24h access-token lifetime, which stays unchanged.)

- [ ] **Step 8: Implement `AuthService.refresh`/`logout`**

In `AuthService.java`, add to the interface:

```java
    LoginResponse refresh(String refreshToken);
    void logout(String refreshToken);
```

In `AuthServiceImpl.java`: add the new constructor dependency, the two new methods, and the private token helpers. Add these imports: `com.codepuppeteer.sistema_gastos_clientes.entity.RefreshToken`, `com.codepuppeteer.sistema_gastos_clientes.repository.RefreshTokenRepository`, `org.springframework.beans.factory.annotation.Value`, `java.security.MessageDigest`, `java.security.NoSuchAlgorithmException`, `java.security.SecureRandom`, `java.nio.charset.StandardCharsets`, `java.util.Base64`.

Add a new `private final RefreshTokenRepository refreshTokenRepository;` field (Lombok's `@RequiredArgsConstructor` on the class picks it up automatically) and:

```java
    @Value("${jwt.refresh-expiration}")
    private Long refreshExpiration;
```

```java
    @Override
    @Transactional
    public LoginResponse refresh(String refreshToken) {
        RefreshToken stored = refreshTokenRepository.findByToken(hash(refreshToken))
                .orElseThrow(() -> new UnauthorizedException("Refresh token inválido"));

        if (stored.getRevoked() || stored.getExpiryDate().isBefore(LocalDateTime.now())) {
            SECURITY_LOG.warn("Refresh rechazado: token revocado o expirado (usuario id={})", stored.getUsuario().getId());
            throw new UnauthorizedException("Refresh token inválido o expirado");
        }

        Usuario usuario = stored.getUsuario();
        stored.setRevoked(true);
        refreshTokenRepository.save(stored);

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", usuario.getId());
        claims.put("rol", usuario.getRol().name());
        claims.put("email", usuario.getEmail());
        String newAccessToken = jwtUtil.generateToken(usuario.getUsername(), claims);
        String newRefreshToken = createRefreshToken(usuario);

        SECURITY_LOG.info("Token refrescado: usuario '{}' (id={})", usuario.getUsername(), usuario.getId());

        return LoginResponse.builder()
                .token(newAccessToken)
                .type("Bearer")
                .userId(usuario.getId())
                .username(usuario.getUsername())
                .email(usuario.getEmail())
                .rol(usuario.getRol().name())
                .refreshToken(newRefreshToken)
                .build();
    }

    @Override
    @Transactional
    public void logout(String refreshToken) {
        refreshTokenRepository.findByToken(hash(refreshToken)).ifPresent(stored -> {
            stored.setRevoked(true);
            refreshTokenRepository.save(stored);
        });
    }

    private String createRefreshToken(Usuario usuario) {
        String raw = generateSecureRandomToken();
        RefreshToken entity = RefreshToken.builder()
                .token(hash(raw))
                .usuario(usuario)
                .expiryDate(LocalDateTime.now().plusSeconds(refreshExpiration / 1000))
                .revoked(false)
                .build();
        refreshTokenRepository.save(entity);
        return raw;
    }

    private String generateSecureRandomToken() {
        byte[] bytes = new byte[64];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(digest.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
```

Finally, in the existing `login()` method, right before `return LoginResponse.builder()...`, add:

```java
            String rawRefreshToken = createRefreshToken(usuario);
```

and add `.refreshToken(rawRefreshToken)` to that builder chain.

Note: refresh tokens are stored as a SHA-256 hash (not bcrypt) — they're high-entropy random values already, not low-entropy secrets like passwords, so a fast hash that supports an indexed `findByToken` lookup is the correct choice (bcrypt's slow, salted design doesn't support indexed lookup at all).

- [ ] **Step 9: Run tests to verify they pass**

Run: `mvn -q -Dtest=AuthServiceImplTest test`
Expected: all 6 tests PASS.

- [ ] **Step 10: Commit**

```bash
cd ../BudgEase-Backend
git add src/main/java/com/codepuppeteer/sistema_gastos_clientes/entity/RefreshToken.java \
        src/main/java/com/codepuppeteer/sistema_gastos_clientes/repository/RefreshTokenRepository.java \
        src/main/java/com/codepuppeteer/sistema_gastos_clientes/dto/auth/RefreshTokenRequest.java \
        src/main/java/com/codepuppeteer/sistema_gastos_clientes/dto/auth/LoginResponse.java \
        src/main/java/com/codepuppeteer/sistema_gastos_clientes/service/interfaces/AuthService.java \
        src/main/java/com/codepuppeteer/sistema_gastos_clientes/service/impl/AuthServiceImpl.java \
        src/main/resources/db/migration/V20__create_table_refresh_tokens.sql \
        src/main/resources/application.properties \
        src/test/java/com/codepuppeteer/sistema_gastos_clientes/service/AuthServiceImplTest.java
git commit -m "feat: add refresh-token rotation to AuthService"
```

---

### Task 2: Backend — `/api/auth/refresh` and `/api/auth/logout` endpoints

**Files:**
- Modify: `../BudgEase-Backend/src/main/java/com/codepuppeteer/sistema_gastos_clientes/controller/api/AuthController.java`

**Interfaces:**
- Consumes: `AuthService.refresh(String): LoginResponse`, `AuthService.logout(String): void` from Task 1.
- Produces: `POST /api/auth/refresh` (body `{refreshToken}` → `LoginResponse`), `POST /api/auth/logout` (body `{refreshToken}` → 204). Both already fall under the existing `permitAll()` rule for `/api/auth/**` — no `SecurityConfig` change needed. Frontend Task 5 calls these two paths directly.

This is pure delegation (no branching logic), so per house convention (no controller-level tests exist elsewhere in this codebase either) it's verified manually rather than with a new test file.

- [ ] **Step 1: Add the two endpoints**

```java
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refresh(request.getRefreshToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequest request) {
        authService.logout(request.getRefreshToken());
        return ResponseEntity.noContent().build();
    }
```

Add the import: `com.codepuppeteer.sistema_gastos_clientes.dto.auth.RefreshTokenRequest`.

- [ ] **Step 2: Verify manually**

Run the backend (`mvn spring-boot:run`), then:

```bash
TOKENS=$(curl -s -X POST http://localhost:8080/api/auth/login -H 'Content-Type: application/json' -d '{"username":"<existing-user>","password":"<password>"}')
echo "$TOKENS"
REFRESH=$(echo "$TOKENS" | python3 -c "import sys,json;print(json.load(sys.stdin)['refreshToken'])")
curl -s -X POST http://localhost:8080/api/auth/refresh -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$REFRESH\"}"
# second call with the SAME $REFRESH must now fail (rotated/revoked):
curl -s -i -X POST http://localhost:8080/api/auth/refresh -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$REFRESH\"}"
```

Expected: first `/refresh` call returns a new `token`+`refreshToken` pair (200); the second call with the stale `$REFRESH` returns 401.

- [ ] **Step 3: Commit**

```bash
cd ../BudgEase-Backend
git add src/main/java/com/codepuppeteer/sistema_gastos_clientes/controller/api/AuthController.java
git commit -m "feat: expose /api/auth/refresh and /api/auth/logout"
```

---

### Task 3: Frontend — Vitest setup + regression tests for `shared/utils`

**Files:**
- Create: `src/test/setup.ts`
- Create: `src/shared/utils/index.test.ts`
- Modify: `vite.config.ts`
- Modify: `package.json`

**Interfaces:**
- Produces: `npm test` (runs once) and `npm run test:watch`, usable by every later task in this plan.

- [ ] **Step 1: Install dependencies**

```bash
npm install -D vitest @testing-library/react @testing-library/jest-dom jsdom
```

- [ ] **Step 2: Wire Vitest into `vite.config.ts`**

Replace the whole file with:

```ts
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    globals: true,
  },
})
```

- [ ] **Step 3: Add the setup file**

`src/test/setup.ts`:

```ts
import '@testing-library/jest-dom';
```

- [ ] **Step 4: Add test scripts to `package.json`**

In the `"scripts"` block, add:

```json
    "test": "vitest run",
    "test:watch": "vitest"
```

- [ ] **Step 5: Write the failing tests**

`src/shared/utils/index.test.ts`:

```ts
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  formatCurrency,
  formatDate,
  isSameMonth,
  filterByPeriod,
  isStrongPassword,
  logout,
} from './index';

describe('formatCurrency', () => {
  it('formatea con espacio normal entre monto y moneda (sin NBSP)', () => {
    const result = formatCurrency(1234.5);
    expect(result).not.toContain(' ');
    expect(result).toContain('1,234.50');
  });
});

describe('formatDate', () => {
  it('no se corre un día atrás para fechas YYYY-MM-DD', () => {
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

  it('"este-mes" solo acepta el mes/año actual', () => {
    expect(filterByPeriod('2026-11-05', 'este-mes')).toBe(true);
    expect(filterByPeriod('2026-10-05', 'este-mes')).toBe(false);
  });

  it('"este-ano" solo acepta el año actual', () => {
    expect(filterByPeriod('2026-01-01', 'este-ano')).toBe(true);
    expect(filterByPeriod('2025-12-31', 'este-ano')).toBe(false);
  });
});

describe('isStrongPassword', () => {
  it('exige 8+ caracteres con letras y números', () => {
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

  it('limpia todas las claves de sesión de localStorage', () => {
    logout();
    expect(localStorage.getItem('isAuthenticated')).toBeNull();
    expect(localStorage.getItem('authToken')).toBeNull();
    expect(localStorage.getItem('refreshToken')).toBeNull();
  });
});
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `npm test`
Expected: fails — `logout` not yet reading/clearing `refreshToken`, `vitest`/config not yet wired (first run after Step 1-4 should at least execute; the `refreshToken` assertion in the `logout` test is the one expected to fail until Task 4 extends `SESSION_KEYS`).

- [ ] **Step 7: Run tests to verify the rest pass**

The `formatCurrency`/`formatDate`/`isSameMonth`/`filterByPeriod`/`isStrongPassword` tests should already PASS (they test existing, already-correct behavior). Confirm with:

Run: `npm test -- index.test.ts`
Expected: 4 of 5 describe blocks pass; `logout` test fails until Task 4.

- [ ] **Step 8: Commit**

```bash
git add package.json package-lock.json vite.config.ts src/test/setup.ts src/shared/utils/index.test.ts
git commit -m "test: add Vitest and regression tests for shared/utils"
```

---

### Task 4: Frontend — `logout()` revokes server-side + `forceLogout` for 401s

**Files:**
- Modify: `src/shared/utils/index.tsx`
- Create: `src/lib/session.ts`
- Test: `src/lib/session.test.ts`

**Interfaces:**
- Consumes: `config.apiUrl` from `src/lib/config.ts`.
- Produces: `forceLogout(message?: string): void`, exported from `src/lib/session.ts`. Task 5 (`api.ts`) calls this on an unrecoverable 401.

- [ ] **Step 1: Write the failing test**

`src/lib/session.test.ts`:

```ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- session.test.ts`
Expected: FAIL — `src/lib/session.ts` doesn't exist yet.

- [ ] **Step 3: Extend `logout()` to revoke the refresh token server-side**

In `src/shared/utils/index.tsx`, add the import `import { config } from '../../lib/config';` near the top, add `'refreshToken'` to `SESSION_KEYS`, and replace the `logout` function:

```ts
const SESSION_KEYS = [
  'isAuthenticated', 'userRole', 'userName', 'authToken', 'refreshToken',
  'clienteId', 'userId', 'userEmail', 'managedClienteId', 'managedClienteNombre',
];

// ponytail: best-effort revoke, sin esperar la respuesta — si falla (sin red, backend caído),
// la sesión local se limpia igual; el refresh token solo queda vivo hasta que expire por su cuenta.
export const logout = (): void => {
  const refreshToken = localStorage.getItem('refreshToken');
  if (refreshToken) {
    fetch(`${config.apiUrl}/auth/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    }).catch(() => {});
  }
  SESSION_KEYS.forEach((key) => localStorage.removeItem(key));
};
```

- [ ] **Step 4: Create `src/lib/session.ts`**

```ts
import toast from 'react-hot-toast';
import { logout } from '../shared/utils';

export const forceLogout = (message = 'Tu sesión expiró. Inicia sesión de nuevo.'): void => {
  logout();
  toast.error(message, { id: 'session-expired' });
  window.location.hash = '/login';
};
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `npm test -- session.test.ts index.test.ts`
Expected: both files PASS, including the `logout` test from Task 3 that was failing.

- [ ] **Step 6: Commit**

```bash
git add src/shared/utils/index.tsx src/lib/session.ts src/lib/session.test.ts
git commit -m "feat: revoke refresh token on logout, add forceLogout for expired sessions"
```

---

### Task 5: Frontend — transparent 401-retry-and-refresh in `apiFetch`

**Files:**
- Modify: `src/lib/api.ts`
- Test: `src/lib/api.test.ts`

**Interfaces:**
- Consumes: `forceLogout` from Task 4, `config.apiUrl` from `src/lib/config.ts`.
- Produces: `apiFetch` keeps its existing signature `(path, options) => Promise<Response>` — callers (every `*Service`) need zero changes.

- [ ] **Step 1: Write the failing tests**

`src/lib/api.test.ts`:

```ts
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
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: false, status: 401 })
      .mockResolvedValueOnce({ ok: false, status: 401 });
    vi.stubGlobal('fetch', fetchMock);

    await apiFetch('/gastos');

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(localStorage.getItem('authToken')).toBeNull();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npm test -- api.test.ts`
Expected: FAIL — current `apiFetch` has no retry/refresh logic (call-count and status assertions fail).

- [ ] **Step 3: Implement the retry-and-refresh wrapper**

Replace `src/lib/api.ts`:

```ts
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test -- api.test.ts`
Expected: all 4 tests PASS.

- [ ] **Step 5: Run the full suite**

Run: `npm test`
Expected: all tests across all files PASS.

- [ ] **Step 6: Commit**

```bash
git add src/lib/api.ts src/lib/api.test.ts
git commit -m "feat: retry once with a refreshed token on 401, then force logout"
```

---

### Task 6: Frontend — store the refresh token on login

**Files:**
- Modify: `src/features/auth/services/index.ts`
- Modify: `src/features/auth/pages/LoginPage.tsx`

**Interfaces:**
- Consumes: backend `LoginResponse.refreshToken` from Task 1/2.
- Produces: `localStorage.refreshToken` populated right after a successful login, which Task 4/5's `logout`/`apiFetch` already depend on.

- [ ] **Step 1: Add `refreshToken` to the `LoginResponse` type**

In `src/features/auth/services/index.ts`, add one field to the interface:

```ts
export interface LoginResponse {
  token: string;
  type: string;
  userId: number;
  username: string;
  email: string;
  rol: string;
  refreshToken: string;
}
```

- [ ] **Step 2: Store it on login**

In `src/features/auth/pages/LoginPage.tsx`, in `handleLogin`:

```ts
      const { token, refreshToken, userId, username: name, email, rol } = await authService.login(username, password);
      localStorage.setItem('isAuthenticated', 'true');
      localStorage.setItem('userRole', rol === 'CLIENTE' ? 'client' : rol === 'SUDO' ? 'sudo' : 'admin');
      localStorage.setItem('userName', name);
      localStorage.setItem('userEmail', email);
      localStorage.setItem('userId', String(userId));
      localStorage.setItem('authToken', token);
      localStorage.setItem('refreshToken', refreshToken);
```

- [ ] **Step 3: Manual verification**

Run both apps (`mvn spring-boot:run` in the backend, `npm run dev` here), log in through the UI, and confirm in devtools → Application → Local Storage that `refreshToken` is now populated. Simulate an expiry by editing `authToken` in devtools to a garbage value and reloading — the app should silently recover instead of bouncing to `/login`.

- [ ] **Step 4: Commit**

```bash
git add src/features/auth/services/index.ts src/features/auth/pages/LoginPage.tsx
git commit -m "feat: store refresh token on login"
```

---

### Task 7: Frontend — configurable brand name and default color scheme

**Files:**
- Modify: `src/features/auth/pages/LoginPage.tsx`
- Modify: `src/shared/components/layout/MainLayout.tsx`
- Modify: `src/shared/components/layout/LeftBar/LeftBar.tsx`
- Modify: `src/features/settings/pages/SettingsPage/SettingsPage.tsx`
- Modify: `src/lib/config.ts`
- Modify: `src/app/main.tsx`

No test — these are one-line string/constant swaps with no branching logic (trivial, per this plan's own testing bar).

- [ ] **Step 1: Wire the existing `config.appName` into the 4 live hardcoded spots**

`src/features/auth/pages/LoginPage.tsx` — add `import { config } from '../../../lib/config';`, then:
- line `<span className="font-display text-xl font-extrabold">BudgEase</span>` → `{config.appName}`
- line `<div className="relative px-12 pb-10 text-[12.5px] text-white/30">© 2026 BudgEase</div>` → `` {`© 2026 ${config.appName}`} ``

`src/shared/components/layout/MainLayout.tsx` — change `titles[path] || 'BudgEase'` to `titles[path] || config.appName` (add the same import).

`src/shared/components/layout/LeftBar/LeftBar.tsx` — change `<h1 ...>BudgEase</h1>` to `<h1 ...>{config.appName}</h1>` (add the same import).

`src/features/settings/pages/SettingsPage/SettingsPage.tsx` — change `Personaliza tu experiencia en BudgEase` to `` {`Personaliza tu experiencia en ${config.appName}`} `` (add the same import).

- [ ] **Step 2: Add a per-deployment default color scheme**

In `src/lib/config.ts`:

```ts
export const config = {
  apiUrl: import.meta.env.VITE_API_URL || 'http://localhost:8080/api',
  appName: import.meta.env.VITE_APP_NAME || 'Sistema Financiero',
  defaultColorScheme: import.meta.env.VITE_DEFAULT_COLOR_SCHEME || 'default',
};
```

In `src/app/main.tsx`, replace the two hardcoded `'default'` fallbacks (lines ~22 and ~26) with `config.defaultColorScheme` (import `config` from `../lib/config`) — a user who later picks a scheme in Preferencias still overrides this via their saved preference; this only changes the fallback for a fresh browser with nothing saved yet.

- [ ] **Step 3: Manual verification**

Set `VITE_APP_NAME="Acme Finanzas"` and `VITE_DEFAULT_COLOR_SCHEME=blue` in `.env`, run `npm run dev`, confirm the login screen and sidebar now say "Acme Finanzas" and the accent color is blue on first load (clear localStorage first to see the fallback, not a saved preference). Revert `.env` afterward if it shouldn't be committed with those values.

- [ ] **Step 4: Commit**

```bash
git add src/features/auth/pages/LoginPage.tsx src/shared/components/layout/MainLayout.tsx \
        src/shared/components/layout/LeftBar/LeftBar.tsx \
        src/features/settings/pages/SettingsPage/SettingsPage.tsx \
        src/lib/config.ts src/app/main.tsx
git commit -m "feat: make brand name and default color scheme configurable per deployment"
```

---

## What's deliberately left out (ponytail: question it)

- **No proactive expiry timer/polling.** The 401-retry-and-refresh in Task 5 is reactive and sufficient; a background interval would be one more moving part for no real gain. Add one only if a page needs to detect expiry *without* making an API call.
- **No full white-label re-theming.** The existing `data-color-scheme` mechanism only remaps the two accent colors (`#8A5CF6`/`#F26D5B`); the base near-black background (`#08080B` etc.) and the light-theme override in `globals.css` stay fixed. Re-theming those would mean redoing that CSS file's selector-remap trick for a new base palette — only worth it when an actual buyer asks for it.
- **No `AuthController` test.** It's pure delegation to the now-tested `AuthServiceImpl`; nothing to assert beyond "the two methods get called," which Task 1's tests already cover at the layer that matters.
- **CLAUDE.md's brand-color section (`#F05984`/`#BC455F`/`#6E4068`) is stale** — the code actually uses `#8A5CF6`/`#F26D5B`. Worth a doc fix, but out of scope here since it's just documentation drift, not code.
