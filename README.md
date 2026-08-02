# VaultAPI

A gated content API, built from scratch as a hands-on Spring Security project.

One codebase that exercises the whole stack: the security filter chain, `AuthenticationManager`, JWT access tokens, refresh tokens with rotation, server-side session management, role-based authorization, and plan-based method security.

> **This is a learning repo.** Every milestone is built by hand, in order, with a passing `curl` before moving on.

---

## The product

Users sign up, log in from multiple devices, and read/write posts.

- **Roles** decide what you can *do* — `USER`, `CREATOR`, `ADMIN`
- **Plans** decide how much you *get* — `FREE`, `BASIC`, `PREMIUM`
- **Sessions** are tracked per device, so logout and device limits actually work

Roles and plans are deliberately separate. A `FREE` **ADMIN** and a `PREMIUM` **USER** are both valid states. That separation is what forces authorization (`hasRole`) to stay distinct from entitlement (`@PreAuthorize` + a custom checker bean).

---

## Tech

| | |
|---|---|
| Java | 21 |
| Spring Boot | 3.x |
| Spring Security | 6.x |
| Persistence | Spring Data JPA + PostgreSQL |
| Tokens | JJWT (`io.jsonwebtoken`) |
| Build | Maven |

---

## Entities

Required fields. Mapping decisions are part of the exercise.

```
UserEntity      id, username (unique), email, password (bcrypt),
                Set<Roles> roles (@ElementCollection), plan, planExpiresAt

SessionEntity   id, tokenHash (unique index), user (@ManyToOne),
                deviceLabel, lastUsedAt, expiresAt

PostEntity      id, title, body, author (@ManyToOne), premiumOnly (boolean)
```

Device limit is derived from the plan — `FREE=1`, `BASIC=2`, `PREMIUM=5` — rather than stored per user. If you choose an override column instead, record the reason in `docs/decisions.md`.

---

## Endpoints

| Method | Path | Auth | Rule |
|---|---|---|---|
| POST | `/auth/signup` | none | always creates `FREE` + `ROLE_USER` |
| POST | `/auth/login` | none | returns AT, sets RT cookie, creates session |
| POST | `/auth/refresh` | RT cookie | rotates AT + RT, updates session |
| POST | `/auth/logout` | RT cookie | deletes session, clears cookie |
| POST | `/auth/logout-all` | AT | deletes every session for the user |
| GET | `/auth/sessions` | AT | list own live sessions |
| GET | `/posts` | AT | any authenticated user |
| GET | `/posts/{id}` | AT | `premiumOnly` posts require `PREMIUM` |
| POST | `/posts` | AT | `hasAnyRole('CREATOR','ADMIN')` |
| PUT | `/posts/{id}` | AT | author **or** `ADMIN` |
| DELETE | `/posts/{id}` | AT | `ADMIN` only |
| GET | `/admin/users` | AT | `ADMIN` only |
| PUT | `/admin/users/{id}/plan` | AT | `ADMIN` only |
| GET | `/me` | AT | own profile, plan, session count |

Three authorization mechanisms are used on purpose, one each — don't collapse them into one:

- **URL matchers** for `/admin/**` and `/auth/**`
- **`hasAnyRole`** for post creation
- **`@PreAuthorize` + custom bean** for premium content and owner-or-admin

---

## Milestones

Each milestone is a branch, and each ends with a passing request.

### M1 · Bare security
`UserEntity implements UserDetails`, `UserDetailsService`, `PasswordEncoder`, `AuthenticationManager` bean, `/auth/signup`, `/auth/login` (no token yet — return the user).

**Done:** wrong password returns `401` with a JSON body, not a stacktrace.
**Trace it:** which class compared the password? Follow `authenticate()` → `AuthenticationProvider` → `UserDetailsService`.

### M2 · Access token + filter
`JwtService`, `JwtAuthFilter extends OncePerRequestFilter`, `SessionCreationPolicy.STATELESS`, registered with `addFilterBefore(..., UsernamePasswordAuthenticationFilter.class)`.

**Done:**
```bash
curl -i localhost:8080/posts                                  # 401
curl -i localhost:8080/posts -H "Authorization: Bearer $AT"   # 200
```

### M3 · Error handling — before refresh, not after
try/catch around JWT parsing inside the filter, plus `authenticationEntryPoint` (401) and `accessDeniedHandler` (403).

**Done:** expired token returns `401 {"error":"Access token expired"}`. Tampered token returns 401. Never a 500.

Do this before M4. Skipping it makes every later milestone undebuggable, because a broken refresh flow and a broken filter look identical from the client side.

### M4 · Refresh token, typed and cookied
A `tokenType` claim (`access` | `refresh`), AT 15 min / RT 7 days, `ResponseCookie` named `refreshToken` with `HttpOnly + Secure + SameSite=Strict + Path=/auth`.

**Done:** sending an **access** token to `/auth/refresh` returns 401 for wrong token type. The cookie name written at login is the exact name read at refresh.

### M5 · Sessions
`SessionEntity` with `tokenHash` = SHA-256 of the RT, unique index, `@UpdateTimestamp` on `lastUsedAt`, `expiresAt` mirroring the RT's `exp`.

**Done:**
```sql
DELETE FROM session_entity WHERE id = 1;
```
then refresh with that RT → **401**, even though the JWT still verifies perfectly. That one test is the proof that revocability exists.

### M6 · Logout
`/auth/logout` deletes the session row and clears the cookie with `maxAge(0)` using the **same** `path` and `domain` it was set with. Plus `/auth/logout-all` and `GET /auth/sessions`.

**Done:** logout, then refresh with the same RT → 401. Cookie gone from the jar. A second logout call still returns 204 (idempotent).

### M7 · Refresh token rotation
Every `/refresh` and `/login` issues a fresh AT + RT and retires the old session row. A rotated-away RT is treated as theft.

**Done:**
```
RT1 -> /refresh -> 200, returns RT2
RT1 -> /refresh -> 401 reuse detected, user's whole session family revoked
RT2 -> /refresh -> 401 (family already revoked)
```

**Decide and document:** does `/login` rotate an existing session or create a new one? "Delete the session on every new login" conflicts with multi-device support. Pick one, write why in `docs/decisions.md`.

### M8 · Device limit
Limit read from the user's plan. LRU eviction sorted by `lastUsedAt`. `@Transactional` around the check-delete-insert.

**Done:** a `FREE` user (limit 1) logs in on device B, and device A's RT stops working. Upgrade to `PREMIUM`, log in on 5 devices, all 5 refresh fine.

### M9 · Plans + method security
`@EnableMethodSecurity`, a plan hierarchy `FREE < BASIC < PREMIUM`, and a custom checker bean:

```java
@PreAuthorize("@plans.atLeast(authentication, 'PREMIUM')")
@PreAuthorize("@posts.isAuthorOrAdmin(authentication, #id)")
```

The checker must verify `planExpiresAt` — an expired `PREMIUM` is a `FREE` user.

**Done:** a `PREMIUM` user reads a `premiumOnly` post → 200. Backdate `planExpiresAt` in SQL → 403 with an upgrade hint. A `BASIC` user → 403. An admin changes the plan via `/admin/users/{id}/plan` and the effect lands on the next request.

---

## Constraints

The grading rubric. Each line is a real bug that shows up in hand-rolled Spring Security code.

1. No secret in source. `jwt.secret` comes from `application.yaml` backed by an env var.
2. Never store a raw refresh token. Store a hash.
3. Never return 500 for an auth problem. `401` for unknown or expired, `403` for known but forbidden.
4. `SignUpDto` must **not** accept `roles` or `plan` from the client.
5. `anyRequest().denyAll()` as the fallback, not `authenticated()`.
6. `EnumType.STRING` everywhere, never `ORDINAL`.
7. Enum collections need `@ElementCollection` + `@CollectionTable`.
8. `@Transactional` on every read-check-write (session eviction, rotation).
9. At most one DB read per authenticated request — and you can explain why it's there.
10. Every endpoint has a test for the allow path **and** the deny path.

---

## Test matrix

| Scenario | Expect |
|---|---|
| no token | 401 |
| malformed token | 401 |
| expired access token | 401 |
| valid AT, wrong role | 403 |
| valid AT, insufficient plan | 403 + upgrade hint |
| valid AT, expired plan | 403 |
| refresh using an access token | 401 |
| refresh using a revoked RT | 401 |
| refresh using a rotated-away RT | 401 + family revoked |
| login past the device limit | oldest session dies, new one works |
| logout, then refresh | 401 |
| author edits own post | 200 |
| another user edits that post | 403 |
| admin edits any post | 200 |

The deny rows matter more than the allow rows. A security bug is always a missing deny.

---

## Layout

```
src/main/java/...            application code
docs/decisions.md            every "I chose X because Y"
docs/threat-notes.md         what each control blocks, and what it doesn't
README.md                    this file
```

Write `docs/decisions.md` as you go, not afterwards. The three decisions worth recording first:

- roles read from the DB vs trusted from the JWT claim
- refresh token expiry: sliding or absolute
- `/login` rotates an existing session vs creates a new one

---

## Running locally

```bash
createdb vaultapi
export JWT_SECRET="change-me-to-at-least-32-bytes-long"
./mvnw spring-boot:run
```

---

## Stretch goals

Only after M9 is green.

- `deviceLabel` derived from `User-Agent`, so `/auth/sessions` is readable
- rate-limit `/auth/login` per username — brute force is the hole none of the above closes
- per-plan API quota (`FREE` = 100/day) enforced in a filter, counted in Redis
- audit table: login, logout, refresh, reuse-detected, plan change
- a `RoleHierarchy` bean so `ADMIN` implies `CREATOR` implies `USER`
