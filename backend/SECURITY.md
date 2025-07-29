# Shieldtag Backend Security Guide

This document outlines the security architecture and best practices implemented in the backend of the **Shieldtag Skill Test**. It is designed to ensure secure, stateless authentication while mitigating common web threats.

---

## 1. Token Storage Strategy

### Access Token

* Stored in **frontend memory (RAM)** only.
* **Do not store** in `localStorage` or `sessionStorage`.
* Short lifespan: **15 minutes**.
* Sent in the `Authorization` header for each request.

### Refresh Token

* Stored in **`HttpOnly`, `Secure`, `SameSite=Strict` cookies**.
* Completely **inaccessible to JavaScript**.
* Long lifespan: **7 days**.
* Automatically sent by the browser on each request.

---

## 2. Refresh Token Rotation

* The old refresh token is **validated then deleted** from the database.
* A **new refresh token is generated**, stored in the database.
* New token is returned via the `Set-Cookie` response header.
* Prevents **replay attacks** using stale refresh tokens.

---

## 3. Threat Mitigation Techniques

### Cross-Site Scripting (XSS)

* No sensitive tokens are exposed in browser storage.
* Uses **Content-Security-Policy (CSP)** via Helmet.
* Strict **input validation** using `express-validator`.

### Man-in-the-Middle (MITM) Attacks

* All API communication must go through **HTTPS**.
* Refresh cookies configured with:

  * `HttpOnly`
  * `Secure`
  * `SameSite=Strict`

### Brute Force Attacks

* **Rate limiting** by IP and/or email using `rate-limiter-flexible` with Redis.
* Lock account after multiple failed login attempts.

### Token Theft

* **Access tokens are short-lived** and not persistent.
* **Refresh tokens are single-use**, rotated on each refresh.
* Whitelist system implemented in the database for refresh token validation.

---

## 4. Frontend Best Practices

* Store access tokens in **memory only**.
* Use **Axios interceptors**:

  * On `401 Unauthorized` → attempt token refresh → retry the original request.
* Never expose refresh tokens to JavaScript.
* On logout:

  * Invalidate refresh token in the database.
  * Clear cookies via `Set-Cookie`.