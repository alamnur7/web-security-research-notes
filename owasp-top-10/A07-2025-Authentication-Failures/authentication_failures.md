# Vulnerability Research: Authentication Failures

## 1. Overview & Impact

* **Vulnerability Type:** Identification and Authentication Failures (OWASP A07)

* **Severity:** High / Critical

* **Description:** Authentication failures occur when functions related to user identity, authentication, and session management are implemented incorrectly or insecurely. This allows attackers to compromise passwords, keys, or session tokens, or exploit implementation flaws to assume other users' identities temporarily or permanently.

* **Impact:**

  * **Full Account Takeover (ATO):** Attackers gain complete control over victim accounts via credential stuffing, brute-forcing, or password reset flaws.

  * **Credential Exposure:** User credentials exposed through predictable session identifiers, weak password policies, or transmission over unencrypted channels.

  * **Automated Abuse:** Unprotected endpoints allowing rapid bot-driven automated login attacks.

## 2. Attack Architecture (Mermaid Diagram)

```
sequenceDiagram
    participant Attacker as Penyerang (Attacker)
    participant API as Vulnerable Auth API
    participant DB as User Database

    Attacker->>API: Kirim ribuan kombinasi password (Credential Stuffing / Brute-Force)
    Note over API: Tanpa Rate Limiting, Account Lockout, atau Captcha
    API->>DB: Query verifikasi password berulang kali tanpa batas
    DB-->>API: Respons login gagal / berhasil
    API-->>Attacker: 200 OK (Akun berhasil dibobol tanpa pembatasan)

```

## 3. Common Weaknesses & Misconfigurations

1. **Lack of Rate Limiting & Account Lockout:** Allowing unlimited login attempts or password reset requests from a single IP or user account without throttling, CAPTCHA, or temporary lockouts.

2. **Weak Password Policies & Credential Stuffing Vulnerabilities:** Permitting weak, default, or breached passwords (e.g., `Password123`) without checking against known compromise databases (HaveIBeenPwned).

3. **Insecure Session Management:** Generating predictable session tokens (weak PRNG), failing to expire sessions upon logout, or omitting `HttpOnly`, `Secure`, and `SameSite` flags on authentication cookies.

## 4. Code Comparison: Vulnerable vs Secure Implementation (Java Spring Boot)

### ❌ Vulnerable Implementation

```
// BERBAHAYA: Tidak ada rate limiting, tidak ada proteksi brute-force, & pesan error yang terlalu spesifik
@PostMapping("/api/v1/login")
public ResponseEntity<String> login(@RequestBody LoginRequest request) {
    Optional<User> userOpt = userRepository.findByUsername(request.getUsername());
    if (userOpt.isEmpty()) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found!"); // Bocorkan info user existence
    }
    User user = userOpt.get();
    if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid password!");
    }
    return ResponseEntity.ok("Login successful. Token: " + generateToken(user));
}

```

### ✅ Secure Implementation & Mitigation

```
// AMAN: Menggunakan rate limiting terintegrasi, pesan error generik (cegah username enumeration), & multi-factor validation
@PostMapping("/api/v1/login")
public ResponseEntity<Map<String, String>> loginSecure(
        @RequestBody LoginRequest request,
        HttpServletRequest httpRequest) {
    
    // 1. Validasi Rate Limiting berdasarkan IP / Username
    if (rateLimiterService.isRateLimited(httpRequest.getRemoteAddr())) {
        securityLogger.warn("SECURITY_EVENT=RATE_LIMIT_EXCEEDED ip={}", httpRequest.getRemoteAddr());
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
            .body(Map.of("error", "Too many login attempts. Please try again later."));
    }
    
    // 2. Gunakan pesan error generik untuk mencegah User Enumeration
    boolean authenticated = authService.authenticate(request.getUsername(), request.getPassword());
    if (!authenticated) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(Map.of("error", "Invalid username or password"));
    }
    
    String secureToken = tokenService.generateSecureToken(request.getUsername());
    return ResponseEntity.ok(Map.of("token", secureToken));
}

```

## 5. Key Defense Strategies

* **Enforce Multi-Factor Authentication (MFA):** Implement mandatory or opt-in MFA (TOTP, WebAuthn/FIDO2) to prevent account takeover even if primary credentials are compromised.

* **Implement Robust Rate Limiting & Account Lockout:** Protect authentication, password reset, and registration endpoints with rate limiters, CAPTCHAs, and temporary account lockout policies after consecutive failed attempts.

* **Standardize Generic Error Messages:** Avoid revealing whether a username exists during failed login or password recovery flows to prevent user enumeration attacks.