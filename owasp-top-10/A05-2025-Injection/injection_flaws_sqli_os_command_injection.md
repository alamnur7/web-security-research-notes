# Vulnerability Research: Injection Flaws (SQL Injection & OS Command Injection)

## 1. Overview & Impact

* **Vulnerability Type:** Injection Flaws — SQL Injection & OS Command Injection (OWASP A03)

* **Severity:** Critical

* **Description:** Injection vulnerabilities occur when untrusted user-supplied data is sent directly to an interpreter (such as a SQL database engine or an operating system shell) as part of a command or query without proper separation between data and executable instructions.

* **Impact:**

  * Complete unauthorized read, modification, or deletion of sensitive database records (SQL Injection).

  * Arbitrary operating system command execution on the host server, leading to full server compromise (OS Command Injection).

  * Authentication bypass and lateral movement across internal infrastructure.

## 2. Attack Architecture (Mermaid Diagram)

```mermaid
sequenceDiagram
    participant Attacker as Penyerang (Attacker)
    participant WebApp as Vulnerable Web Application
    participant Interpreter as Database / OS Shell

    Attacker->>WebApp: Kirim payload berbahaya (cth: ' OR 1=1 -- atau ; cat /etc/passwd)
    Note over WebApp: Aplikasi menggabungkan input langsung ke string perintah (Concatenation)
    WebApp->>Interpreter: Eksekusi query / perintah shell yang telah termanipulasi
    Interpreter-->>WebApp: Mengembalikan seluruh data sensitif / output sistem operasi
    WebApp-->>Attacker: Eksfiltrasi data / Remote Code Execution (RCE)
```

## 3. Common Weaknesses & Misconfigurations

1. **Dynamic Query String Concatenation (SQLi):** Building SQL queries by concatenating raw user input directly into query strings instead of using parameterized statements or prepared queries.

2. **Unsafe OS Command Execution:** Passing unvalidated user input into system execution functions (such as `Runtime.getRuntime().exec()` or `ProcessBuilder` with shell wrappers like `/bin/sh -c`).

3. **Reliance on Blocklist Filtering:** Attempting to sanitize injection payloads by blocking specific characters or keywords (e.g., stripping `'`, `;`, or `SELECT`), which attackers can easily bypass using encoding or alternative syntax.

## 4. Code Comparison: Vulnerable vs Secure Implementation (Java Spring Boot)

### ❌ Vulnerable Implementation

```java
// BERBAHAYA: Menggabungkan input pengguna langsung ke dalam query SQL
public User findUserByUsername(String username) throws SQLException {
    String query = "SELECT id, username, role FROM users WHERE username = '" + username + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);
    return mapToUser(rs);
}
```

### ✅ Secure Implementation & Mitigation

```java
// AMAN: Menggunakan Parameterized Query (PreparedStatement) sehingga input diperlakukan murni sebagai data
public User findUserByUsernameSecure(String username) throws SQLException {
    String query = "SELECT id, username, role FROM users WHERE username = ?";
    PreparedStatement pstmt = connection.prepareStatement(query);
    pstmt.setString(1, username);
    ResultSet rs = pstmt.executeQuery();
    return mapToUser(rs);
}
```

## 5. Key Defense Strategies

* **Use Parameterized Queries (Prepared Statements):** Always separate query structure from user data using parameterized queries or secure ORM abstractions (e.g., Spring Data JPA named parameters).

* **Avoid OS Shell Execution & Enforce Allowlists:** Avoid calling OS commands directly from application code. When strictly necessary, pass arguments as discrete array elements via `ProcessBuilder` without invoking a shell, and validate inputs against a strict allowlist.

* **Enforce Least Privilege on Database & Service Accounts:** Restrict database users and application runtime accounts so that even if an injection occurs, the attacker cannot execute administrative commands or access unrelated tables.