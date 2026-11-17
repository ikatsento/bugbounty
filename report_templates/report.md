# [Component] — [Vulnerability Type] leads to [Impact]

**Platform:** HackerOne / Bugcrowd / Intigriti  
**Program:** Target Program Name  
**Submitted:** YYYY-MM-DD  
**Severity:** Critical / High / Medium / Low  
**CVSS Score:** X.X (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)  
**CWE:** CWE-XXX — Vulnerability Name  

---

## Summary

One paragraph (2–4 sentences): what is vulnerable, what an attacker can do,
and the business impact. No jargon. Write as if the triage team has 10 seconds.

**Example:**  
> The `/api/v1/users/{id}` endpoint fails to verify that the authenticated user owns
> the requested object, allowing any authenticated user to access or modify any other
> user's account data by incrementing the numeric ID. An attacker with a free account
> can harvest all user emails and PII, or take over any account without knowing their
> password.

---

## Vulnerability Details

**Endpoint:** `GET /api/v1/users/{id}`  
**Parameter:** Path parameter `id`  
**Attack Type:** IDOR (Broken Object Level Authorization)  

Explain the root cause in 2–3 sentences. Reference the specific code/behavior
that is wrong (e.g., "the endpoint queries by user ID without checking ownership").

---

## Steps to Reproduce

> Prerequisites: Two accounts — Account A (attacker) and Account B (victim)

1. Log in as Account A
2. Visit `https://target.com/profile` and note your user ID in the URL or API response (e.g., `id=1001`)
3. Send the following request:
   ```
   GET /api/v1/users/1002 HTTP/1.1
   Host: target.com
   Authorization: Bearer <Account_A_token>
   ```
4. Observe that the response contains Account B's email, name, and address
5. To confirm account takeover, send:
   ```
   PATCH /api/v1/users/1002 HTTP/1.1
   Host: target.com
   Authorization: Bearer <Account_A_token>
   Content-Type: application/json

   {"email": "attacker@evil.com"}
   ```
6. Request password reset for `attacker@evil.com` → full account takeover

---

## Proof of Concept

> Attach screenshot or video here.

```
Request:
GET /api/v1/users/1002 HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGc...

Response:
HTTP/1.1 200 OK
{
  "id": 1002,
  "email": "victim@example.com",
  "name": "Victim User",
  "address": "123 Main St..."
}
```

**PoC video:** [Link or attach]

---

## Impact

Describe the worst-case scenario an attacker can achieve:

- **Confidentiality:** Access all users' PII, emails, addresses (affects all N users)
- **Integrity:** Modify any user's email/password → full account takeover
- **Availability:** Delete user accounts (if DELETE endpoint also unprotected)

> An unauthenticated / low-privilege attacker can enumerate all user accounts
> by iterating over integer IDs, collecting emails for phishing, or taking over
> accounts to access linked payment methods.

---

## Suggested Remediation

1. **Primary fix:** Verify that `request.user.id == requested_id` before returning data
2. **Defense in depth:** Use UUIDs instead of sequential integer IDs
3. **Monitoring:** Alert on unusual ID access patterns (e.g., one token accessing 100+ different IDs)

**Secure code example:**
```python
# Before (vulnerable)
def get_user(user_id):
    return db.query(User).filter_by(id=user_id).first()

# After (secure)
def get_user(user_id, requesting_user):
    user = db.query(User).filter_by(id=user_id).first()
    if not user or user.id != requesting_user.id:
        raise PermissionError("Access denied")
    return user
```

---

## References

- [OWASP API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [PortSwigger IDOR](https://portswigger.net/web-security/access-control/idor)

---

*Report submitted via HackerOne. All testing performed against the program's in-scope assets
using my own test accounts. No production data was accessed beyond what was necessary
to demonstrate the vulnerability.*
