# Asset Register & Scope Authorization Template

**Engagement Name:** Authorized Web Application Security Assessment  
**Authorized Stakeholder / Sponsor:** [Stakeholder Name / Organization]  
**Assessment Date:** [YYYY-MM-DD to YYYY-MM-DD]  
**Primary Contact (Emergency):** [Email / Phone]  

---

## 1. Authorized In-Scope Targets

| Hostname / Service | Environment | IP / URL / Identifier | Scope Notes |
|---|---|---|---|
| Main Web Application | Production / Staging | `https://example.com` | Primary user booking and discovery portal |
| Administrative Portal | Staging | `https://admin.example.com` | Admin / Staff management console |
| API Gateway | Production / Staging | `https://api.example.com` | REST / GraphQL endpoints |
| Supabase Backend | Staging | `https://xyzcompany.supabase.co` | Database REST & Storage endpoints |

---

## 2. Explicitly Out-of-Scope Assets
- Third-party payment gateways (Razorpay / Stripe hosted checkout pages, banks, UPI switches).
- Third-party email / SMS transmission infrastructure (SendGrid, Twilio, AWS SES).
- DNS registrar infrastructure, Cloudflare edge networks, and hosting platform control planes.

---

## 3. Provisioned Test Accounts

| Role | Synthetic Username / Email | Verification Mechanism | Scope Restriction |
|---|---|---|---|
| Customer A (Primary) | `test-user-a@example.internal` | Password / Magic Link | Standard user actions only |
| Customer B (Secondary) | `test-user-b@example.internal` | Password / Magic Link | Cross-user IDOR validation |
| Staff / Support | `test-staff@example.internal` | Password / Session Cookie | Role boundary testing |
| Administrator | `test-admin@example.internal` | Session Cookie | Vertical privilege validation |

---

## 4. Operational Boundaries & Testing Window
- **Rate Limit:** Not to exceed 5 requests per second per IP address.
- **Testing Hours:** 10:00 IST to 20:00 IST.
- **Destructive Actions:** Prohibited unless explicitly flagged and approved (e.g., account deletion, password reset on live accounts).
- **Emergency Circuit Breaker:** Creating `webprobe.abort` halts all scanning instantly.

