---
name: NOWPayments test mode
description: Clarifies NOWPayments' use of “Sandbox” and how to handle payment testing safely.
---

NOWPayments uses “Sandbox” to refer to the SAND cryptocurrency, not a separate test API environment. Verify current provider documentation before assuming an API key is test-only.

**Why:** The casino integration sends requests to the production API; confusing the SAND asset with a sandbox environment could accidentally create real payment requests.

**How to apply:** Before using payment credentials, confirm the provider's current test-mode behavior and get explicit user approval before enabling live transactions.
