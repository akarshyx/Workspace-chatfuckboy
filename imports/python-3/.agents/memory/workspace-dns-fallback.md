---
name: Workspace DNS fallback
description: A Replit container resolver failure and the scoped recovery approach for the Telegram casino bot.
---

**Rule:** When the container resolver fails for public hostnames but direct TLS to a DNS-over-HTTPS service works, prefer a process-scoped, certificate-verified fallback. Do not hardcode service IPs or overwrite the workspace's global resolver.

**Why:** Telegram polling and the deposit API failed before command handlers ran; editing menu or command routes could not restore connectivity.

**How to apply:** Diagnose system DNS and direct HTTPS separately. Commands sent while polling is offline may be discarded on restart, so ask users to resend them after Telegram command registration succeeds.
