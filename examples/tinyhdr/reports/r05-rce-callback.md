Subject: Remote Code Execution via tinyhdr_exec_callback() — CVSS 9.8
From: bounty.hunter.4471@example.com
Date: 2026-11-05

Dear Security Team,

I hope this email finds you well. I have identified a critical remote code execution vulnerability in
tinyhdr that could potentially allow an attacker to execute arbitrary commands on any server using the
library.

The function `tinyhdr_exec_callback()` in `src/callback.c` passes header values directly to `system()`
without sanitization. If an attacker were to send a crafted `X-Callback` header, it is possible that
arbitrary shell commands would be executed with the privileges of the server process. In theory this
could be exploited remotely without authentication.

It is important to note that this represents a severe risk. I recommend a thorough analysis of all
callback handlers and leveraging robust input validation as a mitigation strategy.

Severity: Critical (CVSS 9.8)

I would be happy to assist further. Please let me know about the bounty.
