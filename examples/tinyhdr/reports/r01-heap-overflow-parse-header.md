Subject: Heap buffer overflow in parse_header() with long header values
From: Lena Ortiz <lena@example.net>
Date: 2026-10-28

Hi tinyhdr team,

`parse_header()` allocates `HDR_VALUE_MAX` (64) bytes for the value but copies `strlen(value) + 1`
bytes without checking the length (src/tinyhdr.c:29). Any header value longer than 63 bytes writes past
the heap buffer. Tested on tinyhdr 1.4.2 (commit 3f9c2ab).

Impact: an attacker who controls a header line (every HTTP client/server using tinyhdr) can corrupt the
heap; at minimum a crash, possibly more.

Steps to reproduce: save as poc.c and build against the library with ASan.

```c
#include <string.h>
#include "tinyhdr.h"

int main(void)
{
    char line[200] = "X-Long: ";
    struct hdr h;
    memset(line + 8, 'A', 150);
    return parse_header(line, &h);
}
```

```sh
cc -g -fsanitize=address -Iinclude src/tinyhdr.c poc.c -o poc && ./poc
```

```
==3089202==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x506000000060 at pc 0x7fb2700f27ef bp 0x7ffd11ceb900 sp 0x7ffd11ceb0c0
WRITE of size 151 at 0x506000000060 thread T0
    #0 0x7fb2700f27ee in memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:115
    #1 0x55e5ae1416b3 in parse_header src/tinyhdr.c:29
    #2 0x55e5ae14249a in main /tmp/poc.c:9
SUMMARY: AddressSanitizer: heap-buffer-overflow in memcpy
```

Suggested fix: reject or truncate when `vlen >= HDR_VALUE_MAX`, or allocate `vlen + 1`.

Thanks,
Lena
