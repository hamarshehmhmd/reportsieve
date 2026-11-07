Subject: use-after-free in hdr_remove()
From: Tomás Reyes <treyes@example.org>
Date: 2026-11-06

`hdr_remove()` frees the node and then reads `h->next` (src/tinyhdr.c:67). Removing any header that
isn't the last in the list reads freed memory. Found while fuzzing tinyhdr 1.4.2 with libFuzzer + ASan.

Impact: heap use-after-free; with a controlled allocation in between, the freed node's `next` pointer
becomes attacker-influenced.

poc.c:

```c
#include "tinyhdr.h"

int main(void)
{
    struct hdr_list l = {0};
    hdr_list_add(&l, "Host: example.org");
    hdr_list_add(&l, "Accept: */*");
    hdr_remove(&l, "Accept");
    return 0;
}
```

Fix: save `h->next` before freeing.
