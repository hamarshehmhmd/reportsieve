/* bench: parse N copies of a header line. Example code, not part of the library. */
#include <stdio.h>
#include <stdlib.h>
#include "tinyhdr.h"

int main(int argc, char **argv)
{
    long n = argc > 1 ? atol(argv[1]) : 1000;
    struct hdr_list l = {0};
    for (long i = 0; i < n; i++)
        hdr_list_add(&l, "X-Bench: 1");
    printf("%u\n", l.count);
    hdr_list_free(&l);
    return 0;
}
