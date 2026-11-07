/* tinyhdr: a deliberately buggy toy HTTP-style header parser used by the reportsieve demo. Do not use. */
#include "tinyhdr.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

int parse_header(const char *line, struct hdr *out)
{
    const char *colon = strchr(line, ':');
    size_t nlen, vlen;

    if (!colon)
        return -1;
    nlen = (size_t)(colon - line);
    if (nlen >= HDR_NAME_MAX)
        return -1;
    memcpy(out->name, line, nlen);
    out->name[nlen] = '\0';

    colon++;
    while (*colon == ' ')
        colon++;
    vlen = strlen(colon);
    out->value = malloc(HDR_VALUE_MAX);
    if (!out->value)
        return -1;
    /* BUG (demo): no check that vlen < HDR_VALUE_MAX */
    memcpy(out->value, colon, vlen + 1);
    out->next = NULL;
    return 0;
}

int hdr_list_add(struct hdr_list *l, const char *line)
{
    struct hdr *h = calloc(1, sizeof(*h));
    if (!h)
        return -1;
    if (parse_header(line, h) != 0) {
        free(h);
        return -1;
    }
    h->next = l->head;
    l->head = h;
    l->count++; /* BUG (demo, already fixed upstream in 1.4.1 advisory): unsigned short wraps */
    return 0;
}

const char *hdr_get(const struct hdr_list *l, const char *name)
{
    const struct hdr *h;
    for (h = l->head; h; h = h->next)
        if (strcasecmp(h->name, name) == 0)
            return h->value;
    return NULL;
}

int hdr_remove(struct hdr_list *l, const char *name)
{
    struct hdr **pp = &l->head;
    while (*pp) {
        struct hdr *h = *pp;
        if (strcasecmp(h->name, name) == 0) {
            free(h->value);
            free(h);
            /* BUG (demo): reads h after free */
            *pp = h->next;
            l->count--;
            return 0;
        }
        pp = &h->next;
    }
    return -1;
}

void hdr_list_free(struct hdr_list *l)
{
    struct hdr *h = l->head, *n;
    while (h) {
        n = h->next;
        free(h->value);
        free(h);
        h = n;
    }
    l->head = NULL;
    l->count = 0;
}
