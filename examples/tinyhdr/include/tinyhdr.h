/* tinyhdr: a deliberately buggy toy HTTP-style header parser used by the reportsieve demo. Do not use. */
#ifndef TINYHDR_H
#define TINYHDR_H
#include <stddef.h>

#define HDR_NAME_MAX 32
#define HDR_VALUE_MAX 64

struct hdr {
    char name[HDR_NAME_MAX];
    char *value;
    struct hdr *next;
};

struct hdr_list {
    struct hdr *head;
    unsigned short count;
};

int parse_header(const char *line, struct hdr *out);
int hdr_list_add(struct hdr_list *l, const char *line);
const char *hdr_get(const struct hdr_list *l, const char *name);
int hdr_remove(struct hdr_list *l, const char *name);
void hdr_list_free(struct hdr_list *l);

#endif
