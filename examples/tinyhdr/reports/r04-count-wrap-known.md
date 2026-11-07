Subject: Integer overflow of hdr_list count in hdr_list_add()
From: m.ivanova@example.edu
Date: 2026-11-03

`hdr_list_add()` increments `l->count`, an `unsigned short`, with no limit. After 65536 headers the counter
wraps to 0, and code that sizes arrays from `count` under-allocates. Impact: out-of-bounds write in
callers that trust `count`. Seen on tinyhdr 1.4.0.
