Subject: hdr_get() crashes on NULL name
From: dev@example.dev
Date: 2026-11-06

hdr_get() passes `name` straight to strcasecmp, so calling it with a NULL name is a NULL pointer
dereference. I hit this in our proxy when a lookup key was missing, the worker crashed.

Expected: return NULL. Actual: segfault in hdr_get().
