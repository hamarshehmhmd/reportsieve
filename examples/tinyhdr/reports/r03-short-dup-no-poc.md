Subject: overflow when header value > 64 bytes
From: kai@example.com
Date: 2026-11-04

parse_header() mallocs 64 bytes for out->value and then memcpy's the whole value. Long values (e.g. a big
Cookie header) overflow the buffer. Version 1.4.2.
