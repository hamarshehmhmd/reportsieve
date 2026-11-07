Subject: DoS: examples/bench.c allocates unbounded memory
From: perf-watch@example.io
Date: 2026-11-05

examples/bench.c takes N from argv and calls hdr_list_add() N times, so `./bench 100000000` exhausts
memory (denial of service). Steps to reproduce: build examples/bench.c and run it with a large N.
