Bitcoin Core snapshot fuzzing
=============================

This repository contains code that can be used to run kAFL/Nyx-based snapshot
fuzzers on the Bitcoin Core codebase. The fuzz test is a normal bitcoind fuzz test
except that it calls into a hypercall API for VM snapshot/restore functionality
(see: https://intellabs.github.io/kAFL/reference/hypercall_api.html and
https://github.com/AFLplusplus/AFLplusplus nyx_mode). The install.sh script performs
the following:
- fetches a snapshot-compatible fuzz test from a remote bitcoin/bitcoin branch
- builds a Nyx "share directory"
- links the agent code
- runs snapshot-based fuzzing

This is slightly different than the Nyx-based snapshot fuzzing done in [fuzzamoto](https://github.com/dergoegge/fuzzamoto)
as these tests have more access to internal bitcoind state. Each approach has its
advantages and disadvantages. The advantage with the approach in this repo is
that we can fuzz internal state in Core better and still use snapshot fuzzing for
expensive setup. The downside is that we pollute Core a bit more with yet another
fuzzing engine and we have to modify it rather than externally testing it.

Credit: This is mostly Niklas' code and I am simply packaging it for my own use.
