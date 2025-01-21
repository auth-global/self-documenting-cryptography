# Revision history for sha256

## 0.1.0.2 -- 2025-01-21

* Duplicate a C function used from the hash-string package, because hackage's
  build infrastructure had a problem finding hs_hashstring_memcmp.h header file

## 0.1.0.1 -- 2025-01-20

* Original release was accidentally categorized as Graphics, not Cryptography

## 0.1.0.0 -- 2025-01-20

* Rewrite of the FFI portions of the cryptohash-sha256 bindings, in order
  to support precomputed HMAC keys, more efficient streaming and backtracking,
  bitstring inputs, (de)serialization of intermediate states, intermediate
  bytecounts, and more.
