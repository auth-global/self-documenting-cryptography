# Revision history for sha256

## 0.1.0.0 -- 2025-01-20

* Rewrite of the FFI portions of the cryptohash-sha256 bindings, in order
  to support precomputed HMAC keys, more efficient streaming and backtracking,
  bitstring inputs, (de)serialization of intermediate states, intermediate
  bytecounts, and more.
