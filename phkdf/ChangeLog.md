# Revision history for phkdf

## Version 0.1.0.0 (2025-01-20)

*  This includes the Version 2 of PHKDF, which is mostly compatible with
   Version 1 except that the slow extract function has been removed and the
   end-of-message padding has been tweaked to save a byte when the domain tag
   is 20 bytes or longer. A simpler slow-extract function much closer to PBKDF2
   will eventually be factored out of g3p-hash version 2.

*  Saving this byte requires bitstring SHA256 inputs, thus the binding has been
   moved from cryptohash-sha256 to the new sha256 package. This is a new FFI
   binding around the core cryptohash implementation that better and more
   robustly supports the needs of this library.

*  The old code in Crypto.PHKDF has been moved to Crypto.PHKDF.V1.Cookbook

## Version 0.0.0.0 (2024-03-21)

*  The definition of Crypto.PHKDF.Primitives is quite stable.

*  Note that Crypto.PHKDF is intended to be more of a cookbook demonstrating
   how to use and understand PHKDF than anything intended to be deployed.
   The definition and results, and possibly the interface of phkdfSimple and
   phkdfHardened will be completely revamped for Version 0.1
