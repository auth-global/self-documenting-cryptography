* Improve Instances

* Clean up warnings

* Clean up magic constants, replace with symbolic references

* Prepare for Release

    * Headers on all files

    * Fill in at least some of the missing documentation

* Rewrite top-level HKDF functions into a (relatively) point-free style, a la G3Pb2

   * We want to ensure that a reused partial application is as efficient as possible,
     so at least 1 point (i.e. named argument) per function should be "acceptable", and
     sometimes more.

* Rewrite top-level PBKDF2 functions into a (relatively) point-free style, a la G3Pb2

* Support for Mutable Contexts and States

   * Modify the sha256_updates and sha256_feeds functions to make use of this

   * Modify the PBKDF2 binding to make use of this.

* Better support for hashing things other than ByteStrings

* Add tests

   * throughly exercise the buffer-handling code

   * Implement the NIST test suite

   * Random testing against e.g. sha256sum and other implementations

* Single interface, multiple backends? (But maintain a capability of static compilation)

   * An implementation in terms of SmallArray instead of ByteArray

      * Main payoff would be the possibility of using shrinkSmallMutableArray#

      * What are the tradeoffs, especially with regard to availability?

      * Consider making this default.

   * Enable fine-grained parallel testing, to achieve an effect not unlike
     what (temporarily) existed (poorly) in the debugging code for sha256

   * Add support for web browsers via web assembly

   * Ensure reasonable-to-excellent support for vector instructions.

   * Support native SHA256 instructions when available.