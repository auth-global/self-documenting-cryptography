* Improve Instances

* Add bindings for serializing/deserializing Sha256State and Sha256Ctx

* HKDF Support

* PBKDF2 Support

* Better support for hashing things other than ByteStrings

* Add tests

   * ensure that the comparison for Sha256State provides the same ordering
     as serializing the states and then doing an normal lexicographic comparison
     on the result.

   * other tests regarding comparisons

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

   * Ensure reasonable-to-excellent support for vectorization.

   * Support native SHA256 instructions when available.