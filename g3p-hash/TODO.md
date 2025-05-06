* Fix Haddock documentation
    * documentation at the start of a module seems to be often missing
        * https://hackage.haskell.org/package/g3p-hash-2.0.0.0/docs/Crypto-G3P-V2.html
	* https://hackage.haskell.org/package/g3p-hash-2.0.0.0/docs/Crypto-G3P-V1.html
	* https://hackage.haskell.org/package/g3p-hash-2.0.0.0/docs/Crypto-G3P-BCrypt.html

* Write tests for blowfishRevexpand, blowfishTranscode, blowfishEncode, blowfishDecode, blowfishDecryptECB64

* Demo controlling bcryptXs's final state for a chosen pair of inputs using
  blowfishTranscode, salt0, saltL, and saltR

* Demo controlling bcryptXs's final output for a chosen pair of inputs using
  blowfishDecryptECB64 and saltZ

* Either finish the haskell implementation of bcryptXs's outer loop, or move
  that to the test suite.