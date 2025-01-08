* Base64 encoding

   * current (untested) binding uses RFC4648 alphabet without padding

   * Need to support RFC4648's Url-safe encoding as an alternative alphabet

       * any other alphabets we should support here?

       * how do we support alternative alphabets?

   * what should we do about padding?

       * RFC 4648 is plainly wrong about requiring padding to avoid ambiguity.

       * The real advantage seems to be that if you are using padding, *and* your
         decoder supports padding in the middle of string, then you can concatinate
	 bytestrings by simply concatinating their base64-encoded parts. Without
	 padding, a simple concatination can shuffle bits between bytes, instead
	 of achieiving a concatinative homomorphism of bytes. (Alternatively, one
	 could implement a special routine to concatinate base64-encoded bytestrings
	 in a relatively direct manner, minimizing intermediate structures.)

       * The downside of allowing padding in the middle of a string is that we
         cannot deduce the length of the decoded data without counting the number
	 of padding bytes, which requires knowing something more than just the
	 length of the encoded data.

   * Hackage's "base64" library seems to be... less consistent about these issues than
     I'd prefer, e.g. version 1 seems to have either a documentation bug or a naming
     bug, doesn't offer all four options, and decodeBase64Untyped assumes one option

   * Options that seem "important" enough to support out of box:

   * generate syntax with or without padding

   * decoding gets more complicated, as there are many more options about what syntaxes
     to require/allow/prohibit.

        * Require RFC 4648 alphabet

        * Require RFC 4648 URL alphabet

        * Allow either RFC 4648's default or URL alphabets.

        * Require strict padding

        * Allow strict padding

        * Prohibit padding

        * Allow strict padding inside any 4-byte block, which enables the concatinative homomorphism.

        * More lenient forms of padding?

        * But then how do you interpret malformed padding?  There might be more than one reasonable way to do so, at least in some cases.