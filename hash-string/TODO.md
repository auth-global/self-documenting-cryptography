* Garbage Collection/Finalizer considerations

   * It'd be nice to get an explicit bzero upon garbage collection

   * It'd also be nice to ensure reasonably low-latency GC when (if?) a value
     gets promoted to a later generations.

* Memory allocation considerations:

   * It would be very nice to have a HashString datatype that is allocated in
     a memory page that won't be written out to swap, even in a suspend-to-disk
     situation. Instead, the sensitive keys should be forgotten and would have
     to be re-generated via other means.

   * mlock() is a somewhat naive way to do this in Linux, and is likely worth
     using even if it isn't perfect.  Still, with the existence of things like
     CAP_IPC_LOCK suggests to me tha deeper investigations of these issues are
     warranted, and if there's a better, more modern solution to these issues,
     maybe those should be pursued as well.

* Mutable interface

   * This would reduce memory allocation, and can help ensure that intermediate
     cryptographic values are forgotten more quickly, with lower latency.

* Base64 encoding

   * current (untested) binding uses RFC4648 alphabet without padding

       * the traditional bcrypt binding in the G3P also adapts sc00bz's code,
         and is at least somewhat tested.

   * Need to support RFC4648's Url-safe encoding as an alternative alphabet

       * any other alphabets we should support here?

       * how do we support alternative alphabets?

   * what should we do about padding?

       * RFC 4648 is plainly wrong about requiring padding to avoid ambiguity.

       * The real advantage seems to be that if you are using padding, *and* your
         decoder supports padding in the middle of string, then you can concatinate
         bytestrings by simply concatinating their base64-encoded parts. Without
         padding, naive concatination sometimes shuffles bits between bytes,
         instead of achieiving a concatinative homomorphism of bytes.

         Instead of relying on naive concatination, one could implement a special
         routine that shuffles base64 digits as needed. This in turn can reduce
         the need for creating intermediate data structures that would be typical
         of a more naive implementation of concatinating two base64-encoded
         bytestrings. The fact that any potential concatination issue can be dealt
         with by avoiding naive concatination makes me question why padding might
         be a "good idea" from a design standpoint.

       * The downside of allowing padding in the middle of a string is that we
         cannot deduce the length of the decoded data without counting the number
         of padding bytes, which requires inspecting the entire string to calculate
         or verify.

   * Hackage's "base64" library seems to be... less consistent about these issues than
     I'd prefer, e.g. version 1 seems to have either a documentation bug or a naming
     bug, doesn't offer all four options, and decodeBase64Untyped assumes one option

   * encoding options that seem "important" enough to support out of box:

        * generate syntax with or without padding

        * some level of support for alternative base64 alphabets

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