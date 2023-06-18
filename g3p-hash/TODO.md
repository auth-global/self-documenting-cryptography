Documentation TODOs:

1.  Write API documentation

    Include detailed discussion of the timing side-channels associated with the length of each parameter, and some suggestions for what one might wish to say using this new communication technology. 



Testing TODOs: (roughly in ascending order of difficulty)

1.  Write a test suite for tuplehash-utils

    Relatively straightforward, the testing TODOs are roughly in ascending order of difficulty.  Write a parser that turns an encoded bytestring back into a numerical type, check that things round trip. Test on 2^i and 2^i-1 for all i in range, as well as smallcheck and quickcheck.  Check that the length field is correct (if left-encoded), and check that the first byte thereafter is not the null byte.

2.  Write a test suite for bcryptRaw

    This is slightly complicated by the fact that the G3P removed all of the code surrounding the core bcrypt algorithm to deal with unix-style password hashes, replacing it with PHKDF. Good riddance, as that code has repeatedly proven to be problematic. For this reason, the G3P cannot be implemented in terms of standard bcrypt libraries.

    There's the issue that G3P generalizes bcrypt's cost parameter to any number of rounds. Also, standard bcrypt truncates the output hash to 23 bytes, a feature that started out life as a bug. The G3P depends on all 24 output bytes, and furthermore needs reliable, unimpeded access to the entire input parameters of the core algorithm.

    That said, the core bcrypt algorithm is completely unmodified. Thus one can test bcryptRaw against other bcrypt implementations.  In order to do so, the test suite will have to implement the code to generate (and possibly also parse) unix-style hash encodings. High enough quality implementations might even be a candidate for gettting into the binding itself, even though it's not strictly necessary for the G3P.

3.  Test cases for G3P and PHKDF are very incomplete

    The quality of common implementations will limit how robust the G3P will ultimately prove to be in practice. Given the data format complexity exhibited by this design, a comprehensive, carefully curated test suite is very much required.

    Go through the design.  Any time there's conditionals, modular arithmetic, encoding of nonnegative integers, etc, make sure there's reasonably comprehensive test coverage on every code location. Fortunately the G3P never ever makes a decision based on anything more than the length of the parameters, so this is largely a matter of choosing the right lengths for the right parameters to achieve the test coverage desired.

4.  Write the design criteria into a test suite

    This is a tricky one, as we will need an alterative G3P implementation that leaves it's internal message structure more explicit, instead of fused into the consumers like the initial reference implementation.

    Check that the side-channels exist as intended, and not otherwise.

    Check that our intentions regarding buffer positioning are met.

