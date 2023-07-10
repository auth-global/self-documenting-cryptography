## Functionality TODOs:

1. Finish the seguid-protocol-v1 initialization vector & standard public interface

## API Documentation TODOs:

1.  HKDF

2.  seguid-protocol

3.  update design documents to reflect new (and likely final) padding design

## Testing TODOs:

(roughly in ascending order of difficulty)

1.  Write a test suite for tuplehash-utils

    Check that the length field is correct (if left-encoded), and check that the first byte thereafter is not the null byte. Write a parser that turns an encoded bytestring back into a numerical type, check that things round trip. Test on 2^i for all in range, similiarly for 2^i-1. Apply smallcheck and quickcheck.

2.  Write a test suite for Crypto.PHKDF.Primitives

3.  Write a test suite for Crypto.G3P.BCrypt

4.  Test cases for G3P and PHKDF are incomplete

    The quality of common implementations will limit how robust the G3P will ultimately prove to be in practice. Given the data format complexity exhibited by this design, a comprehensive, carefully curated test suite is very much required.

    Add an input method in the json test vector format to represent cyclically repeated strings to easily and compactly specify test vectors with the necessary input lengths.

    Go through the design.  Any time there's conditionals, modular arithmetic, encoding of nonnegative integers, etc, make sure there's reasonably comprehensive test coverage on every code location. Fortunately the G3P never ever makes a decision based on anything more than the length of the parameters, so this is largely a matter of choosing the right lengths for the right parameters to achieve the test coverage desired.

    For this reason, I added backreferences to allow large input lengths to be compactly specified.  I've started to include reasonable test vector coverage of the password padding function. There's more to do. Also curious how difficult it would be to use AFL-like fuzzing technologies to evolve a more complete, compact collection of test vectors.

5.  Write the API documentation into a test suite

    Testing already includes a few assertions regarding positioning within a SHA256 buffer, which helped sanity-check the padding design. There is more to do, especially with regard to the end-of-message padding provided by PHKDF-STREAM

    Check that the side-channels exist as intended, and not otherwise, by counting the number of SHA256 blocks processed.

    This is a tricky one, as we will need an alterative G3P implementation that leaves it's internal message structure more explicit, instead of fused into the consumers like the initial reference implementation.
