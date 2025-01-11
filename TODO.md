## Functionality TODOs:

1. Finish the seguid-protocol-v1 initialization vector & standard public interface

## API Documentation TODOs:

1.  HKDF

2.  seguid-protocol

3.  major revision of design documents

    * A fresh version of a design document for G3Pb2 has been started.

    * Write section on deployment considerations

    * Write section(s) with detailed specifications

## Testing TODOs:

(roughly in ascending order of difficulty)

1.  Write a test suite for Crypto.PHKDF.Primitives

2.  Improve test suite for Crypto.G3P.BCrypt?

    * should there be independent tests for bcryptRaw and/or bcryptXsFree?

4.  Test cases for G3P and PHKDF are incomplete

    The quality of common implementations will limit how robust the G3P will ultimately prove to be in practice. Given the data format complexity exhibited by this design, a comprehensive, carefully curated test suite is very much required.

    At the moment, the tests surrounding the padding and formatting issues associated
    with the G3P's use of PHKDF seems to be reasonably complete. The bulk of the
    incomplete work that I'm specifically aware of surrounds the bcrypt integration,
    but of course it would be nice to have better tests "local" to the PHKDF.

    * Add an input method in the json test vector format to represent cyclically repeated strings to easily and compactly specify test vectors with the necessary input lengths.

    * Go through the design.  Any time there's conditionals, modular arithmetic, encoding of nonnegative integers, etc, make sure there's reasonably comprehensive test coverage on every code location. Fortunately the G3P never ever makes a decision based on anything more than the length of the parameters, so this is largely a matter of choosing the right lengths for the right parameters to achieve the test coverage desired.

    For this reason, I added backreferences to allow large input lengths to be compactly specified.  I've started to include reasonable test vector coverage of the password padding function. There's more to do. Also curious how difficult it would be to use AFL-like fuzzing technologies to evolve a more complete, compact collection of test vectors.

5.  Write the API documentation into a test suite

    Check that the side-channels exist as intended, and not otherwise, by counting the number of SHA256 blocks processed.

    This is a tricky one, as we will need an alterative G3P implementation that leaves it's internal message structure more explicit, instead of fused into the consumers like the initial reference implementation.
