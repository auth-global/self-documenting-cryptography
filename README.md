This repository introduces the concept of self-documenting cryptography, which is the art of using self-reference and self-narration in cryptographic constructions in order to communicate certain indelible facts to legitimate users and other observers.

This in turn implicates the topic of cryptoacoustics, which is the art of encoding messages in the medium of cryptographic state changes in ways that are easily decoded and understood by observers, and that maximize the overall resistance to obfuscation.

Since most (all?) common cryptographic hash functions exclusive-or their input into a state machine, suffixing a plaintext tag to the end of observer-supplied input plausibly exhibits desireable cryptoacoustical properties for most any cryptographic hash function.

This project follows various philosophies of documentation-driven design. It is also an example of design for reverse engineering. The two headline contributions in this repository are the Global Password Prehash Protocol (G3P), and the Seguid Protocol.

## Global Password Prehash Protocol (G3P)

The G3P is a self-documenting password hash function based on PHKDF and BCrypt. It designed to be particularly suitable for use on the user's endpoint before a password is sent to an authentication server.

The G3P is self-documenting in the sense that password hashes are supposed to be _traceable_ or _useless_ after they have been _stolen_. If Acme Corporation were to deploy the G3P, and their password hash database was stolen, then it is supposed to be impossible for the thief to outsource any brute force attacks on Acme's password database without announcing that the password hashes are Acme's.

The purpose is to point their conspirator in the correct direction to sell out the endeavor to Acme and report the hashes as stolen. In doing so, I hope to make it increasingly untenable to post meaningful password hashes where they can be widely seen without drawing the attention of relevant security departments.

Similarly, if a botnet is used to try to crack Acme's password hashes using stolen computing resources, then the G3P is designed to make it easy for a security analyst who observes this payload on the botnet to report the payload(s) and other observations back to Acme's security tip line.

In the longer run, I hope that will disrupt the activities of the cybercriminal scene. That said, I expect the more profound change in behavior will ultimately the promotion of more antifragile attitudes and practices among security departments.

The major design goals for the G3P were:

1. All HMAC calls and the overwhelming majority of SHA256 blocks should be covered by at least one self-documenting constant.

2. Follow the guidance of RFC 5869 and NIST Special Publication 800-108r1 as closely as possible

3. Offer the strongest API guarantees that are reasonably possible, without introducing extravagant complexity to do so.  Any implementation complexity must result in meaningful payoffs.

## Seguid Protocol

The Seguid Protocol is a domain-specific hash function that produces Self-Documenting Globally Unique Identifiers, or _seguids_. Seguids are self-documenting in the sense that they cryptographically attest to their own provenance and their own official documentation for y'all to follow. This feature helps improve coverage of the G3P by self-documenting tags, thus advancing our first goal. It also plausibly advances the second goal as well, as the seguid protocol is intended to produce outputs that qualify as a _key derivation key_ (KDK) in NIST parlance.

The Seguid Protocol aspires to be a meta-KDK that can produce the highest quality KDKs on demand, thus providing answers for "what salt should I use for HKDF?" among other questions.

## Password Hash Key Derivation Function (PHKDF)

PHKDF is a unification and synthesis of PBKDF2, HKDF, and TupleHash. The lower-level `phkdfStream` primitive intentionally violates the letter of HKDF's design philosophy of maintaining a clean separation between extraction and expansion. However this is in service to allowing a single primitive to serve in both roles, allowing self-documenting tags to be consistently applied to every call to HMAC in a larger key derivation protocol.

Taking a higher-level view, PHKDF affirms the spirit of the HKDF's design principle. It is highly recommended that any complete key derivation protocols that employ `phkdfStream` themselves express a clear distinction between extraction and expansion. For examples of how this might be done, see the documentation of the `Crypto.PHKDF.Primitives`.

Furthermore `phkdfSimple` and `phkdfPass` are fully worked examples about how one might use `phkdfStream` to implement a complete password hash function.  These are essentially slightly simplified design studies for the G3P, though they could conceivably be of interest for deployment.
