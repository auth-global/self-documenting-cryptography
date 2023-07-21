# The Global Password Prehash Protocol G3P, a Case Study in Self-Documenting Cryptography

(by Leon P Smith,  Auth Global)

This work is licensed under a Creative Commons Attribution-ShareAlike 4.0 International License.

## Abstract

The Global Password Prehash Protocol (G3P) is a slow password hash function that is _self-documenting_ in the sense that its output hashes aim to be _traceable_ or _useless_ after they have been _stolen_ by an evesdropper. It does this by extending the role of the traditional _salt_ parameter to serve as a communication channel intended to be used by deployments to identify themselves.

This communication channel is based on _cryptoacoustics_, which is the art of encoding messages in cryptographic state changes in ways that are easy for observers to decode and difficult for attackers to obfuscate.

Here, an observer is anybody is capable of computing the correctly-salted G3P hash function on hardware they provide on passwords of their own choosing. An attacker might be a data thief who would like to outsource a cracking attack on a G3P password hash without simulatenously extending an invitation to report that G3P hash as stolen.

Most (all?) common cryptographic hash functions exclusive-or their input into a state machine, therefore suffixing this salt as a plaintext tag to the end of observer-supplied input is a plausibly-secure cryptoacoustic communication channel for many choices of hash function.

Computing such a tagged hash function announces the plaintext of the tag to anybody who can observe the internal workings of the state machine that natively computes that hash function. Without providing exotic cryptographic algorithms, the plaintext of these tags will always be within reach of a reasonably good reverse engineer. This plausibly provides a natural chokepoint against obfuscation.

Homomorphic Encryption (HE) can plausibly hide the internal transitions of arbitrary state machines from even the best reverse engineers. Although the cost overhead of HE is currently prohibitive in the context of password cracking, the G3P would very much like to keep it that way. Thus the G3P uses _cryptoacoustic repetition_ to amplify the overhead plausibly associated with the exotic cryptography required of any truly secure virtual black-box tag obscuration attack.

## Introduction

Authentication services are a _high-value asset_, and therefore a natural target for cyberattackers to prioritize. Successfully evesdropping on a password-based login flow often reveals the plaintext password itself. Because users often use the same or similar passwords across multiple websites, the plaintext password can often then be used to attack other accounts.

We can do better. The Global Password Prehash Protocol (G3P) is a slow password hashing function based on PHKDF and bcrypt that is designed to be particularly suitable for use on the user's endpoint before a password is sent to an authentication server. If the service provider requires[^require-prehashing] prehashing, the provider can all but ensure that they will never see plaintext passwords.

When the G3P is deployed as a client-side prehash, then further server-side hashing or other suitable password authentication technology such as SCRAM or PAKE is required before the hash can be safely stored in the server's authentication database. In some cases this might be as simple as a single application of SHA256, HMAC, or any other suitable cryptographic hash function applied to the prehash itself.

One of the practical challenges of deploying a client-side password prehash function is communicating the salt for the password function to the authenticating party. Any careless adaptation or implementation of a traditional random-salt-per-password design in a prehash setting has the potential to leak information such as whether or not a given account exists, or if the password for a given account has changed.

The G3P eliminates this complication by seperating the salt into the _username_ parameter, which is expected to be known of an authenticating party, and various deployment-identifying cryptoacoustic tags such as the _seguid_ and the _domain-tag_. These tags can be shared by all users, and can be constant across an entire deployment.

Typically, most of these tags would be publicly known. They are intended to point to the start of a documentation path that leads to the deployment's security disclosure portal. This referenced documentation should be reasonably specific, and should be published for everybody to see for free and without registration over https and possibly also InterPlanetary FileSystem (IPFS), a content-addressable distributed storage technology that also supports strongly-authenticated publication channels.

In this way, the G3P transparently binds the output of the hash to a specific username on a specific authentication service. In doing so, the G3P provides domain seperation among usernames and services. Say there is a user reuses the same or similar password across multiple accounts. Say there is an evesdropper with the ability to see inside encrypted TLS sessions, and they intercept a G3P prehash of our user's reused password.

In order for the evesdropper to use the stolen prehash against the other accounts, the reused plaintext password must first be cracked. Beyond cracking and replaying, the domain-seperated, channel-locked prehash is otherwise almost certainly useless.

A G3P hash cannot be transported between deployments of the protocol in dishonest ways. This is analogous to ingress and egress filtering routinely deployed on Internet Protocol routers.  In ingress/egress filtering, traffic that claims to originate from inside the network is not allowed to enter the network from the outside, and traffic that claims to originate from outside the network is not allowed to be leave the network from the inside.

To strengthen the second half of the analogy, the G3P protocol introduces a secondary security goal into the password hashing process. The G3P tries to ensure that a password hash is either _traceable_ or _useless_ after it has been _stolen_ by an evesdropper.  For example, say Acme Corporation deploys the G3P, and their password database gets stolen and posted on a darknet website.

The goal is that in order to have a possibility of cracking those stolen hashes, any observer must know (or guess) that they came from Acme Corporation. Thus, if a security researcher witnesses the password hashes on the sketchy website and those hashes are genuinely crackable, then the security researcher is supposed to have an easy time figuring out that the hashes should be reported to Acme Corporation as stolen.

In another plausible scenario, let's say that an evesdropper chooses to conduct an offline brute-force attack against stolen password hashes using a botnet or other stolen computing resources. If a security analyst observes this payload, that analyst is supposed to have an easy time figuring out that the stolen resources appear to be devoted to cracking Acme Corporation's password hashes. That analyst would ideally then have an easy time finding Acme's counterintelligence tip line to report their observations directly to Acme.

The tagging constructions I propose provide no way to determine whether or not any particular password hash is actually from Acme Corporation. Even if you successfully crack a plaintext password from a hash using the official Acme Corporation-branded password hash function, it's trivial to forge such password hashes.

This proposal purposefully leaves unaddressed the issue of authenticating whether or not any purported password hash is genuinely Acme Corporation's or not. On that specific question, it seems preferable to Acme to maintain plausible deniability. We need our tagging construction to be a robust communication channel from deployments to observers, but the type of tagging that is needed is much weaker than say, an indelible property tag attached to a physical object.

Our security goal is that if one of Acme Corporation's geniune password hashes is obtained by an evesdropper, and is subsequently subjected to a cracking attack, then it should be prohibitively expensive for the evesdropper to hide the target of the attack from whomever is providing the resources to carry the attack out, thus building a closer approximation to a closed-loop detector for leaked password hashes.

In this way, this proposal hopes to supplement and enhance _Have I Been Pwned_, which is a website that includes an effort to document the huge and currently growing problem of stolen passwords and stolen password hashes. Troy Hunt's pioneering effort at closed-loop leaked password hash detection directly inspired a desire for password hashes that are _traceable-or-useless_, which helped inspire the invention of cryptoacoustics and self-documenting cryptography.

## Design Requirements

This paper introduces a series of cryptographic hash protocols. Two are based on PBKDF2, one is based on HDKF, two are used to introduce PHKDF, and the final introduces the full Global Password Prehash Protocol (G3P). This introduction provides an overview of the design requirements for a complete prehash protocol. The three most important parameters of a complete input block are the username, password, and domain tag:

```
username   : ByteString
password   : ByteString
domain-tag : ByteString
```

The username and password are normally provided by an authenticating party. A complete password prehash protocol should not impose any theoretical limitation less than the maximum input length supported by an underlying cryptographic hash function. If implementations impose a maximum length on the username or password, that upper limit should not be less than 2048 bytes long.

Furthermore, both parameters must support arbitrary binary data, including null bytes. Every single bit must match: there must be no password-truncation or password-encoding gotchas like bcrypt. There must be no timing side-channels in the protocol that depend on anything more than the length of the parameters, and a complete password prehash protocol must take steps to minimize those side channels.

The username is functionally a second password. The username must match, and the username and password cannot be swapped, nor bytes shuffled between them. Though the username is often not considered a secret, both inputs are functionally identical in the sense that if either the username or the password is a high-entropy secret, the result must be a high-entropy secret.

From the perspective of our primary, classical security model of password hashing, the domain tag is functionally a third password. In normal use cases, the domain tag is intended to be a constant (or near-constant) specified by a deployment of a password prehashing protocol, thus serving as a form of salt. Though the domain tag may contain arbitrary binary data, we recommend specifying a domain tag that consists of UTF8-encoded plaintext strings, possibly seperated by null bytes, due to the cryptoacoustic properties of the domain tag that our  _traceable-or-useless_ security goal depends upon.

The domain tag is normally expected to start with an RFC 3490-compliant DNS name under your control, an RFC 3986-compliant URI that points to documentation relevant to the deployment, or at least an RFC-6530 email address to report security incidents to. Additional data may be included in a domain tag after an ASCII space ("\x20"), CR LF newline ("\x0D0A"), or horizontal tab character ("\x09").

```
domain-tag = "your-domain.example"

- or -

domain-tag = "your-email-address@provider.example"
```

A high-quality deployment should clearly document the intended audience and use case. For example, a deployment of the G3P might be intended to be used by employees of the Acme Corporation in order to login into Acme's website. This purpose should be clearly documented, and then a link to those documents should be included in the plaintext tags specified by the deployment itself. This can be done in the domain tag directly; alternatively all of the complete PHKDF-based protocols all support various other tagging locations, such as the `long-tag` which is constant-time for any length up to nearly 5 KiB:

```
long-tag = "https://your-domain.example/link/to/deployment/docs"

E.G.

long-tag = "https://login.acme-corp.example/.prehash/v0"
```

These tags are a form of salt intended to provide a cryptoacoustically robust plaintext communication channel from _deployments_ to _observers_. In this context, an observer is whomever is capable of computing the correctly-salted hash function using hardware of their choosing.

A G3P-based password authenticator can securely display (part of) the domain tag to the user, and the user can then double check the domain tag against their expectations. Even if a user were to reuse a password between say, a social media account and an online bank account, there is no direct, immediate benefit to an attacker to ask the user's authenticator for the password to the social media account in an attempt to gain access to the financial account.[^reduced-round-attacks]

This communication channel makes the domain tag functionally distinct from the username and password.  Reciprocal relationships are not design requirements: for example, if an observer can compute a hash for an arbitrary domain tag of their choice, and some hidden username and password, they are not required have access to the plaintext of either the username or password.

The domain tag is allowed, even encouraged, to exhibit strong timing side-channels revealing a range into which the length of the domain-tag falls. This is an unavoidable consequence of achieving _cryptoacoustic repetition_, where the plaintext of the domain tag is repeatedly hashed into the final result, very much like the `info` parameter in HKDF.

In our PHKDF-based protocols, the domain tag is free of timing side-channels if it is 19 bytes or less. In the range of 20 and 83 bytes, the domain tag incurs the computation of one additional SHA256 block _per round_ and _per output block_, plus a small constant number of extra blocks. Every 64 characters added to the domain tag thereafter incurs this same incremental cost. The domain tag is otherwise entirely free of timing side channels.

Space in the domain tag can be at a premium, depending on one's goals. Although for many or most purposes a 20-83 byte or even longer domain tag should work quite well, keeping it to 19 bytes or less means PHKDF remains the most directly comparable to PBKDF2 as possible. Longer domain tags also introduce extra overhead during final output expansion; while the magnitude of this timing effect is much smaller, it can't be easily compensated for by adjusting a cost parameter, and the location where the overhead is incurred could conceivably be more cost sensitive in some applications.

For this reason, the G3P protocol intends to register well-known URLs so that one can start from a domain name, and easily find that domain's G3P deployment constants and other relevant documentation. Also, our complete protocols offer a variety of alternate tagging locations that are hashed into the result only once or a few times. These are ideal places to specify additional tags that convey longer messages to observers.

The last parameter that appears in all of the complete protocols in this paper is the `seguid`, which serves as sort of a global salt. One of the cryptographically most important things a typical deployment can do is specify a constant seguid.  The seguid is then used as the HMAC key throughout most or all of a protocol, and is not used for any other purpose by the protocol itself.

The seguid parameter is fully defined for arbitrary bitstrings, however, the parameter corresponds to a _key derivation key_ (KDK) in NIST Special Publication 800-108r1.  As such, it is highly recommended that the input be 256-512 bits long, and resemble a string chosen uniformly at random.  Using a genuine seguid meets both of these recommendations.   Using a 512-bit seguid is basically free, and theoretically stronger than a 256-bit seguid, however, in the context of HMAC-SHA256, seguids that are longer than 512 bits are equivalent to a 256-bit seguid.

```
seguid : BitString
```

We highly recommend that the input to the seguid parameter be a genuine self-documenting globally unique identifier, possibly one generated by the Seguid Protocol. Genuine seguids are suitable for turning HMAC keys into indirectly self-documenting tags, with the assistance of search engines.  In this context, generating a seguid for your deployment requires hashing the URL of your deployment's public documentation page, precomputing the HMAC key associated with that hash, publishing both results on that public page, and ensuring that the page is indexable.

It is recommended that every deployment generates and uses its own genuine seguid, because doing so is easy and because it always improves the coverage of self-documenting tags throughout our protocols.

For example, without either using a deployment-specific seguid or modifying the HMAC construction altogether, it's impossible to add a deployment-documenting tag to the last SHA256 block required to compute a full application of HMAC. This block is fairly common in the core key-stretching component of PHKDF, typically consisting of one out of three or four blocks, depending on the length of the domain tag. Using a deployment-specific seguid plausibly amplifies any overhead associated with hypothetical tag obscuration attacks.

While it is recommended to use your own seguid, it is also perfectly secure to use a default seguid; it just won't point back to your specific deployment, and instead you'll be entirely reliant on other tags to communicate with observers.

Be aware that using a default seguid can bring with it additional expectations or requirements. For example, while the above recommendation that the domain tag start with a domain name, email address, or URI is a universal recommendation no matter what seguid is ultimately specified, these recommendations might become an expectation if a default seguid is used. On the other hand, a deployment could change the seguid and then do whatever it wants to with the domain tag.

## A First Implementation

Our first protocol meets all of our design requirements and is relatively simple and foolproof to implement.  It is literally PBKDF2 deployed in an alternate mode of operation. This alternative is plausibly better for at least three reasons: first, this mode of operation is the only way to turn PBKDF2-HMAC-SHA256 into an iterated self-documenting hash function. Second, this mode of operation allows a PBKDF2 computation to efficiently transferred to another computing element at nearly any time, with full credit for any key-stretching work already performed. Third, this mode of operation comports more closely with modern recommendations for key derivation functions as found in NIST Special Publication 800-108r1 and RFC 5869.

```
TAGGED-PBKDF2-HMAC-SHA256 : (
    username : ByteString,
    password : ByteString,
    credentials : ByteString = "",
    seguid : BitString,
    domain-tag : ByteString,
    rounds : PositiveInteger = 375000
  ) -> ByteString(32) =

hashed-username = HMAC-SHA256 (
    key = seguid,
    msg = username || parameter-padding("username", domain-tag)
  )

hashed-password = HMAC-SHA256 (
    key = seguid,
    msg = password || parameter-padding("password", domain-tag)
  )

return PBKDF2-HMAC-SHA256 (
    salt = hashed-username || hashed-password || credentials || domain-tag,
    password = seguid,
    rounds = rounds
  )
```

TAGGED-PBKDF2-HMAC-SHA256 uses a parameter padding scheme that doesn't depend on the length of the input parameter.  Under this constraint, the padding is design to maximize the input length range for which the hashing protocol will operate in constant time.  In this case, any input from 0-63 bytes long will be processed in constant time.  Every 64 bytes thereafter will cause the computation of exactly one additional SHA256 block, thus also minimizing the side-channel.

This is done by ensuring that the length of the padding is of the form (56 + 64 n), with n determined by the length of the parameter's name and the domain tag.  SHA256's end-of-message padding requires 8 bytes plus 1 bit. This is effectively 9 bytes if you constrain SHA256 inputs to bytestrings. Thus the parameter padding and the minimum-length end-of-message padding together consume (65 + 64 n) bytes, leaving 63 input bytes left to go before another SHA256 block computation is incurred on the 64th byte.

```
parameter-padding : (
    name : ByteString,
    tag  : ByteString
  ) -> ByteString =

pad = "\x00" || name || "\x00" || tag

n = (56 - byte-length(pad)) mod 64

// add 0-63 null bytes

return (pad || (n * "\x00"))
```

The use of deployment-specific seguids are especially highly recommended in this context. The domain tag only achieves 2x repetition per password guess, not 3x, because the hashed username can be furnished in leiu of the plaintext username.  Thus without the use of a deployment-specific seguid, a tag obscuration attack would only have to hide those two repetitions of the domain tag.

Including a deployment-specific seguid means that any obscuration attack would need to be employed for every single application of HMAC and every SHA256 block in the call to PBKDF2 itself. In practice this would often mean hiding tens or hundreds of thousands of indirectly self-documenting tags per password guess. This is why our first implementation doesn't even suggest a default seguid.

However, a seguid is only indirectly capable of conveying a plaintext message, so this assumes a slightly more sophisticated observer who uses a search engine to follow the seguid back to its self-verifiable source. By contrast, the domain tag is capable of directly conveying a plaintext message to observers, without external assistance of any kind.  Therefore it would be highly desirable to repeatly hash the plaintext of the tag into the result as well, in order to plausibly harden the domain tag against obscuration attacks.

The remainder of the constructions in this paper will lift the domain tag into the iterated hash construction behind PBKDF2 and HKDF, very much analogous to HKDF's `info` parameter.  As I was fishing around for good PBKDF2-like construction that does this, and could be implemented in a time- and/or space- efficient manner in terms of WebCrypto, I came up with the following hash function:

```
TAGGED-HMAC-HKDF : (
    inputs : BitString,
    domain-tag : ByteString,
    seguid : BitString,
    rounds : PositiveInteger = 255,
  ) -> ByteString(output-length) =

msg = HKDF (
    salt = seguid,
    ikm  = inputs,
    info = domain-tag,
    len  = output-length * rounds
  )

return HMAC (
    key = seguid
    msg = msg || domain-tag
  )
```

This function can be implemented with constant memory consumption,  because the output of HKDF and the input of HMAC are both streamable.  However, WebCrypto doesn't support streaming operations, so a WebCrypto-based implementation will briefly use eight or sixteen kilobytes of memory to construct the intermediate message before it is hashed into the final result. Increasing the number of rounds only increases the amount of memory needed.  Also, specifying more than 255 rounds technically violates the specification of HKDF and NIST 800-108r1, and probably can't be guaranteed to work with webcrypto implementations anyway.

Also it's important to point out that this call to HKDF only achieves 1x repetition of the seguid, so overall, TAGGED-HMAC-HKDF achieves 2x repetition of the seguid.  We've achieved 256x repetition of the domain tag, but at the unnecessary cost of giving up most of the repetitions of the seguid.

While one would hope that an implementation of the WebCrypto API would provide a time-efficient implementation of HKDF, it's not guaranteed either.  While TAGGED-HMAC-HKDF is likely a perfectly secure cryptographic hash function that somewhat meets some of our goals, it seems interesting mostly as an academic curiousity that helped inspire PHKDF, and might help justify PHKDF.

Alternatively, we can lift the domain tag into the iterated hash construction of PBKDF2 by instantiating it with a nonstandard pseudorandom function (PRF).  In our case, a HMAC function suffixed with our domain tag is very likely a suitable PRF for PBKDF2, and achieves repetition of a plaintext tag without technically stepping outside of PBKDF2.  Thus PBKDF2-TAGGED-HMAC would repeat both the seguid and the domain tag, but would also omit the counter that HKDF and PHKDF include.

```
TAGGED-HMAC (
    key : BitString
    msg : ByteString
    tag : BitString
  ) -> ByteString =

return HMAC (
    key = key
    msg = msg || tag
  )
```

However, one of the few advantages that any of the constructions of this section have over PHKDF is that TAGGED-PBKDF2-HMAC can be efficiently implemented in terms of common, baroque APIs such as WebCrypto.  Unfortunately, this isn't true of PBKDF2-TAGGED-HMAC, and at that point PHKDF seems superior to both.

The main limitation is that the WebCrypto's interface doesn't support precomputed HMAC keys. Recomputing the key for every application of HMAC means that in the core iterated hash construction behind PBKDF2 requires four SHA256 blocks to be computed per round, instead of two SHA256 blocks per round. Reusing a precomputed HMAC key saves half the blocks needed to compute PBKDF2.  This result is exact modulo a small constant number of blocks. A very similar statement is true of PHKDF and HKDF, though longer tags/info parameters change these calculations.

Of course, a sufficiently advanced WebCrypto implementation might use less-than-local imperative effects to cache one or more HMAC keys behind the scenes. However, it is not sound software engineering practice to rely on this kind of dark magic. Often, such key-caching won't be implemented. Even when it is, key-caching can introduce additional problems and limitations.

It is better to provide a more comprehensive HMAC interface that explicitly supports precomputed keys. By depending upon that sort of interface, implementations of PBKDF2 and similar iterated HMAC constructs can robustly specify the key reuse they need to be efficient, no effects needed.

## Secure Tagging

In our context, the security goal of a tagging construction is this: if an observer has the ability to compute a cryptographic hash function on inputs of their choice using hardware under their direct control, then the tags must be known to (or at least knowable by) the observer!  The topic of virtual black-box obfuscation has been studied before, as a cryptographically-strong form of program obfuscation.   That said, to the best of my knowledge the precise security goal discussed in this section has not been formally modelled or studied, nor will this paper do that.  This section provides an informal description of security model of a tagging construction, and proposes several complementary solutions.

Our security model comes into play only after a password hash has been _stolen_. If an observer is a legitimate user, the benefits of these tagging constructions are far more robust. Deploying a hypothetical tag obscuration attack against a legitimate user would provide nonexistent, dubious, or minor secondary benefits to an attacker. This is because an attacker who can alter the user's authenticator will be able to lie about the tag, and won't need a cryptographic attack to do so! In many common cases it would also be trivial to simply steal the plaintext password directly.  Passwords are replayable if you get close enough to the source!

The self-documenting constructions used in this paper primarily revolve around the following plausible understanding of the cryptoacoustic properties of HMAC:

```
HMAC-SHA256 (
    key = indirect-tag
    msg = short-tag
       || derived-from-observer-input
       || long-tag
  )
```

Tags that appear after user input are plausibly secure plaintext tags with no caveats. One of these long tags is capable of directly conveying an arbitrarily long plaintext message to an observer without relying on external means, because we are encoding our message into the cryptographic state changes of the standard algorithm that computes SHA256.

In order for an attacker to defeat a long tag, they would have to provide a virtual black-box obfuscated algorithm to an observer that enables `SHA256 (x || long-tag)` to be computed for arbitrary `x` chosen by the observer, using any compatible hardware of the observer's choice and under their direct control, while securely hiding the plaintext of the `long-tag` from the observer. This implementation would have to provide quite an exotic algorithm for computing SHA256, because observing the internal workings of the standard algorithm trivially reveals the plaintext of the tags our attacker wishes to obscure.

The observation that suffixing is a plausibly-secure plaintext tagging construction applies not only to the entire SHA-2 family of functions, but also Blake2, SHA-3, Ascon, and many or most other cryptographic hash functions. Even if SHA256 turns out to be a less than ideal choice for this construction, it is at least possible that other cryptographic hash functions are more suitable for various cryptoacoustically secure tagging constructions.

Thus the G3P also uses bcrypt in a self-documenting mode of operation to supplement the primary crypoacoustic construction,  with the understanding that every bit of bcrypt's two 72-byte inputs is a cryptoacoustic plaintext tag under the assumption that a sufficient number of bytes has been derived from observer input.

A notable counterexample is Blake3. It too exclusive-ors its input into a cryptographic state machine, so thus it too exhibits plausibly-secure cryptoacoustic properties. However, it also offers parallel computation and incremental updates via it's internal tree structure, which complicates the cryptoacoustic properties of this function.

This means the tag-suffixing construction can only be cryptoacoustically secure with additional assumptions about the lengths of the tag and other inputs to Blake3, which shouldn't be anything insurmountable in cryptoacoustically-sensitive designs, but it is an unusual example nonetheless.  Blake3's parallelism and incremental updates seem largely at odds with the goals of cryptoacoustics, but perhaps there is a shift in perspective that could somehow render these features cryptoacoustically attractive

The expansion phase of all the PHKDF-based protocols relies on a slight variant of our primary understanding, where the entire hmac message must be known to an observer if they provide the key:

```
HMAC-SHA256 (
    key = derived-from-observer-input
    msg = plaintext-tag
  )
```

The main limitation of a short HMAC tag is that it must be substantially shorter than one block (64 bytes in the case of SHA256) to ensure that the first block processed includes the `indirect-tag` and a sufficient quantity of observer-derived input so that the observer must compute that SHA256 block themselves and cannot be provided with a precomputed block. Our final protocols basically limit the use of this exact construct as protocol-identifying domain seperation constants.

However, our final padding design employs a slight extension of the short tag construction to ensure that whomever computes the SHA256 blocks where the `password`, `credentials`, or `seed-tags` parameters are located in the overall protocol must know those short tags, where the domain and various other tag parameters are fit into a fixed number of bytes, usually 32 bytes, in a truncated or cyclically extended form.  All such parameters are repeated fully elsewhere, so none of these truncations lead to trivial collisions.

```
HMAC-SHA256 (
    key = indirect-tag
    msg = length-is-exact-multiple-of-64
       || short-tag
       || encoded-parameter-blocks
       || remainder-of-message
   )
```

With the help of Self-documenting Globally Unique Identifiers (seguids), HMAC keys are indirectly usable as tags. Indirect tags cannot be used to convey a plaintext message without the help of external means, such as openly-published seguids and reverse-lookup search engines.

This tag is necessarily indirect because two precomputed SHA256 hashes of the key can be used to compute the HMAC function in lieu of the plaintext of the HMAC-SHA256 key itself. An analogous statement is true no matter which underlying hash function HMAC is instantiated with. This observation is critical to efficient implementations of PHKDF and PBKDF2 when instatiated with an HMAC-based pseudorandom function (PRF).

Homomorphic Encryption seems theoretically capable of hiding arbitrary state machines, which would then seem to be capable of defeating our tagging constructions. Thus our _traceable-or-useless_ secondary security goal might be too simplistic, somewhat in vain, or at least decidedly non-trivial. However, Homomorphic Encryption currently introduces 6+ orders of magnitude of overhead, and is unlikely to be practical in this application space anytime soon. Just to be safe, the G3P somewhat naively attempts to add another 4+ orders of magnitude of overhead on top of that, via PHKDF and bcrypt.

Just as homomorphic transciphers are a research topic that seeks to design cryptographic primitives and constructions that are relatively efficient when executed inside an HE encrypted environment, the topic of cryptoacoustics seems to imply the need to research the dual problem: cryptographic primitives and constructions that are designed to be especially inefficient inside homomorphic execution environments.

I don't know that there isn't a more efficient tag obscuration attack. Perhaps it would be specific to SHA256; such an attack need not depend on a general-purpose framework for encrypted computation such as HE. In any case, a meaningful tag obscuration attack would require a rather exotic SHA256 algorithm. It seems plausible that this exotic algorithm would impose significant overhead versus the native SHA256 algorithm. Thus we might as well try to hedge against any such hypothetical attack by attempting to amplify this plausible overhead.

The G3P protocol ensures that every HMAC call and nearly every SHA256 block it specifies contains at least one self-documenting constant. This is an educated but naive attempt at amplifying the overhead imposed by any hypothetical tag obscuration attack. It accomplishes this using PHKDF, a cryptographic primitive introduced in the next section that is the result of deconstructing PBKDF2 and HKDF and reconstructing them into a natively self-documenting cryptographic construction. If the self-documenting constants weren't throughly suffused throughout PHKDF, then it perhaps the virtual black-box tag obscuration algorithm would only need to be used for a few blocks instead of tens of thousands of blocks per password guess.

G3P further hedges the self-documenting properties of PHKDF by using bcrypt in a cryptoacoustically self-documenting mode of operation. While further improvements are likely be found by reconstructing bcrypt as well, this would necessarily involve much deeper and more subtle changes. A design goal of Version 1 of the G3P is to be relatively cautious in the changes it chooses to introduce, and to be adventurous only when the risk-to-reward ratio seems highly favorable.

Furthermore, even if our hope for a durable plaintext communication channel to observers is overly optimistic, the domain seperation itself enables a sufficiently sophisticated observer to deduce openly-published, non-secret tags even from perfect black-box implementations of a G3P deployment.

Let's say an attacker provides an observer with a virtual black-box implementation of Acme's prehash function, like a webservice that accepts plaintext passwords, and returns a resulting G3P hash while keeping the tags securely hidden from the provider of the password.

Of course, such a literal G3P-as-a-webservice would be almost entirely useless to deploy in practice. It's of no use to password crackers, because generating password guesses is cheap, but actually calculating their hash so that the guess can be checked is expensive, so this arrangement does not outsource the real cost of password cracking in addition to introducing substantial new costs. And of course a literal G3P-as-a-webservice is a comically insecure deployment decision if the G3P is actually being used as a client-side prehash. However, G3P-as-a-webservice is a useful mental approximation of the virtual black-box oracle needed for our thought experiment.

For the remainder of this section, we assume our attacker has the superpower to produce a virtual black-box oracle for Acme's prehash function that allows this "webservice" to be shared as a executable program with 10x overhead or less, or somehow otherwise magically find another solution that is bordering on practical for purposes of outsourcing password cracking attacks. Even in this scenario, a sufficiently advanced observer should still have relatively little difficulty figuring out which deployment is being hidden behind the oracle.

All the observer need to do is to simply select some username and password at random, and use the oracle to compute the corresponding hash. Then enumerate all openly published prehash function deployments, and try each one until the observer figures out that it is Acme's deployment of the G3P that the attacker is trying to hide behind the oracle. The problem is the obscurer is attempting to hide a publicly-known "secret" in their black-box oracle, so they are naturally in for a bad time of it.

There's a certain lack of compositionality in this thought experiment: let's say that Acme is storing their prehashes using a secret HMAC key. Say an attacker learns Acme's secret storage key, and then constructs an oracle that computes the composition of Acme's G3P prehash and their secret storage function. No observer outside of Acme's cybersecurity administrators and engineers could deduce that the oracle's hidden function is at all relevant to Acme Corporation.

In general, it seems plausible that our hypothetical attacker could lift the entire password-checking computation into their virtual black-box, so that an observer simply gets a "yes/no" answer to any given password guess. Thanks to our attacker's superpower, this would enable practical password cracking attacks to be outsourced to third parties while also hiding the target of the attack from those providing the resources to carry it out.

Ultimately, it is important to remember that a tag obscuration attack is only relevant to our extended secondary security model that password hashes must be _traceable_ or _useless_ after they have been _stolen_. A successful tag obscuration attack means that an attacker removed or changed some of the signposts that we are attempting to leave for observers. Successful attacks of this kind have no impact the classical model of password security, which is still our first and primary security model.

Our secondary _traceable-or-useless_ security model appears to be novel, and is relevant only when a third-party observer is a witness to a stolen G3P hash. By contrast, our primary security model is classical, and very much relevant to the normal day-to-day functioning of an authentication service. Moreover, in the context of normal operations, the observers are authenticating parties not password crackers. In this primary context, tag obscuration attacks are far less useful in practice and therefore the benefits provided by the G3P's domain seperation methodology are much more robust.

## PHKDF

The Password Hash Key Derivation Function (PHKDF) is a unification, synthesis, and distillation of PBKDF2, HKDF, and TupleHash. It was created in order to build the Global Password Prehash Protocol (G3P).  The fundamental, low-level building block is PHKDF-STREAM, which outputs an unbounded cryptographically-secure pseudorandom number generator (CSPRNG).

The core PHKDF-STREAM construction uses HMAC-SHA256 in a feedback mode, much like PBKDF2's stream generator.  The main difference is that PHKDF carries the 4-byte counter all the way through the iterated hash construction, and additionally suffixes a contextual tag after the counter.   In this analogy, the PHKDF's `key` parameter corresponds to PBKDF2's `password` parameter, whereas PHKDF's `msgs` parameter corresponds to PBKDF2's `salt` parameter.   Of course we reverse PBKDF2's standard mode of operation, and use the HMAC key as a salt instead of the password input, which comports more closely to the advice of RFC 5869 and NIST 800-108r1.

```
PHKDF-STREAM-HMAC-SHA256 : (
    key  : BitString,
    args : Vector<BitString>,
    ctr  : Word32,
    tag  : BitString
  ) -> output : UnboundedByteStream =

state = concat-map(encode_string, args) || "\x00"

n = (32 - byte-length(state)) mod 64
// add 0-63 bytes, landing on 32-byte buffer boundary
state ||= cycle-bitstring-with-null( n, tag )

loop as needed:
    state := HMAC-SHA256 ( key, state || encode_be32(ctr) || tag )

    // this increment must cleanly wrap around from 2^32-1 to 0
    ctr += 1

    output ||= state
```

PHKDF-STREAM makes use of TupleHash's `encode_string` subroutine from NIST Special Publication 800-185 in order to unambiguously differentiate between an arbitrary number of bitstring inputs. After this vector of bitstrings has been fully encoded, we mark the end of the vector with a single null byte. Because the output of `encode_string` always starts with a byte that is not null, this end marker ensures that our encoding is _one-to-one_ and _well-defined_.

At first, I tried to avoid incorporating length-prefixing syntax like TupleHash in the G3P.  But I wanted the end-of-message tag placed in a consistent buffer location. I also wanted to be able to look at any given HMAC message generated by the G3P and be able to unambiguously understand exactly which call to HMAC it is within the construction. All parameters should be unambiguously parseable from the inputs to at least one set of calls to HMAC. I eventually came to believe the only practical way to really accomplish these and a few other minor perceived constraints was to adopt something like TupleHash syntax to properly frame inputs.

After we mark the end of the vector, we generate between 0 and 63 additional bytes of padding in order to bring the end of the HMAC message we are encoding to a half-buffer boundary. This step ensures that all the timing side-channels associated with the length of tag occur at a consistent length.

This variable-length padding is generated via the subroutine `cycle-bitstring-with-null`, which always returns a bytestring of a given length. This routine is used throughout these constructions to improve the coverage of SHA256 blocks by self-documenting constants. It is implemented using `cycle-bytestring`, which repeats it's bytestring argument as many times as needed, followed by a prefix of the bytestring, to reach the desired length.

```
cycle-bitstring-with-null : (
    out-bytes : Integer,
    tag       : BitString
  ) : ByteString =

  // suffix 0-7 null bits to fill the last byte
  // Then add a full null byte.
  str = extend-to-bytestring(tag) || "\x00"
  return cycle-bytestring(out-bytes, str)

cycle-bytestring : (
    out-bytes : Integer,
    str       : ByteString
  ) -> ByteString =

  if out-bytes <= 0:
      return ""
  else:
      n = byte-length(str)

      if n == 0:
          return (out-bytes * "\x00")
      else:
          (q, r) = div-mod(out-bytes, n)
          return ((q * str) || take-prefix(str, r))

```

If we unroll the demand-driven loop of `PHKDF-STREAM` a few steps, PHKDF conceptually looks like this:

```
PHKDF-STREAM (key, args, ctr, tag) =
  output0 = HMAC (key, encode(args) || encode_be32(ctr)     || tag)
  output1 = HMAC (key, output0      || encode_be32(ctr + 1) || tag)
  output2 = HMAC (key, output1      || encode_be32(ctr + 2) || tag)
  ...
  return output0 || output1 || output2 || ...
```

The interface of PHKDF-STREAM _superfically_ resembles the interface of HKDF, with the `key` corresponding to HKDF's salt parameter, `msgs` corresponding to the initial keying material (IKM), `tag` corresponding to `info`, and PHKDF-STREAM's `ctr` as kind of a little extra bonus `info` parameter:

```
HKDF (salt, ikm, info) =
  key = HMAC (salt, ikm)
  output1 = HMAC (key,            info || encode_u8(1))
  output2 = HMAC (key, output1 || info || encode_u8(2))
  ...
  output255 = HMAC (key, output254 || info || encode_u8(255))
  return output1 || output2 || ... output255
```

However, it is important to understand that this superficial resemblence is _deceiving_. The first thing to notice about `PHKDF-STREAM` is that it doesn't matter how secure the `args` parameter is, if you use a publicly known key, counter, and tag, then revealing a full output block reveals the remainder of the output stream.

This is in contrast to HKDF, which allows the secret initial keying material to be expanded into a large number of output blocks that can be arbitrarily partitioned into non-overlapping portions that may be revealed independently of each other.

Thus `PHKDF-STREAM` is actually a much lower-level hash function than `HKDF`. As such it has it's own _modes of operation_ that offer various different answers to the issue of output stream predictability.  Building a proper replacement for HKDF requires combining to or more calls to `PHKDF-STREAM` in different modes of operation.

The first and simplest mode of operation is discard all but the first output block. In this case, `PHKDF-STREAM` simplifies to a call to HMAC with the addition of TupleHash style encoding, and custom end-of-message padding determined by the counter and tag. Thus we can use this mode to
implement the key extraction portion of an HKDF-like hash function.

In this mode of operation, we can safely use `PHKDF-STREAM` with secret initial keying materials and optionally non-secret salt, counter, and tag, and possibly even reveal the output. After all it doesn't matter if anybody can predict the remainder of the stream if it's never been granted any meaning.

The second mode of operation is to use `PHKDF-STREAM` with a secret key, non-secret arguments, and optionally secret counter and tag.  In this mode, we can reveal arbitrary non-overlapping portions of the output stream to third parties, without worry that any portion can be derived from the others.

Thus we can implement a variant of the HKDF construction using these two modes of operation in conjunction with each other:

```
HKDF-SIMPLE
   ( salt : BitSttring
   , ikms : Vector BitString
   , tag  : BitString
   ) -> output : UnboundedByteStream

   echoArgs = ["hkdf-simple"]
   inputCtr = decodeBE32 "IN\x00\x00"
   outputCtr = decodeBE32 "OUT\x00"

   key = PHKDF-STREAM (salt, ikms, inputCtr, tag)

   return PHKDF-STREAM (key, echoArgs, outputCtr, tag)
```

However, we must be aware of the _echo args gotcha_: for reasons intimately related to the predictability of `PHKDF-STREAM` with a non-secret key, counter, and tag, the `echoArgs` parameter must not include any important new secrets.

This time we are deriving a secret key using initial keying material. However, if that material is potentially guessable, then introducing a high-entropy secret in the @echoArgs@ parameter will secure the first output block, but revealing two output blocks would re-reveal the ability to guess the original keying material.

Thus all secrets should be included in the derivation of the key, or possibly included in the tag parameter. A secret counter can also help, but cannot provide a sufficient level of entropy to secure the output all by itself.

One of HKDF's design principles was to obtain a clean seperation between the extraction and expansion phases.  This seperation allows HKDF's design to avoid the _echo args gotcha_ by specifying that `echoArgs` is the empty string.

In a literal, low-level sense, `PHKDF-STREAM` intentionally violates this seperation. In a metaphorical, higher-level sense, PHKDF affirms this design principle, rather PHKDF's goal is to allow a single primitive to serve both roles. This unification makes it easy to create cryptographic hash protocols where every call to HMAC is covered by a directly self-documenting plaintext tag.

Moreover, PHKDF's alternative to PBKDF2 is its slow extraction function `PHKDF-SLOW-EXTRACT`, which makes crucial use of the /echo args gotcha/.  That brings us to a third mode of operation, which keeps the output stream secret, except possibly for the very last output block examined.

In this way, you can safely use secret _args_ parameters with a publicly known _key_, _tag_, and _counter_ to start a predictable output stream at an unpredictable location. By keeping the output stream secret, _key stretching_ of the secret inputs can be achieved in a PBKDF2-like fashion while at the same time also providing _cryptoacoustic repetition_ of those publicly-known salts.  This construction combines all the best features of `TAGGED-PBKDF2-HMAC-SHA256`, `TAGGED-HKDF`, and `PBKDF2-TAGGED-HMAC`, which are the three starting points for our design.

The `PHKDF-SLOW-EXTRACT` function uses two calls to `PHKDF-STREAM`, the first to produce a pseudorandom stream that stays secret because it is immediately consumed by a second call to `PHKDF-STREAM`. Thus first output block of `PHKDF-SLOW-EXTRACT` is extra expensive to produce, but subsequent output blocks are computed just as quickly as the key-stretching blocks. The output stream of `PHKDF-SLOW-EXTRACT` suffers from the same issues of predictability as `PHKDF-STREAM`, so this too is a low-level construction that when used in this suggested way, it's output is also truncated to 32 bytes or remains secret.

`PHKDF-SLOW-EXTRACT` combines the output blocks of it's internal CSPRNG with SHA256; by contrast, PBKDF2 uses `xor`.  This means PHKDF's slow extraction routine requires the computation at least three SHA256 blocks per round, or possibly more if the tag is greater than 19 bytes long. PBKDF2 only requires two blocks per round.  Thus 250k rounds of PHKDF-SLOW-EXTRACT is likely roughly comparable in strength to 375k rounds of PBKDF2 for a short domain tag (0-19 bytes), or 500k rounds PBKDF2 equivalent for a medium-length domain tag (20-83 bytes).

Every additional 64 bytes of tag length likely adds another 125k rounds of PBKDF2 equivalence. On the other hand the most cautious comparison is direct: it would seem rather difficult to believe that 250k rounds of PHKDF-SLOW-EXTRACT is any less secure than 250k rounds of PBKDF2. In any case, if PBKDF2 or PHKDF is the sole key-stretching component of a prehash function, we recommend at least 375k rounds of PBKDF2 or 250k rounds of PBKDF.

These extra blocks that PHKDF requires can be computed in parallel with the internal CSPRNG.  Therefore, if an implementation can employ 1.5x parallel computation (or less for domain tags longer than 19 bytes), then this additional cost need not add any latency to the hashing computation.

PHKDF-SLOW-EXTRACT's suggested default counter value provides a word of blessing and encouragement to the tag that follows.  It does this for the year 2023 and every subsequent year for one more than the number of rounds specified, plus the number of output blocks examined.

```
PHKDF-SLOW-EXTRACT-HMAC-SHA256 : (
    key  : BitString,
    msgs : Vector<BitString>,
    tag  : BitString,
    ctr  : Word32 = decode_be32("go\x00\x00") + 2023,
    tags : Vector<BitString> = [],
    fn-name : BitString = "phkdf-slow-extract-v0",
    rounds  : Word32 = 250000
  ) -> UnboundedByteStream =

secretStream = PHKDF-STREAM-HMAC-SHA256 (
    key  = key,
    msgs = msgs,
    ctr  = ctr,
    tag  = tag
  )

phkdfLen = (rounds + 1) * 512

phkdfLenTag = left_encode(phkdfLen)

extFnNameLen = 32 - 2 - byte-length(phkdfLenTag)

extFnName = cycle-bitstring-with-null(extFnNameLen, fn-name)

fillerTag = cycle-bitstring-with-null(32, tag)

phkdfArg = ""

for _ in 0..rounds:
    phkdfArg ||= secretStream.read(bytes = 32)
    phkdfArg ||= fillerTag

// This must cleanly wrap around from 2^32-1 to 0
endCtr = ctr + rounds + 1

return PHKDF-STREAM-HMAC-SHA256 (
    key  = key
    msgs = [extFnName, phkdfArg] || tags
    ctr  = endCtr
    tag  = tag
  )
```

Fact: `PHKDF-SLOW-EXTRACT` can be implemented in constant space. This is because both the output of `PHKDF-STREAM`, and any input message of known length, are both streamable. This is left as an exercise for the reader, though you can refer to the author's sample implementation. This slow extraction function introduces a helper function, which are used in subsequent constructions.

`PHKDF-SIMPLE` implements a full HKDF-like construction by using `PHKDF-SLOW-EXTRACT` to derive a secret key to use in another call to `PHKDF-STREAM`, which generates final output which is much safer to reveal to semi-trusted third parties. This is analogous to the extract-then-expand construction `HKDF` and `HKDF-SIMPLE`, but now with key stretching analogous to `PBKDF2` and enhanced cryptoacoustic repetition.

`PHKDF-SIMPLE` uses variable-length parameter padding to all but eliminate timing side channels revealing the length of the username or password. The exact rules are a little complicated, but a very good approximation is that each input is constant time on 0-101 bytes, or constant time if their combined length is less than roughly 3-8 kilobytes, depending on the length of the long-tag.  Any overages cost one sha256 block per 64 bytes, thus keeping incremental costs to a minimum.

Moreover, as a low-level primitive, `PHKDF-SLOW-EXTRACT` allows the rounds parameter to be varied without fully recomputing its key-stretching parameter. The high-level `PHKDF-SIMPLE` remedies this situation by encoding the number of rounds into the initial inputs to the slow extract.

```
PHKDF-SIMPLE : (
    username : BitString,
    password : BitString,
    domain-tag : BitString,
    seguid : BitString,
    long-tag : BitString = domain-tag,
    credentials : Vector<BitString> = [],
    tags : Vector<BitString> = [],
    rounds : Word32 = 250000
  ) -> UnboundedByteStream =

phkdfTag = expand-domain-tag(domain-tag)

headerExtract = [ "phkdf-simple0 username", username ]

headerUsername = headerExtract || [
    username-padding(headerExtract, domainTag)
  ]

headerProtocol =
    "password-hash-key-derivation-function phkdf-simple0\x00"
    || left_encode(bit-length(domain-tag))
    || bare-encode(rounds)

headerLongTag = [ long-tag, headerProtocol ]

passwordPad =
    password-padding (
        headerUsername,
        headerLongTag,
        long-tag,
        domain-tag,
        password
    )

credentialsPad =
    credentials-padding (
        credentials,
        long-tag,
        domain-tag
    )

secretKey = PHKDF-SLOW-EXTRACT-HMAC-SHA256 (
    key = seguid,
    msgs = headerUsername
        || [ password ]
        || headerLongTag
        || [ passwordPad ]
        || credentials
        || [ credentialsPad ]
        || tags
        || [ encode-vector-length(tags) ]
    tag = phkdfTag,
    rounds = rounds,
    tags-1x = tags,
    fn-name = "phkdf-simple0 compact\x00" || domain-tag
  ).read(bytes = 32)

echoHeader = cycle-bitstring-with-null(30,"phkdf-simple0 expand echo")

return PHKDF-STREAM-HMAC-SHA256 (
   key = secretKey,
   msgs = [echoHeader] || tags,
   ctr = decode-be32("OUT\x00"),
   tag = phkdfTag
 )
```

The username and password padding is specifically designed so that the plaintext username need _not_ be known in order to crack the corresponding password hash. This built-in feature doesn't provide any significant level of key-stretching, and so is not a very strong defensive line on its own without being a part of larger, more holistic deployment considerations. If a deployment specifically wants to avoid this feature, they could say, put the username of their login flow into the "password" parameter of the G3P and vice-versa, swapping the suggested interpretations of these two parameters.

Being theoretically able to obscure the username might be useful as a damage-enhancement strategy in a court of law in cases where password hashes are stolen or otherwise disclosed: somebody who trafficks in password hashes can at least somewhat protect the privacy of the usernames of their victims. Failing to do so says something relevant about the trafficker. Of course this damage-enhancement strategy is more likely to be meaningful if everybody is aware of the possibility up front, which is a major reason why I wrote this paragraph.

The subroutines `encode-vector-length`, `bare-encode`, `expand-domain-tag`, `username-padding`, `password-padding`, and `credentials-padding` are all introduced in this protocol.  The first is used to unambiguously differentiate between the credential vector and the echo tag vector.  A design principle employed by these prehash protocols is that all the initial parameters must be unambiguously parseable from the initial extraction call to HMAC. This ensures that any change to the initial parameters require a complete recomputation of PHKDF's key stretching.

The use of `encode-vector-length` isn't strictly necessary for avoiding collisions in the overall PHKDF-SIMPLE protocol; however, omitting it would then admit trivial collisions in the initial extraction function by shuffling inputs between the end of the credentials vector and the beginning of the echo-tags vector.  This mean that the overall PHKDF-SIMPLE protocol would then be computable for multiple inputs without redoing the key-stretching computation.

It would be unlikely that the ability to cheaply shuffle a very specific input between these two vectors would be relevant to real deployments of the G3P, but this would still need to be properly documented. So, for the sake of keeping the interface documentation as concise and accurate as possible, and the interface as potent and as generally applicable as possible, we definitely want to avoid this early collision by suffixing the length of the echo-tags vector.

This design maximizes opportunities for streaming at the cost of requiring an unbounded-lookhead grammar to unambiguously parse the inputs to HMAC. This benefit is likely irrelevant, but this cost is almost certainly irrelevant. However, this choice does imply that the length tag needs to be locatable relative to the end of the overall `msgs` input vector. This is why these protocols always place the tagging vector length in the very last index.

```
encode-vector-length : (
    v : Vector<BitString>
  )  -> Vector<BitString> =

  return bare-encode(vector-length(v))

bare-encode : (n : NonnegativeInteger) -> ByteString =
  encode "n" in a minimum number of bytes, using big-endian notation.
  the common element of left_encode and right_encode, without a length field
  e.g.   0 = "\x00"
       127 = "\x7F"
       256 = "\x01\x00"
     65536 = "\x01\x00\x00"
  etc.
```

The next function, `expand-domain-tag` is used to add 0-63 extra bytes onto it's argument to ensure that the last block of the call to HMAC is filled.  This is particularly important as in context, this last block is likely to be repeated thousands of times within a relatively tight loop, so this step can significantly improve coverage of SHA256 blocks by self-documenting constants. However, the consequence is that the expanded tag does not necessarily encode the domain tag with 100% unambiguity. For this reason, our password prehash protocols encode the bit length of the raw, unprocessed domain tag in the first call to PHKDF.

Bitstrings that are 19 bytes or less are short enough to fit into PHKDF's iterated hash construction without triggering the computation of extra SHA256 blocks.  Thus there doesn't seem to be much benefit to cyclically extending such a tag to a full block.  Moreover, the tag as passed to PHKDF is also cycled to generate the variable-length end-of-message padding to HMAC messages, cyclically extending a short tag to a non-integer multiple of itself will in some cases change this padding.

```
expand-domain-tag : (
    tag : BitString
  ) -> ByteString =

  tag := extend-to-bytestring(tag)

  n = byte-length(tag)

  if n <= 19:
    return tag
  else:
    x = (19 - n) mod 64
    return cycle-bitstring-with-null(n + x, tag)
```

The third function, `username-padding`, hides the length of the username input and provides a short plaintext tag for the password input. This short tag ensures that whomever provides the password input must be provided with the first 32 bytes of the domain tag if they are to compute the SHA256 blocks corresponding to the password input themselves. It also has the effect of
flushing the SHA256 blocks containing the username, and synchronizing the
relative location of the SHA256 buffer thus masking the length of the password outside those blocks.

```
username-padding (
    headerExtract : Vector<BitString>,
    domain-tag : BitString
  ) =

  a = 157 - encoded-vector-byte-length(headerExtract)

  while (a < 32)
     a += 64

  return cycle-bitstring-with-null(a - 32, domain-tag)
      || cycle-bitstring-with-null(    32, domain-tag)
```

The fourth function, `password-padding`, is used to harden the username, password, and long-tag against any timing side channels except on multi-kilobyte inputs.  On these extremely long inputs, the overage incurs a cost of one SHA256 block per 64 bytes. This padding also ensures the first 32 bytes of the SHA256 block where the credentials vector starts is filled with the first 32 bytes of the domain tag.  This provides a short plaintext tag for that block, and synchronizes the buffer position.

```
password-padding (
    headerUsername : Vector<BitString>,
    headerLongTag  : Vector<BitString>,
    long-tag : BitString,
    domain-tag : BitString,
    password : BitString,
    bytes : Int = 8413
  )

  a = bytes - encoded-vector-byte-length(headerLongTag)

  while (a < 3240)
    a += 64

  a -= encoded-vector-byte-length(headerUsername)

  while (a < 136)
    a += 64

  a -= encoded-byte-length(password)

  while (a < 32)
    a += 64

  return cycle-bitstring-with-null(a - 32, long-tag)
      || cycle-bitstring-with-null(    32, domain-tag)
```

The fifth function, `credentials-padding`, comes in between the credentials vector and the tags vector.  It hardens the credential vector against timing side channels, and provides a short tag to the tags vector.  This tag is only 29 bytes long as to maximize the amount of tagging bytes (0-63) that operate in constant time, given that the tags vector is then followed by the end-of-message padding that is built into `PHKDF-STREAM`.

```
credentials-padding (
    credentials : Vector<BitString>,
    long-tag : BitString,
    domain-tag : BitString
  )
  a = 122 - encoded-vector-byte-length(credentials)

  while (a < 32)
    a += 64

  return cycle-bitstring-with-null(a - 29, long-tag)
      || cycle-bitstring-with-null(    29, domain-tag)
```

The next protocol, PHKDF-PASSWORD, adds a role. This parameter is a tweak that can be repeatedly and robustly applied without recomputing the expensive part of hash function.  Changing other parameters require starting over from the beginning. The role is useful for implementing domain seperation within the context of a single authentication service, among other possible use cases.

```
PHKDF-PASSWORD (
    username : BitString,
    password : BitString,
    credentials : Vector<BitString> = [],
    seguid : BitString,
    domain-tag : BitString,
    long-tag : BitString = domain-tag,
    seed-tags : Vector<BitString> = [],
    rounds : Word32 = 250000,

    role : Vector<BitString> = []
    echo-tags : Vector<BitString> = seed-tags,
  ) -> UnboundedByteStream

phkdfTag = expand-domain-tag(domain-tag)

headerExtract = [ "phkdf-pass-v0 username", username ]

headerUsername = headerExtract || [
    username-padding(headerExtract, domainTag)
  ]

headerProtocol =
    "password-hash-key-derivation-function phkdf-pass-v0\x00"
    || left_encode(bit-length(domain-tag))
    || bare-encode(rounds)

headerLongTag = [ long-tag, headerProtocol ]

passwordPad =
    password-padding (
        headerUsername,
        headerLongTag,
        long-tag,
        domain-tag,
        password
    )

credentialsPad =
    credentials-padding (
        credentials,
        long-tag,
        domain-tag
    )

secretSeed = PHKDF-SLOW-EXTRACT-HMAC-SHA256 (
    key = seguid,
    msgs = headerUsername
        || [ password ]
        || headerLongTag
        || [ passwordPad ]
        || credentials
        || [ credentialsPad ]
        || seed-tags
        || [ bare-encode(vector-length(seed-tags)) ]
    tag = tag,
    rounds = rounds,
    tags-1x = seed-tags,
    fn-name = "phkdf-pass-v0 compact\x00" || domain-tag
  ).read(bytes = 32)

secretKey = PHKDF-STREAM-HMAC-SHA256 (
    key = seguid,
    msgs = [ "phkdf-pass-v0 combine" || secretSeed ]
          || role || echo-tags,
    ctr = decode-be32("KEY\x00"),
    tag = tag
  ).read(bytes = 32)

return PHKDF-STREAM-HMAC-SHA256 (
    key = secretKey,
    msgs = echo-tags,
    ctr = decode-be32("OUT\x00"),
    tag = tag
  )
```

In order to avoid the _echo args gotcha_, the expansion subroutine of PHKDF-PASSWORD hashes the plaintext of the _echo tags_ twice: once to derive the secret key used to produce the final output, and then once as the _echo args_ for that final output expansion call.

We don't bother unambiguously encoding the `role` and `echo-tag` vectors in expansion subroutine of PHKDF, which is resolved in the last call. Because we are done with key-stretching at this point, we depart from our precedent of using `encode-vector` to immediately resolve the ambiguity. Instead, we defer the disambiguation until the last call, and gain three additional bytes of free tagging space.

PHKDF-PASSWORD is very close to the final G3P protocol, the major difference being that the G3P incorporates bcrypt. The problem with PBKDF2, and by extension PHKDF, is that they are good at adding latency but can also be inexpensively parallelized. This is the worst possible combination, as legitimate users are particularly cost-sensitive to serial latency, but password crackers are particularly cost-sensitive to parallel throughput.

Users are going to be upset if every password attempt takes ten seconds to answer. That's far less upsetting to an attacker that can afford a machine that can try a million password guesses in parallel. That's still an average cracking rate of a 100k password guesses per second, enough to crack a seven-digit PIN in a minute or two, or a ten-digit PIN in not more than 28 hours. A ten-digit pin is approximately equivalent to a three-word passphrase selected from one of EFF's shortlists, which have 6^4 = 1296 words.

## G3P Protocol

Because PHKDF is not a particularly effective expenditure of latency, the G3P incorporates a single fully encapsulated call to bcrypt as its primary key-stretching component.  As of the writing of this paper, given a latency budget less than about 0.25 seconds, bcrypt is empirically one of the best expenditures of that latency among well-established password hash functions.

Bcrypt's partial cache-hardness means that building and operating a bcrypt password cracker is going to be particularly expensive relative to the level of parallelism achieved. Within the G3P, bcrypt is primarily used as an expensive compression function. Bcrypt is secondarily used as another cryptographically self-documenting construction in order to reinforce and hedge the self-documenting properties of PHKDF.

To derive the inputs for bcrypt's password and salt parameters, PHKDF-SLOW-EXTRACT is used to generate two sets of 16 pseudorandom bytes to which the bcrypt tags are appended. These tags are either truncated or cyclicly expanded to 56 bytes. This truncation does not lead to trivial collisions, because each bcrypt tag is also included in the initial inputs. Thus varying this tag also requires recomputing those two set of 16 pseudorandom bytes, which requires PHKDF's key-stretching computation to be redone.

This rather nonstandard arrangement turns bcrypt into an expensive compression function that turns 32 pseudorandom input bytes into 24 pseudorandom output bytes, and improves the utilization of bcrypt's cryptoacoustic transmission potential. Moreover, changing any of the bcrypt tag or rounds parameters requires a complete recomputation of those 32 pseudorandom input bytes.

Finally, a seed is created by hashing another 32 pseudorandom bytes from PHKDF-SLOW-EXTRACT with bcrypt's 24-byte output. Other than this use of bcrypt, and different choices for protocol constants and how to fill in padding in certain locations, the G3P is largely the same as PHKDF-PASSWORD.

The G3P actually uses a mildly generalized variant of bcrypt that allows for any number of rounds between `1..2^32`, not just powers of two of index `0..31`. This allows for finer-grained tuning of the cost parameter. Choosing `4095` as G3P's `bcrypt-rounds` parameter corresponds exactly to the traditional bcrypt cost parameter of `12`, because `4095 = 2^12 - 1`.

We recommend that a deployment of the G3P specify 4000 rounds of bcrypt, give or take a factor of four or so, corresponding to a traditional bcrypt cost parameter of 10-14. We also suggest cutting down the number of PHKDF rounds by an order of magnitude relative to PHKDF-PASSWORD, to about 20,000 rounds, give or take a factor of two or so. Note that each individual bcrypt round is significantly more expensive than an individual PHKDF round, so if you use these suggested parameters, the main computational cost is bcrypt.

If the latency budget is increased to about one second or more, argon2 becomes one of the empircally best expenditures of latency among well-established password hash functions. As an alterative to significantly increasing the PHKDF and/or Bcrypt cost parameters, cybersecurity engineers should consider incorporating a memory-hard password hashing function such as argon2 into the larger hashing protocol.

```
G3P-HASH : (
    username : BitString,
    password : BitString,
    credentials : Vector<BitString> = [],
    seguid : BitString,
    domain-tag : BitString,
    long-tag : BitString = domain-tag,
    bcrypt-tag : BitString = take(56, domain-tag),
    bcrypt-salt-tag : BitString = bcrypt-tag,
    seed-tags : Vector<BitString> = [],
    phkdf-rounds : Word32 = 20240,
    bcrypt-rounds : Word32 = 4095,

    role : Vector<BitString> = []
    echo-tags : Vector<BitString> = seed-tags,
  ) -> UnboundedByteStream =

phkdfTag = expand-domain-tag(domain-tag)

headerExtract = [ "G3Pb1 alfa username", username ]

headerUsername = headerExtract || [
    username-padding(headerExtract, domainTag)
  ]

bcryptHeader = [ bcrypt-tag, bcrypt-salt-tag ]

headerProtocol =
    "global-password-prehash-protocol version G3Pb1"
    || left_encode(bit-length(domain-tag))
    || left_encode(phkdf-rounds)
    || bare-encode(bcrypt-rounds)

headerLongTag = [ long-tag, headerProtocol ]

bytes = 8413 - encoded-vector-byte-length(bcryptHeader)

while (bytes < 8295)
    bytes += 64

passwordPad =
    password-padding (
        headerUsername,
        headerLongTag,
        long-tag,
        domain-tag,
        password,
        bytes
    )

credentialsPad =
    credentials-padding (
        credentials,
        bcrypt-tag,
        bcrypt-salt-tag
    )

secretStream = PHKDF-SLOW-EXTRACT-HMAC-SHA256 (
    key = seguid,
    msgs = headerUsername
        || [ password ]
        || bcryptTags
        || headerLongTag
        || [ passwordPad ]
        || credentials
        || [ credentialsPad ]
        || seed-tags
        || [ encode-vector-length(seed-tags) ]
    tag = phkdfTag,
    rounds = phkdf-rounds,
    tags-1x = seed-tags,
    fn-name = "G3Pb1 bravo\x00" || domain-tag
  )

// re-expand the output of G3Pb1 compact bravo

phkdfHash  = secretStream.read(bytes = 32)

bcryptPass = secretStream.read(bytes = 16)
          || cycle-bitstring-with-null(56, bcrypt-tag)
bcryptSalt = secretStream.read(bytes = 16)
          || cycle-bitstring-with-null(56, bcrypt-salt-tag)
bcryptHash = bcrypt ( bcryptPass, bcryptSalt, bcrypt-rounds )

// G3Pb1 combine charlie
// combine the two hashes to get a secret seed

secretSeed = PHKDF-STREAM-HMAC-SHA256 (
    key = seguid,
    msgs = [ "G3Pb1 charlie" || phkdfHash ||
             cycle-bitstring-with-null(56, bcrypt-salt-tag) || bcryptHash ||
             cycle-bitstring-with-null(32, bcrypt-tag)
           ]
          || seed-tags,
    ctr = decode-be32("SEED"),
    tag = phkdfTag
  ).read(bytes = 32)

// G3Pb1 revise delta
// combine the seed and a role to get a secret key

secretKey = PHKDF-STREAM-HMAC-SHA256 (
    key = seguid,
    msgs = [ "G3Pb1 delta" || secretSeed ]
          || role
          || echo-tags,
    ctr = decode-be32("KEY\x00"),
    tag = phkdfTag
  ).read(bytes = 32)

// finally, G3Pb1 expand echo:

return PHKDF-STREAM-HMAC-SHA256 (
    key = secretKey,
    msgs = echo-tags,
    ctr = decode-be32("OUT\x00"),
    tag = phkdfTag
  )
```

## Deployment considerations

A "deployment" specifies how to use the G3P in some context.  While effort was taken to give parameters a suggestive name, the interpretation and usage of any given parameter is ultimately defined by a deployment, not this standard. It is not inherently "wrong" to use any parameter in a way that differs from these suggestions, though of course there are problems that can be introduced by a specific deployment.

The G3P protocol purposefully punts on issues relevant to a deployment-ready authentication flow, including:

* username normalization
* password syntax
* syntax for putting prehashes into password boxes/login forms

Taking a lesson from the bcrypt experience, these issues are probably best left to be specified by the deployment itself.  Here are a few recommendations:

* username normalization can be arbitrary, but must be _consistently implemented_, _everywhere_!
    * Keeping normalization simple is _highly_ recommended
    * Consider offering server-side RPCs and reference implementations

* Even if the username is usually not a secret, there can be contexts in which it's still best kept private
    * Consider seperating screen names from login names
    * Screen names are typically shared with other users, at least in some contexts
    * Screen names often (but don't always) serve as something akin to an address, like a phone number or email
    * Consider keeping login names private-ish
    * Users can use private login names to guard against minor privacy leaks that arise from the login process itself

* sticking to UTF8-encoded passwords recommended, to avoid bcrypt-like issues

* Bech32 syntax recommended for putting prehashes into password boxes

Finally:

* educate users about operational security
    * random passphrases
    * two-factor authentication
    * publish a public playbook
        * make relevant, high-quality documentation freely available
        * documents should be specific to a deployment context
        * discuss how various behaviors impact opsec
        * be clinically accurate about implications
        * be (relatively) judgement-free
        * make clear recommendations, and explain why

## Future Work

Version 1 of the G3P was primarily designed to be something concrete and specific that I would interested in deploying myself.  Version 1 was secondarily designed to accommodate the guidance of the National Institute of Standards and Technology (NIST) regarding password handling, produce something that might be easy for NIST to approve of in the future, and stick as much as possible to cryptographic primitives that have been extensively studied and have stood the test of time.

PBKDF2 and bcrypt are both viable modern candidates for password security despite the fact they were both invented decades ago.  However, they have their own rather distinct practical shortcomings. The G3P weaves both technologies together in ways that they cover for the weaknesses of the other, in ways that they hedge the strengths of the other, and in ways that go beyond contemporary standards for password security.

In this light, it seems like a good time to revisit a number of password hashing practices. Furthermore, some of the guidance offered by NIST is somewhat contradictory, or not up to date with the current state of the art outside the world of FIPS compliance.

Designing self-documenting cache-hard and memory-hard password hash functions seems like a fruitful and important line of research. Bscrypt and argon2 are two particularly interesting password hash functions. While they would seem to be logical choices for future variants of the G3P, unfortunately they are both rather dead, cryptoacoustically speaking. There is simply no way to achieve cryptoacoustic repetition without some relatively delicate modifications of these functions.

Version 1 itself is likely to have one or more officially-endorsed extensions developed for it.  One extension currently planned will include detailed recommendations about how to best implement second secrets via the `credentials` vector, directly inspired by 1password's two-secret key derivation (2SKD).

## History

As I have contemplated password authentication over the years, I have long had a growing but difficult-to-articulate hunch that the traditional password salting methodology was paying a rather substantial design cost but not receiving much benefit in return.

This was especially true in the context of client-side prehashing, which I have had a longstanding interest in. In context, revealing a salt to an authenticating party who is attempting to log into a given account can reveal things such as the existence or non-existence of an account, or if a password has changed. Of course whether or not these issues actually manifest depends on precise implementation details, but these are sorts of issues that are all but guaranteed to arise in any careless design or implementation of a prehashing protocol.

As somebody who with longstanding interests in communications, signals, and acoustics, the process of designing the G3P was a bit like designing a sound system.  Discerning the plausible tagging constructions of HMAC-SHA256 was like figuring out how to build voice coils and drivers. Designing PHKDF was like converging upon a highly efficient horn-loaded design for a tweeter/midrange loudspeaker unit.  Adding bcrypt was like adding a big subwoofer and endeavoring to accommodate the neighbors.  Making bcrypt's integration a self-documenting construction was like finally solving the riddle of properly integrating all that bass into a listening setup so that it sounds really good.

This somewhat fanciful analogy was made in retrospect, so the metaphor does not describe a literal causal model of my historical, in-the-moment creative thought processes. Even if this metaphor doesn't work this specific sense, there is a common causal factor in my thought processes on both sides of the cryptoacoustic analogy. My intuition for communications and signals and transmission mediums undergird my thinking on both topics. Also, the temporal order in which my ideas were developed basically matches the order given above.

Because my the path of my thinking about self-documenting cryptography was long and fuzzy, it's difficult for me to give a highly detailed account of how I arrived at the G3P. Shortly before I started work, my most distinctive experience was having my subconcious yell at me with ever increasing volume that there does exist a robust channel of communication from deployments to observers, and I needed to find and develop it.  Which was weird because I really lacked the vocabulary to put my thoughts into words at time, so it was more like a highly pointed, gutwrenching feeling.

Once I started work in earnest, deeper insight came slowly.  That insight was often the long slow result of rewriting of the "why", then rewriting the "how", and then incessantly alternating those two processes until I converged on a result I was satisfied with.  That took many months, with deeper insight often coming about once a month or so.

The larger topic of self-documenting cryptography really brought together lines of thought that for me originated in four very different subjects: optics, number theory, the theory of computation, and programming languages.

For me, optics at was an introduction to signals in disguise. Number theory introduced me to RSA, and got me thinking about digital identity in particular and more deeply about cryptography in general. Once I started looking for a workable way to send a watermark-type signal from deployments to observers, my experience with programming languages and abstract interpretation made it trivally easy for me to recognize that adding a suffix to externally-supplied SHA256 input is a plausibly secure plaintext tagging construction.

I found the theory of computation to be indispensible when designing the syntax of PHKDF and the G3P to be safe and secure.  I spent quite a bit of time trying to keep TupleHash syntax out of the G3P, but the theory of computation lead me to believe that incorporating something like TupleHash was not optional given my design goals.

## Acknowledgements

I would particularly like to thank both Soatok and Steve "sc00bz" Thomas for a number of fruitful online interactions that profoundly influenced this work.  I would especially like to thank sc00bz for sharing his insights from his practical research into password cracking, and for developing bscrypt.

I would also like to thank Troy Hunt. I doubt my invention of self-documenting cryptography would have happened without the existence of Have I Been Pwned. It was Troy's effort to document the terrible state of password cybersecurity that provided me a clue of what payoff the traditional salting process was missing out on. Troy Hunt helped inspire my idea to modify the password hashing process to build a closer approximation to a closed loop detector for leaked password hashes.

## Bibliography

TODO: Format this more properly

NIST Special Publication 800-185

NIST Special Publication 800-108r1

https://tools.ietf.org/html/rfc3490

https://tools.ietf.org/html/rfc3986

https://tools.ietf.org/html/rfc5869

https://tools.ietf.org/html/rfc6530

https://tools.ietf.org/html/rfc8018

https://blog.cryptographyengineering.com/2014/02/21/cryptographic-obfuscation-and/

[^require-prehashing]:
    Requiring prehashing is a potent and consequential move for an authentication service, but it's also important to point out the servers cannot verify that a purported "prehash" was actually computed via any particular cryptographic hash function. The best that the servers can do is to ensure that the prehash "looks right": i.e. has the correct length and format and passes one or more entropy estimation checks whenever the password is set.

    Indeed, in cases where an account is only ever used in conjunction with a password manager, it benefits both the user and the authentication service for the password manager to circumvent the prehash function altogether, and simply generate a "prehash" uniformly at random.  This "prehash" effectively has no plaintext password associated with it.  The only way to "crack" such a prehash is to conduct a successful preimage attack on the cryptographic hash function itself, inventing a plaintext password where there was none before.  This is part of the reason why the G3P strongly recommends that deployments specify syntax and mechanisms so that login boxes and forms can accept prehashes directly.

    There are strong security and compatibility incentives to implementing the recommended prehash function for a domain. While substituting another suitable prehash function is in some senses "harmless" and arguably even beneficial to the authentication servers, such shenanigans are best restricted to password managers.  Implementing unsanctioned hash functions directly in a software client has huge potential to create user support issues with often dubious security benefits, so in other senses it is harmful to the authentication service as a whole.

[^reduced-round-attacks]:
    Such a simplistic lie is certainly not the only kind of lie that can be told about a domain tag. Probably the most interesting lie I can think of that might somehow sorta work in some fuzzy, unknown hypothetical scenario, is to ask a G3P authenticator for some password with the correct domain tag, but with a substantially reduced number of rounds. This first login attempt will fail, but then the attacker is presumably doing this to obtain a much less expensive guessing attack on the plaintext password associated with that domain tag, which might then be usable to bootstrap attacks elsewhere.