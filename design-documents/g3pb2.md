# The Global Password Prehash Protocol (G3P), Version 2

# Introduction

The Global Password Prehash Protocol (G3P) version 2 (G3Pb2) is a slow password
hash and key derivation function based on HMAC-SHA256 and blowfish, using
variants of PBKDF2, HKDF, and bcrypt that have been minimally modified in
order to better support self-documenting cryptography. Also, the G3P is
explicitly designed to support keying end-to-end encryption (E2EE) off of the
password, so long as the G3P is deployed as a client-side prehash.

In this context, self-documenting cryptography aims to make password hashes[^comparable-to-hashes] _traceable_ or _useless_ after they have been stolen by an evesdropper, Eve.

Let's say Alice is an IT administrator works for Acme Corporation, Inc. The
basic idea is to add "this password is for Acme Corporation, Inc." as a tag
onto the end of every password before it is hashed. This happens automatically
and outside the control of the user, leaving an indelible fingerprint on the
resulting hash.

This fingerprint means that a password cracker must add on "this password is
for Acme Corporation, Inc." onto the end of every guess, otherwise they are
automatically guessing the wrong password. And if the cracker is guessing
that "this password is for Acme Corporation, Inc.", then it should be possible
to contact Acme and say, "Hey, we think we may have come across some of your
stolen password hashes".

This is an example of Adversarial Literate Programming: Alice gets to specify
an algorithm with some associated documentation. Eve wants to provide Craig
the ability to run Alice's algorithm on his own hardware, while denying Craig
access to Alice's documentation.

The security goal of Adversarial Literate Programming is to force Eve to
provide Craig a sporting chance of recovering Alice's documentation from Eve's
instruction, or force Eve to give up on the idea of letting Craig run Alice's
algorithm himself.

In theory it should be possible for Eve to use some flavor of Homomorphic
Encryption to construct an implementation of Alice's algorithm that securely
hides the fact that "this password is for Acme Corporation, Inc." from Craig.
For example, people have demonstrated being able to compute a few blocks of
SHA-256 inside Fully Homomorphic Encryption (FHE) within a few seconds.

While most forms of Homomorphic Encryption impose significant overhead, FHE is
in a class of its own. It is normally possible to compute millions of SHA256
blocks within a few seconds even on modest hardware. The overhead of even
state-of-the-art FHE is extreme, often increasing the time and resources needed
to perform a computation by a factor of a 100,000 or more.

However, the suprising existence of FHE, and the fact that it can in theory
obscure any computable algorithm whose output itself doesn't give away secrets,
suggests that it might not even be possible to stake Adversarial Literate
Programming's  security goal on an asymptotic difference in the complexity of
algorithms. Rather, Adversarial Literate Programming may be limited to a linear
factor, making its security margin relatively weak for cryptography. I would
even say that acheiving a traditionally-strong security margin in the context
of Adversarial Literate Programming seems implausible.

On the other hand, password cracking is sensitive to even modest overhead.
In this context, FHE doesn't seem to be any immediate threat to Adversarial
Literate Programming based on standard on standard cryptographic primitives
like SHA-256 and blowfish.

In fact, a topic of research in FHE is the construction of homomorphic
transciphers, which are alternative cryptographic primitives designed to be
relatively efficient when executed inside FHE. Perhaps alternative
cryptographic primitives designed to be particularly _in_efficient when
executed inside any suitable method of homomorphic encryption should also
be pursued as an anti-problem.

While I don't know how much better future Homomorphic Encryption schemes might
be able to perform on SHA-256 and blowfish, I'm not expecting revolutionary
improvements in efficiency in the near future, and thus I'm expecting FHE will
remain a less-than-practical threat for some time to come. On the other hand,
the threat of FHE is also significant enough that the design of the G3P
needs to take it into account.

In particular, argon2 is not particularly secure in the sense of Adversarial
Literate Programming. All of the inputs to argon2 are hashed in a single call
to Blake2, and that resulting hash is the only thing needed to compute argon2's
key-stretching phase.

While this is sufficient for domain separation purposes, it's not enough
for adversarial literate programming. Eve could simply hide Acme's tag and
other parameters inside an FHE-based implementation of this initial call to
Blake2, and return the plaintext hash needed for key-stretching.

Now, Craig _might_ be able to still determine the parameters hidden inside FHE
by computing a hash with a known password and then cracking the unknowns.
This approach can be facilitated when Craig is aware of Alice's documentation
among others but is not yet aware that Alice's documentation is immediately
relevant.

However, this requires more sophistication and often more computation on
Craig's part compared to reverse engineering Alice's documentation from Eve's
implementation. Furthermore, if the additional parameters hidden inside FHE
include say, a random 16-byte salt for account separation purposes, then this
approach to recovering Alice's documentation won't work.

While the overhead to compute this initial call to Blake2 inside FHE would be
substantial, it still might be low enough that Eve would consider deploying FHE
to hide Alice's argon2-backed documentation from Craig in an obfuscation attack.

For this reason, the G3P is designed such that Alice's documentation is
required throughout the entire key-stretching process. Ideally, the only way
for Eve to carry out a secure obfuscation attack would be to run the entire
key-stretching process in Fully Homomorphic Encryption, thus maximizing the
computational overhead inflicted on Craig by Alice and Eve.

# Simplified Overview

This section elides certain details, including some of the auxiliary inputs
and all length-related padding, from the construction of the G3P. Thus this
section is not intended to be suitable as an implementation reference.

The key-stretching phase of the G3P is an iterated HMAC-SHA256 construction.
The first form of key-stretching is very PBKDF2-like.[^pbkdf2-tagged-hmac]
PBKDF2's CSPRNG generator is show below, followed by the modified generator
which takes a signficant amount of inspiration from HKDF.

    i = (output block number, typically 0 but also [1..] for longer outputs)
    U 1 = HMAC (Password, Salt + INT_32_BE(i))
    U 2 = HMAC (Password, U 1)
    ⋮
    U c = HMAC (Password, U (c−1))

    i = 1196361704
    T 0 = HMAC (Seguid, "G3Pb2 alfa" +
                      + UserSalt + Password + LongTag + Credentials
                      + ContextTags + INT_32_BE(i) + DomainTag )
    T 1 = HMAC (Seguid, T 0 + INT_32_BE(i + 1) + DomainTag )
    ⋮
    T c = HMAC (Seguid, T (c-1) + INT_32_BE(i + c) + DomainTag )

One of the most obvious differences is that the parameter that PBKDF2 calls the
"password" is now called the "seguid". Instead of using the actual password as
an HMAC key, the G3P recommends using the seguid as a supplemental salt. The
G3P suggests moving the actual password into the parameter that PBKDF2 calls
"salt". Furthermore, the G3P's password is both prefixed and suffixed with
additional forms of salt and length padding.

An advantage to moving the password is that it can be forgotten as soon as it
has been hashed the first time, and need not be preserved until the end of
key-stretching.

The use precomputed HMAC keys avoids the need to preserve PBKDF2's "password"
throughout the computation. However, precomputed HMAC keys apply no
key-stretching, so effectively none of the key-stretching work accrues to the
intermediate state until the HMAC key is forgotten after the end of
key-stretching.

By contrast, this change means that a single cracking attempt against any
minimal intermediate state of the G3P is always nearly as expensive as the
computation required to generate that intermediate state. This in turn
allows the key-stretching computation to be transferred to another trusted
device without providing that device with a cracking attack on the plaintext
password that is significantly less expensive per guess than the work already
done.

PBKDF2 then xors the blocks `U 1 ^ U 2 ^ ... ^ U c` to generate its final
output block.  The G3P does the same, but then it derives two cryptographically
independent keys from the result:

    c = (number of PHKDF rounds, ideally ~20000 or so)
    sumT = T 0 ^ T 1 ^ ... ^ T c
    endT = T (c+1)
    keyB = HMAC (SeguidB, "G3Pb2 bravo" +
                          "B" + endT + sumT + ContextTags + "KEYB" + DomainTag)
    keyC = HMAC (SeguidB, "G3Pb2 bravo" +
                          "C" + endT + sumT + ContextTags + "KEYC" + DomainTag)

Now, we are ready for the second form of key-stretching, which uses a
bcrypt-like construction. Overall, this key-stretching phase looks like
a single call to HMAC:

    seed = HMAC (SeguidB, "G3Pb2 charlie"
                        + keyB + bcryptOutput
                        + keyC + ContextTags + "SEED" + DomainTag)

The inclusion of continuation control key ("keyC") allows for some or all of
the bcrypt key-stretching computation to be outsourced to another semi-trusted
device without losing control of the final seed.

Here, `bcryptOutput` is one or more binary blobs largely consisting of
bcrypt's P-box and S-box, with one blob for every super-round. There is one
super-round for every 128 bcrypt rounds, rounded up.

    msg   = ""
    state = (standard bcrypt initial state based on digits of pi)

    for each super-round:
       key0   = HMAC ( SeguidB, "G3Pb2 charlie"
                              + keyB + msg + BcryptTags + "KEY0" + DomainTagB )
       msg   += key0
       key1   = HMAC ( SeguidB, "G3Pb2 charlie"
                              + keyB + msg + BcryptTags + "KEY1" + DomainTagB )
       msg   += key1
       state := bcryptSuperRound ( state, key0, key1, LongTagB )
       msg   += state

    bcryptOutput = msg

Note the key and initial message prefix that is shared across all calls to
HMAC. In fact, for a secure implementation, the HMAC function must be
computed using streaming and backtracking. This has the added benefit of
reducing the memory required to compute the bcrypt key-stretching phase to a
constant ~4268 bytes[^byte-estimate] or so.

The transition between each superround serves as a synchronization
point[^minimal-continuation] where cracking an intermediate state costs very
nearly as much per guess as computing that intermediate state, thus allowing
the transfer of a partial bcrypt computation to another semi-trusted device
without providing that device a cracking attack on the plaintext password
that is significantly cheaper per guess than the work already performed.

By contrast, in the middle of the super-round, not only can key0 and key1
be cracked directly, it is possible to run the bcrypt state machine in
reverse, which can be shared across multiple guesses. It is the act of
forgetting key0 and key1 at the end of each super-round that renders this
irreversible, [^streaming-hmac-sha256] allowing the ratchet of key-stretching
to make progress.

Once we have completed the computation of the seed, the role vector provides
a last-minute opportunity for domain separation before final output expansion:

    keyL = HMAC ( SproutSeguid, seed + Role + "KEYL" + SproutTag )

    out0 = HMAC ( keyL + KeyR, EchoHeader + INT_32_BE(EchoCounter) + EchoTag )
    out1 = HMAC ( keyL + KeyR, out0 + INT_32_BE(EchoCounter + 1) + EchoTag )
    out2 = HMAC ( keyL + KeyR, out1 + INT_32_BE(EchoCounter + 2) + EchoTag )
    ...

This construction resembles HKDF-SHA256, with the computation of `keyL`
corresponding to HKDF-Extract, and the output blocks corresponding to
HKDF-Expand.

However there are a handful of mostly minor changes: we are using a
parameterized 4-byte counter before the domain tag, whereas HKDF uses a
hardcoded 1-byte counter after the info tag. Furthermore, this construction
also parameterizes of the right 32 bytes of the output key as well as
the 32-byte initial generator state.

Note a trivial collision can be obtained by feeding an output block
back into the Header parameter and by incrementing the counter by one, which
is the same thing as the next output block. There are other issues the Header
parameter is associated with, but it is also not particularly difficult to
use safely: see the reference implementation's API documentation for
details and suggestions.

Very much like HKDF-SHA256, these final steps perform no key-stretching, so
they are very fast relative to the computations required to compute the seed.
This means a large quantity of cryptographically independent output blocks can
be efficiently generated from a single key-stretching computation, something
that the suggested way of producing longer outputs with the original PBKDF2
fails at.

# Deployment Considerations:

A deployment designer may notice that the Global Password Prehash Protocol has
no less than 21 parameters. This may seem excessive, but the thing to remember
is that the G3P is carefully designed so that almost every parameter must be
an exact match. Any difference means the outputs will be cryptographically
independent to any efficient observer who isn't privy to all the inputs.

There are a few exceptions, but they are all documented: there are some trivial
(but largely uninteresting) "collisions" involving HMAC-SHA256 keys. This
behavior is externally dictated by relevant standards. Additionally, there are
truncation and other gotchas associated with the echo-header and echo-key
parameters, which are used to tweak the final output hash. All other collisions
on the G3P are cryptographically non-trivial.

All parameters fall into one of five categories: things needed only _once_ near
the beginning of the computation, things needed _sporadically_ throughout a
computation, things needed _constantly_ throughout a computation, parameters
that determine how _expensive_ a key stretching phase will be to compute, and
parameters that can be used to efficiently _tweak_ the output after
key-stretching has been performed.

Additionally, there is a visibility graph between parameters. For example,
being able to specify the "username" and compute the output hash yourself on
your own hardware implies that your computer must know every other parameter.
Being able to specify the "password" implies knowledge of every parameter
other than the "username", the plaintext of which can be hidden using partial
evaluation.

Your computer must know the plaintext of any "tag", if you are specifying
either the username or password. However, plaintext HMAC-SHA256 keys can always
be replaced with two intermediate SHA256 states via parital evaluation.

These intermediate states are essentially two SHA256 hashes of the plaintext
HMAC key. As these are constant and must be known to your computer, using
self-documenting globally unique identifiers (seguids) as HMAC-SHA256 keys
allow you to indirectly convey a message via these intermediate states.
This approach happens to be the only way to include a self-documenting
domain separation constant in the computation of HMAC's outer pad.

# Major changes since Version 1:

1.  In PHKDF version 1's slow extract function, the block generator was
    summarized with hmac-sha256.  The G3P version 2 does not use this function,
    and instead summarizes its block generator using xor, bringing it much
    closer to PBKDF2.

    One of the unfortunate consequences of using sha256 to consume the output
    blocks of PHKDF's generator is that cracking attacks on the intermediate
    state need not compute this summary. Thus, the key-stretching benefit of a
    third[^domain-tag-length] of SHA256 blocks did not accrue until after the
    computation of slow-extract is complete.

    In the new version, a cracker on an intermediate state can choose to attack
    either the xor-sum or the extension code. If a cracker attacks the xor-sum,
    the computation of the last PHKDF round can always be elided.

    If the cracker attacks the extension code instead, they'll need to compute
    one more round of PHKDF, but can elide the computation of the xor-sum.
    One round of PHKDF is a constant amount of additional work while
    maintaining a xor-sum of all generated blocks is a linear amount of work,
    however, one round of PHKDF is at least two SHA256 block computations,
    which is a comparable amount of work as tracking the xor-sum over a
    large number of PHKDF output blocks.

    Either way, compared to version 1, this is a relatively small
    difference between the effort required to create an intermediate state
    and the effort required to make a single cracking attempt against
    that intermediate state.  (I really need to work on a pithier way of
    referring to that particular constraint on the internal streaming
    structure (topology?) of the hashing algorithm.)

2.  Bcrypt's integration has been entirely reworked, using an enhanced
    salting process.

    The new process uses HMAC-SHA256 to derive independent KEY0 and KEY1 which
    are xor-ed into the P-box of blowfish, alternating every half-round key
    expansion. This is exactly how the "password" and "salt" parameters are
    treated in the original bcrypt.

    However, whereas every key expansion encrypted a string of null bytes,
    the new integration encrypts the bcrypt long tag parameter as an extended
    plaintext salt. Technically speaking, this encryption is the Blowfish
    block cipher used in a variant of cipher block chaining (CBC) mode that
    additionally incorporates a key feedback mechanism.

    The original bcrypt uses this mode of operation to initialize the state
    by encrypting a cyclc extension of the salt. After this single key
    expansion, the original bcrypt switches to using null bytes. The G3P's
    novel bcrypt variant replaces these null bytes with a counter and
    tag.
    
    Furthermore, the original bcrypt extracts its final hash by encrypting
    the string "OrpheanBeholderScryDoubt" with 64 rounds of blowfish in ECB
    mode. The new integration simply uses HMAC-SHA256 to summarize the bcrypt
    state, consisting of both the P-box and S-box. Moreover, KEY0 and KEY1 are
    forgotten and re-derived from the new summary every 128 bcrypt rounds,
    consisting of 257 half-round blowfish key expansions.

    This re-derivation process means that at every 128th round, computing a
    single cracking attempt is very nearly as expensive as the work that it
    took to create that intermediate state. The only advantage to an
    intermediate-state cracker is that the last half-round key expansion does
    not need to be computed, which in context is a negligible amount of work
    per guess.

    This extended plaintext salting process also means that the suggested
    number of PHKDF rounds was halved. Futhermore, each round is now one
    SHA256 block less expensive than the old version. Thus assuming a short
    domain tag (less than 20 bytes) and the suggested cost parameters, the
    G3P version 2 spends approximately one third of the time in PHKDF
    relative to version 1.

3.  When domain tags are 20 bytes or longer, the end-of-message padding that
    PHKDF applies to HMAC-SHA256 was tweaked to use a proper bitstring.
    This saves one byte and simplifies the documentation for the domain-tag
    parameter.

4.  There is a syntactic oops in the constants for Version 1 stemming from
    an insufficient understanding of the lexical syntax of Haskell string
    constants that are prefixed with null bytes. To be honest I'm not interested
    in deploying version 1 at this point, so I'm not interested in deciding
    whether or not the old implementation is wrong, and whether or not the old
    specification is wrong.

5.  The final HKDF-like output phase has been reworked and generalized a bit,
    and makes fewer assumptions about its parameters.

[^comparable-to-hashes]:
    Or anything comparable to a password hash, such as a server-side PAKE
    credential.

[^pbkdf2-tagged-hmac]:
    Except for the addition of a counter that is incremented every round, the
    modified PHKDF key-stretching phase is literally PBKDF2 instantiated
    with a a tagged PRF, namely `HMAC(key, msg + DomainTag)`.

    Assuming the domain tag is less than 20 bytes long, the only algorithmic
    change that PHKDF's key-stretching phase makes to PBKDF2 is that some of
    HMAC-SHA256's input bytes that were specified to be mostly null are now
    specified otherwise.

    In cases where the domain tag is 20 bytes or longer, this adds one or more
    additional SHA256 block computations per round, which shouldn't be a real
    issue. In fact, it should be extremely safe to compensate for longer tags
    by specifying a smaller number of PHKDF rounds.

[^streaming-hmac-sha256]:
    Note that key0 and key1 become part of the msg string. For this reason,
    HMAC must actually be computed using streaming and backtracking. This
    allows the HMAC computations during the bcrypt key-stretching phase to be
    shared over common prefixes, and allows key0, key1, and the previous bcrypt
    state to actually be forgotten between bcrypt super-rounds.

[^domain-tag-length]:
    This assumes a short domain tag of less than 20 bytes. For example, a
    quarter of sha256 blocks don't accrue before completion for domain
    tags 20-82 byte long, etc.

[^byte-estimate]:
    Bcrypt's P-box is 72 bytes, Bcrypt's S-box is 4096 bytes, plus one SHA256
    accumulator context at 32 bytes, plus two 32 byte derived bcrypt keys, plus
    a 4-byte bcrypt round counter.

[^miniminal-continuation]:
    A minimal data package for transferring the key-stretching continuation to
    another computer at one of these synchronization points would consist of
    the P-box, S-box, SHA256 accumulator, the number of superrounds to be
    performed, and any necessary salt parameters.  Ignoring the salts, this
    totals to ~4204 bytes, possibly less given that the number of superrounds
    would typically be storable in one byte instead of four.