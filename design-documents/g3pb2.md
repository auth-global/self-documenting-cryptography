# The Global Password Prehash Protocol (G3P), Version 2

(by Leon P Smith,  Auth Global)

This work is licensed under a Creative Commons Attribution-ShareAlike 4.0 International License.

# Introduction

The Global Password Prehash Protocol (G3P) version 2 (G3Pb2) is a slow password
hash and key derivation function based on HMAC-SHA256 and blowfish, using
variants of PBKDF2, HKDF, and bcrypt that have been minimally modified in order
to better support self-documenting cryptography. Also, the G3P is explicitly
designed to support keying end-to-end encryption (E2EE) off of the password,
so long as the G3P is deployed as a client-side prehash.

In this context, self-documenting cryptography aims to make password
hashes[^comparable-to-hashes] _traceable_ or _useless_ after they have been
stolen by an eavesdropper.

The basic idea is to add "this password is for Acme Corporation, Inc." as a tag
onto the end of every password before it is hashed. This happens automatically
and outside the control of the user, leaving an indelible fingerprint on the
resulting hash.

This fingerprint means that a password cracker must add on "this password is
for Acme Corporation, Inc." onto the end of every guess, otherwise they are
automatically guessing the wrong password. And if that is the cracker's guess,
then it should be possible for the cracker to contact Acme and say, "Hey, we
think we may have come across some of your stolen password hashes...".

This is an example of **Adversarial Literate Programming**: Alice is an IT
administrator who works for Acme. She gets to specify an password hash
algorithm that depends upon some associated documentation. Eve has stolen some
of Acme's password hashes, and she wants to provide Craig the ability to run
Alice's algorithm on his own hardware, while denying Craig access to
Alice's documentation that the hashes come from Acme.

The security goal of Adversarial Literate Programming is to force Eve to
provide Craig a sporting chance of recovering the invitation to contact Acme
Corporation from Eve's instruction, or force Eve to give up on the idea of
letting Craig run Alice's algorithm himself.

In theory it should be possible for Eve to use some flavor of Homomorphic
Encryption (HE) to construct an implementation of Alice's algorithm that
securely hides the fact that "this password is for Acme Corporation, Inc." from
Craig. For example, people have demonstrated being able to compute a few blocks
of SHA-256 inside Fully Homomorphic Encryption (FHE) within a few seconds.

While most forms of Homomorphic Encryption impose significant overhead, FHE is
in a class of its own. It is normally possible to compute millions of SHA256
blocks within a few seconds even on modest hardware. The overhead of even
state-of-the-art FHE is extreme, often increasing the time and resources needed
to perform a computation by a factor of a 100,000 or more.

However, the suprising existence of FHE, and the fact that it can in theory
obscure any computable algorithm whose output itself doesn't give away secrets,
suggests that it might not even be possible to stake Adversarial Literate
Programming's security goal on an asymptotic difference in the complexity of
algorithms. Rather, Adversarial Literate Programming may be limited to a linear
factor, making its security margin relatively weak for cryptography. I would
even say that acheiving a traditionally-strong security margin in the context
of Adversarial Literate Programming seems implausible.

On the other hand, that linear factor is quite large, and password cracking is
sensitive to even modest overhead. In this context, FHE doesn't seem to be any
immediate threat to Adversarial Literate Programming based on standard
cryptographic primitives like SHA-256 and blowfish.

In fact, a topic of research in FHE is the construction of homomorphic
transciphers, which are alternative cryptographic primitives designed to be
relatively efficient when executed inside FHE. Perhaps alternative cryptographic
primitives designed to be particularly _inefficient_ when executed inside any
suitable method of homomorphic encryption should also be pursued as an
anti-problem.

Studying this anti-problem could potentially offer insight into homomorphic
transciphers and/or homomorphic encryption, as well as possibly extend the
applicability of Adversarial Literate Programming outside of password hashing.

While I don't know how much better future Homomorphic Encryption schemes might
be able to perform on SHA-256 and blowfish, I'm not expecting revolutionary
improvements in efficiency in the near future, and thus I'm expecting FHE will
remain a less-than-practical threat to the G3P for some time to come. On the
other hand, the threat of FHE is also significant enough that the design of the
G3P needs to take it into account.

In particular, argon2 is not particularly secure in the sense of Adversarial
Literate Programming. All of the inputs to argon2 are hashed in a single call
to Blake2, and that resulting hash is the only thing needed to compute argon2's
key-stretching phase.

While this is sufficient for domain separation purposes, it's not enough for
adversarial literate programming. Eve could simply hide Acme's tag and other
parameters inside an FHE-based implementation of this initial call to Blake2,
and return the plaintext hash needed for key-stretching.

In this scenario, Craig _might_ be able to still determine the parameters
hidden inside FHE by computing a hash with a known password and then cracking
the unknowns. This approach can be facilitated when Craig is aware of Alice's
documentation but is not yet aware that Alice's documentation is immediately
relevant to the hash function he is reverse engineering.

However, this requires more sophistication and more computation on Craig's part
compared to reverse engineering Alice's documentation from Eve's implementation.
Furthermore, if the additional parameters hidden inside FHE include say, a
random 16-byte salt for account separation purposes, then this approach to
recovering Alice's documentation won't work.

While the overhead to compute this initial call to Blake2 inside FHE would be
substantial, this initial computation is a relatively negligible part of the
overall argon2 computation. Therefore, the total overhead might be low enough
that Eve would consider deploying FHE to hide Alice's argon2-backed
documentation from Craig in an obfuscation attack.

For this reason, the G3P is designed such that Alice's documentation is
required throughout the entire key-stretching process. Ideally, the only way
for Eve to carry out a secure obfuscation attack would be to run the entire
key-stretching process in Fully Homomorphic Encryption, thus maximizing the
computational overhead inflicted on Craig by Alice and Eve.

# Example Threat Scenarios

In Adversarial Literate Programming, Alice specifies a password hash function,
Eve steals some hashes, which she wants to give to Craig to crack. Here's
a few examples where applying self-documenting domain separation via plaintext
tags to a password hash function can help.

## The Muskian Cybercoup

When Mr. Big Balls parades into your organization's server room and copies all
of your password hashes, self-documenting tags prevents him from usefully
giving your password hashes to his cybercriminal buddies at The Com
without being honest about where those hashes originally came from.

Here, Mr. Big Balls is acting as Eve, and The Com is acting as Craig.

If somebody among The Com were to betray the effort of Mr. Big Balls and report
the stolen hashes back to your organization, then they'd be acting as a friendly
Craig.

## The Botnet Cracker

If The Com then decides to use stolen computing resources in an attempt to
crack your passwords, then there is an unavoidable risk of the computation
being observed, and the payload given to a security analyst.

Thanks to self-documenting domain separation, the security analyst will be able
to take The Com's implementation of your password hash algorithm, and from it
reverse engineer your invitation to contact your organzation about the stolen
hashes

Here, The Com is acting as Eve, and the stolen computing resource is acting as
Craig.

Also in this story, the stolen computing resource is acting as an Eve, and the
security analyst is acting as a friendly Craig.

In this highly adversarial scenario, The Com might consider deploying some kind
of Homomorphic Encryption to securely hide your tags from the security analyst,
so it's important to inflict a signficant amount of overhead in this case.

This means that the plaintext of some tag should be required throughout a
substantial portion of the key-stretching computation, which means that
argon2 by itself should not be considered sufficient.

Those wishing to use argon2 could use the G3P with a reduced number of rounds
as a preprocessing and/or postprocessing step in order to avoid tag obscuration
attacks. Ideally, someday a close analog of argon2 would be available that
supports carrying a plaintext tag throughout the entire key-stretching process.

## The Professional Cracker

There are certainly legitimate use cases for password cracking. Without the use
of self-documenting tags to securely enforce the origin of password hashing
data, many who are involved in legitimate password cracking activities are at
risk of unknowingly participating in unethical and/or illicit activities.

For example, let's say a corporation outsources legitimate password cracking
work to a professional who is interested in staying above board. Today's
password hashing technology does not itself impose any impediment to a corrupt
IT worker who wishes to commingle outside password hashes into the data being
forwarded to the professional password cracker.

The best case scenario would be that self-documenting tags have been applied to
all the legitimate data to be cracked. Self-documenting domain separation
prevents all outside data from getting in, greatly reducing the scope of abuse
of legitimate password cracking services.

On the other hand, applying self-documenting domain separation to outside data
also prevents it from getting cracked by legitimate, professional crackers,
even if they cannot robustly restrict their efforts to only legitimate data.

In this less-adversarial scenario, an ethical professional should not knowingly
accept or run any password cracker that incorporates Homomorphic Encryption.
Thus infliciting the maximum overhead is relatively less important, so
plaintext tags backed by HMAC or argon2 alone should be good enough in this
rather limited situation.

# Simplified Overview

## Iterated HMAC preprocessing

This section elides certain details, including some of the auxiliary inputs and
all length-related padding, from the construction of the G3P. Thus this section
is not intended to be suitable as an implementation reference.

This length padding includes the bitlength of every argument so that one cannot
create cryptographically trivial collisions by shifting bytes between
parameters, and often repeats otherplaintext tags as message fillers.

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
    T 0 = HMAC (Seguid,
                "G3Pb2 alfa" +
                Username + Password + LongTag + Credentials +
                ContextTags + INT_32_BE(i) + DomainTag )
    T 1 = HMAC (Seguid, T 0 + INT_32_BE(i + 1) + DomainTag )
    ⋮
    T c = HMAC (Seguid, T (c-1) + INT_32_BE(i + c) + DomainTag )

One difference is the addition of a counter and the domain tag to salt every
round of PHKDF: this is literally just taking bytes that in PBKDF2 would be
null, and using them as a supplemental salt in the same vein as HKDF's info
parameter.

One of the more obvious differences is that the parameter that PBKDF2 calls the
"password" is now called the "seguid". Instead of using the actual password as
an HMAC key, the G3P recommends using a seguid as a supplemental salt that
identifies the deployment. The G3P suggests moving the actual password into the
parameter that PBKDF2 calls "salt". Furthermore, the G3P's password is both
prefixed and suffixed with additional forms of salt and length padding.

A practical advantage to this alternate mode of operation for PBKDF2 is that
the password need not be preserved until the end of key-stretching, but can be
forgotten as soon as it has been hashed the first time. This isn't true at all
in classic bcrypt: the plaintext password must be known up until the middle of
the very last bcrypt round.

The use precomputed HMAC keys avoids the need to preserve the literal plaintext
of PBKDF2's nominal "password" parameter throughout the key-stretching
computation. However, precomputed HMAC keys apply no key-stretching, so
effectively none of the key-stretching work accrues to PBKDF2's intermediate
state until the HMAC key is forgotten after the end of key-stretching.

The G3P follows a stronger design principle of _fully incremental
key-stretching_, where the benefit of key-stretching should regularly accrue
throughout a password hash computation. Thus, this alternate mode of operation
for PBKDF2 is used because the computation repeatedly reaches a
_synchronization point_.

Synchronization points are intermediate states of a password hash computation
whose minimal continuation[^minimal-continuation-phkdf] reveals as little as
possible about the original passsword. Because this continuation must include
all information necessary for computing the final hash, it necessarily provides
a cracking attack against the password.

Sometimes cracking isn't really necessary. In classic bcrypt, any continuation
will reveal the plaintext of the password directly, as it is needed throughout
the key-stretching process. In other cases, such as PBKDF2's classic mode of
operation, such a continuation must reveal a hashed version of the password
with no key stretching applied.

A synchronization point is a continuation whose most efficient cracking attack
costs almost as much _per guess_ as the work required to create that
continuation in the first place. This property implies that a password hash
computation can transferred from one device to another with full credit for
key-stretching work already performed.

Neither classic bcrypt nor classic PBKDF2 have any useful synchronization
points. PHKDF has a synchronization point every round.

PBKDF2 xors the blocks `U 1 ^ U 2 ^ ... ^ U c` to generate its final output
block. The G3P does the same, but starts at zero, computes one additional round,
and then derives two cryptographically independent keys from the results:

    c = (number of PHKDF rounds, ideally ~20000 or so)
    sumT = T 0 ^ T 1 ^ ... ^ T c
    endT = T (c+1)
    keyB = HMAC
             (Seguid,
             "G3Pb2 bravo" + "B" + endT + sumT +
             ContextTags + "KEYB" + DomainTag)
    keyC = HMAC
             (Seguid,
             "G3Pb2 bravo" + "C" + endT + sumT +
             ContextTags + "KEYC" + DomainTag)

Now, we are ready for the second form of key-stretching, which uses a
construction very similiar in flavor and spirit as classic bcrypt to generate
a long input to HMAC. Overall, this phase looks like a single call to HMAC:

    seed = HMAC (BcryptSeguid,
                 "G3Pb2 charlie" + keyB + bcryptOutput +
                 keyC + ContextTags + "SEED" + DomainTag)

The inclusion of the continuation control key ("keyC") allows for some or all of
the bcrypt key-stretching computation to be outsourced to another semi-trusted
device while retaining exclusive control over the final seed.

## KDF-based output

The seed is fed into a key derivation function (KDF) built around HMAC-SHA256,
which provides a last-minute opportunity for domain separation before final
output expansion.  This function performs no additional key stretching, so
therefore it is very fast relative to computing the seed itself.

    keyL = HMAC ( SproutSeguid, seed + Role + "KEYL" + SproutTag )

    out0 = HMAC ( keyL + KeyR, EchoHeader + INT_32_BE(EchoCounter) + EchoTag )
    out1 = HMAC ( keyL + KeyR, out0 + INT_32_BE(EchoCounter + 1) + EchoTag )
    out2 = HMAC ( keyL + KeyR, out1 + INT_32_BE(EchoCounter + 2) + EchoTag )
    ...

This final key derivation function resembles HKDF-SHA256, with the computation
of `keyL` corresponding to HKDF-Extract, and the output blocks corresponding
to HKDF-Expand.

However, there are a handful of mostly minor changes: we are using a
parameterized 4-byte counter before the domain tag, whereas HKDF uses a
hardcoded 1-byte counter after the info tag. Furthermore, this construction
also parameterizes of the right 32 bytes of the output key as well as the
32-byte initial generator state.

Note a trivial collision can be obtained by feeding an output block back into
the Header parameter and by incrementing the counter by one, which is the same
thing as the next output block. There are other issues the Header parameter is
associated with, but it is also not particularly difficult to use safely: see
the reference implementation's API documentation for details and suggestions.

Very much like HKDF-SHA256, these final steps perform no key-stretching, so
they are very fast relative to the computations required to compute the seed.
This means a large quantity of cryptographically independent output blocks can
be efficiently generated from a single key-stretching computation, something
that the suggested way of producing longer outputs with the original PBKDF2
fails at.

## bcrypt key stretching

G3P uses a modified bcrypt algorithm that is very closely based on the classic
bcrypt. Many existing analyses of bcrypt should apply to this variant with
minimal need for revision.

To compute the seed, we need `bcryptOutput`, which is one or more fixed-length
>12 kiB binary blobs consisting of bcrypt's P-box and S-box interspersed with
portions of the bcrypt long tag, with one blob for every super-round. There is
one super-round for every 128 bcrypt rounds, rounded up.

    msg   = ""
    state = (classic bcrypt initial state based on digits of pi)

    for each super-round:
       key0   = HMAC
                 ( BcryptSeguid,
                   "G3Pb2 charlie" + keyB + msg +
                   BcryptContextTags + "KEY0" + BcryptDomainTag )
       msg   += key0
       key1   = HMAC
                 ( BcryptSeguid,
                   "G3Pb2 charlie" + keyB + msg +
                   BcryptContextTags + "KEY1" + BcryptDomainTag )
       msg   += key1
       state := bcryptSuperRound ( state, key0, key1, BcryptLongTag )
       msg   += state

    bcryptOutput = msg

Note the key and initial message prefix is shared across all calls to HMAC. In
fact, for a secure implementation, the HMAC function must be computed using
streaming and backtracking. This has the added benefit of simplifying the
implementation and reducing the memory required to compute the bcrypt
key-stretching phase to a constant ~4268 bytes[^modified-bcrypt-memory-estimate]
or so, not including the memory needed to store other parameters.

The transition between each super-round serves as a synchronization
point[^minimal-continuation-bcrypt] during the bcrypt key-stretching phase.

Each super-round consists of 128 modified bcrypt rounds, except for the first
super-round which consists of 1-128 rounds. These modified rounds are modelled
very closely on the original bcrypt. For example, compare an original
bcrypt round on top with the modified round on bottom:

    S = (blowfish state, a bytestring of length 4168)
    T = (transition code, a bytestring of length 4168)

    XOR : T -> S -> S
    BLOWFISH-EXPAND : T -> S -> S
    CYCLE(String, Len) =
         (truncate or cyclically extend String
         until the result is Len bytes long.)

    ~ is bitwise complement, like C
    + is string concatination, like Python

    // original bcrypt

    TruncatedPassword =
       (truncate at 72 bytes or the first null byte,
        whichever is shorter)

    S_0 = (state from previous round)

     |  XOR( CYCLE(TruncatedPassword + "\x00", 72)
     |     + CYCLE("\x00", 4096) )
     v

    S_1

     |  BLOWFISH-EXPAND( CYCLE("\x00", 4168) )
     v

    S_2

     |  XOR( CYCLE(Salt, 72)
     |     + CYCLE("\x00", 4096) )
     v

    S_3

     |  BLOWFISH-EXPAND (CYCLE('\x00', 4168))
     v

    S_4 = (state either for the next round, or to generate the final output
           hash by encrypting "OrpheanBeholderScryDoubt" 64 times via
           blowfish in the Electronic Codebook (ECB) mode of operation)

    // The Global Password Prehash Protocol version 2:

    S_0  = (state from previous round)

     |   XOR ( key0 + BcryptLongTag
     |       + CYCLE("\x00", 4136 - LENGTH(BcryptLongTag)) )
     v

    S_1

     |   BLOWFISH-EXPAND
     |     ( INT_32_BE(roundCtr) + "bcrypt-xs-free ..."
     |     + CYCLE(BcryptLongTag + "\x00", 4136) )
     v

    S_2

     |   XOR ( key1 + BcryptLongTag
     |       + CYCLE("\x00", 4136 - LENGTH(BcryptLongTag)) )
     v

    S_3

     |   BLOWFISH-EXPAND
     |     ( INT_32_BE(~roundCtr) + "bcrypt-xs-free ..."
     |     + CYCLE(BcryptLongTag + "\x00", 4136) )
     v

    S_4 = (state for next round and/or input for HMAC-SHA256)

This simplified overview demonstrates that the G3P's modifications to bcrypt
also requisitions previously unused null bytes, much in the same way that PHKDF
requisitions previously unused null bytes found in PBKDF2 for its own purposes.

If two states collide, then modifying that state with XOR(x) will always be
different than that same state modified by XOR(y) for distinct x and y. This
observation is also true of BLOWFISH-EXPAND.

For this reason, any state collisions in the original bcrypt will get pushed
back apart at least once per round, because in order to be a collision, the
password and/or salt must be different. Thus no collision matters unless it
occurs on the very last round. This also demonstrates that the literal
plaintext password is needed throughout bcrypt's key-stretching phase.

In modified bcrypt, differences in the long tag will cause any state collisions
to be pushed apart four times per round. Moreover differences in the password
or any other committed parameter will manifest as a cryptographically-guaranteed
difference in key0 and key1, meaning that even if the long tag is the same, any
collisions on the bcrypt state will be pushed apart twice per round.

Finally, the addition of the counter breaks all loops, because if a single
bcrypt state is ever reentered in the course of a single key-stretching
computation, the counter guarantees the following state _will_ be different
than all previous following states.

Both the original and modified bcrypt have a half-round state initialization
phase. In the original bcrypt, it runs at the beginning of every computation.
In the modified bcrypt, it runs once at the beginning of every super-round.

    // original bcrypt

    S_0  = (based on digits of pi)

     |   XOR( CYCLE(TruncatedPassword + "\x00", 72) )
     v

    S_1

     |   BLOWFISH-EXPAND( CYCLE(Salt, 4168) )
     v

    S_2 (starting state for the first bcrypt round)

    // The Global Password Prehash Protocol version 2:

    S_0  = (state from previous super-round, or digits of pi)

     |   XOR( (first 40 bytes of the long tag suffixed with null bytes)
     |      + key0 + (remaining bytes of long tag) )
     v

    S_1

     |   BLOWFISH-EXPAND (key1 + CYCLE(BcryptLongTag + "\x00", 4136))
     v

    S_2 (starting state for the first round of a super-round)

The transitions between two super-rounds are designed to be synchronization
points, and it doesn't make much sense to transfer a bcrypt key-stretching
computation from one device to another outside these transitions.

In the middle of a super-round, key0 and key1 would need to be transferred.
These values must be computed before a super-round can begin, thus a cracker
could attack these keys directly and would not need to compute any portion of
the current super-round.

Also, the bcrypt state machine can be run in reverse. There is an efficient
implementation of BLOWFISH-COEXPAND that will produce a starting state given
a final state. This computation can be shared across multiple guesses, meaning
that a cracker can instead attack the final bcrypt state of the previous
super-round. Compared to cracking key0, this saves a half-round of bcrypt and
more than 12 kilobytes of SHA256 input processing.

These keys are forgotten as part of the transition between super-rounds, which
prevents moving backwards across the XOR steps and prevents moving backwards
across the call to BCRYPT-EXPAND in the initializing half-round. The act of
forgetting these keys enables the key-stretching ratchet to make forward
progress.

There is also an efficient implementation of BLOWFISH-TRANSCODE which takes
as input any single pair of starting and ending states, and produces the unique
transition code that can be used with EXPAND and COEXPAND to move directly
between those two states.

These three functions implies that the bcrypt state machine forms a quasigroup
with 2^33334 elements. This observation both suggests attacks if one is allowed
too much control over the transition code, and informed the modifications to
bcrypt in an attempt to avoid these issues.

# Combinatorics of Cryptographic Continuations

How many password hash functions are there? Cryptographic hash functions
aspire to be a "good enough" approximation of an idealized random oracle.
Random oracles cannot exist in reality, but they provide a useful model for
analyzing cryptographic constructions. In particular, this

An idealized random oracle is a pure function whose input space is all finite
strings, and whose output space is several hundred fair coin flips.  As there
are a countable infinity of finite strings, there are an uncountable infinity
of idealized random oracles.

In an idealized random oracle, any difference anywhere in an input string leads
to statistically independent output bits. This means that by interleaving some
constant data as "salt" with the input data in an unambiguous, canonical way,
one can produce an unlimited number of "new" random oracles from a base random
oracle.

**Theorem**: Any change in this salt will, with probability 1, cause at least
one output to change. Otherwise, one would have to win an infinite number of
fair coin flips without losing even once.

In practice, any change in the salt will cause all outputs to be different.
Colliding a single output requires not losing any of hundreds of fair coin
flips. Thus there are a negligible number of collisions that will never be
found in practice.

**Corollary**: The mapping from salts to idealized random oracles is
_almost surely_ injective.

This idealized model is agnostic to how salt is interleaved: every distinct
interleaving will result in a distinct random oracle, but this naive model
offers no way to distinguish how the salt is interleaved with the input.

However this naive view is misleading: practical hash functions usually support
streaming input. For example, SHA256 uses a compression function that applies
an input block of 64 bytes to a state of 32 bytes, resulting in a new state.
This allows arbitrarily long inputs to be processed one block at a time, and
is more or less how most cryptographic hash functions are structured.[^not-blake3]

Even if we assume the compression function is an idealized random oracle, this
structure reveals that with prefixed salts, finding a single collision on the
compression function can be enough to produce an infinite family of collisions,
as a single collision can propagate throughout the rest of the computation.
This is something that does not happen with suffixed salts. Some variation of
this argument is inherent to any streaming implementation.

In the context of SHA256, any prefixed salt can be removed 64 bytes at a time,
replaced by modifications to the 256-bit state. This is an example of _partial
evaluation_, which can be shared across an unlimited number of applications.

Algebraically speaking, we are comparing the partial evaluations of the
functions `λx → hash(A + x)` and `λx → hash(B + x)` for distinct salts `A`
and `B`. If these salts collide the compression function, then we can trivially
produce "new" collisions by simply choosing any arbitrary bitstring and
appending it to both salts. Because these functions are pointwise equal,
they are two different descriptions of the same underlying function.

Partial evaluation of SHA256 demonstrates there cannot be more than 2^256
functionally distinct prefixed salts without leaving some salt in the input
buffer, or suffixing some salt after the password. Even though the input space
of prefixed salts is much larger than 256 bits, collisions on the compression
function propagate throughout the remainder of the computation.

Similarly, the G3P processes the plaintext password in a single pass near the
beginning of the hash computation. Applying the previous argument means that
there cannot be more than 2^256 functionally distinct combinations of prefixed
salt and password.[^extracting-entropy-with-sha256]

Now that we've bounded the input space, we can answer our original question:
there are (2^256)^(2^256) = 2^(2^264) password hash functions assuming a
compression function with a 256-bit internal state and 256-bit output, and
that are limited to one pass over the plaintext of the password.

Representing a single such function sampled uniformly at random from this
distribution would require at least 2^264 bits of storage, which is roughly
comparable to the 3*10^80 particles estimated to exist in the observable
universe.

For all practical purposes, this is an utterly inexhaustible supply of
password hash functions, even without stepping outside this artificially narrow
definition of what a password function "is".[^excludes-many-existing-password-hash-functions]

On the other hand, any leftover prefixed salt,[^low-entropy-inputs] and all
suffixed salt, cannot be processed without first choosing a value for the
password input. This forces the full plaintext of any appended salt to be
available to any ordinary implementation capable of computing hashes for
arbitrary passwords.

**Fact:** Given a hash function modelled as a _compression function_ that is
assumed to be an idealized random oracle, the mapping from _suffixed_ salts to
hash functions is injective, with an ultra-negligible number of counterexamples.

Suffixed salts do not produce produce families of collisions even when we
take compression functions into account. Because the plaintext of a suffixed
salt cannot be processed until the password has been chosen, the functions
`λx → hash(x + Y)` and `λx → hash(x + Z)` don't readily admit non-trivial
partial evaluations.

Moreover, colliding this partial application of suffixed salt is highly
implausible. Because the salts `Y` and `Z` must be distinct, a counterexample
would be able to create a very large number of cryptographically distinct
collisions for free.

Because these collisions are distinct, finding a counterexample remains
implausible even if we assume access to another oracle that grants a small
number of collisions in the desired form "for free".

By the pigeonhole principle, such counterexamples have to exist. However, if
compression functions are idealized as random oracles, then due to the utterly
inexhaustible supply of similar password hash functions within the confines of
the Milky Way galaxy, it seems like at least one of those salts would almost
certainly have to be much _much_ longer than 2.3 million terabytes, a number
chosen for the sake of discussion because that's the length limit imposed by
SHA256.

**Conjecture:** It seems highly plausible, and rather probable, that the map
from suffixed salts to password hash functions is injective in practice even
when more idealized models are instantiated with a reputable cryptographic
hash function such as HMAC-SHA256.

One could argue that the mapping of prefixed salts to password hash functions
is also injective in practice. After all, a collision on SHA256 has never been
publically demonstrated, which might make this argument seem purposeless and
pendantic. But I have two responses: firstly, suffixed salts are injective
in practice in a significantly stronger sense than prefixed salts. Secondly,
much of the design work around the G3P revolves around understanding and
controlling partial evaluation!

For example, we want to enhance the utility of legitimate forms of partial
evaluation, which is why the G3P adopted fully incremental key-stretching as a
design goal. Also, we don't want to allow the possibility of partially
evaluating away the plaintext of any parameter called a "tag", therefore
prefixed salts cannot be tags, which is the reason the G3P's "username"
parameter doesn't have "tag" anywhere in the name.

**Observation:** Remember that our goal is to adversarially pass messages inside
algorithms via the mathematics of game theory. Our primary communications
objectives are the domain tag and long tags. One or both of these is expected
to typically be on the order of one hundred to a few hundred bytes long, which
is much longer than the 256-bit SHA256 state machine.

We need to argue that our message is implied by the algorithm we specify. Thus
we should prefer to argue that our message describes a unique algorithm in a
space of up to 2^(2^264)) hash functions rather than arguing that our message
describes some inscrutable equivalence class consisting of those inputs that
produce a single one of 2^256 possible SHA256 states.

We should prefer the former argument over the latter even if we are unlikely to
ever be able to explicitly find a collision, because it is a stronger argument.
The difference reminds me of the distinction between information-theoretic
versus computational security. Moreover, the act of making the latter argument
is (at the very least) a brown M&M suggesting that partial evaluation may be
possible, which we wish to prevent in the case of tags!

Suffixing salts after a password plausibly achieves the properties necessary to
make our preferred argument work, whereas prefixed salts clearly do not.
Furthermore, partial evaluation provides a method of obscuring (part of) a
prefixed salt, meaning that arbitrary messages cannot be robustly passed via
a prefixed salt alone.[^seguids]

On the other hand, prefixed salts are still useful, especially for account
separation purposes. This ensures that the password hash function has fully
committed to a particular account before the plaintext of the password can be
processed. In effect, the password serves as a tag relative to the prefixed
salt.

This is the reason why the G3P uses "username" as the name of the prefixed
salt parameter; these parameter names do not prescribe a particular usage, but
they do suggest an intended usage.

# The Cryptoacoustic Transmission Medium

The goal that pervades every part of G3P's design is to adversarially pass
messages inside password hash algorithms via the mathematics of game theory.
Cryptoacoustics is a methodology that attempts to solve the Adversarial
Literate Programming problem between Alice, Eve, and Craig.

Cryptoacoustics is a logical converse of cryptography, not unlike the way
Statistics is a logical converse of Probability. Cryptography ensures that if
you have access to the plaintext of a key, then you can run an algorithm.
However, conventional crytography is filled with concrete examples, including
the HMAC construction, where the ability to run an algorithm implies access
only to something derived from the key, which usually isn't suitable for
communicating messages. Cryptoacoustics ensures that if you can run an
algorithm, then you will have access to the plaintext of a key. These types
of keys are what we call "tags".

In the context of the G3P, the plaintext of any tag can be recovered by reverse
engineering a memory replay of any ordinary implementation of the hash function
in action. Thus any truly secure tag obfuscation attack by Eve must incorporate
some form of Homomorphic Encryption to prevent Craig from observing those
memory replays.

If you can pass messages, then there must be some kind of transmission medium.
Though in late 2020 I had some insights that lead to the vaguest conceptions
that it should be possible to improve the service provided by "Have I Been
Pwned" by insourcing it[^have-i-been-pwned], my eureka moment came shortly
after writing about the novel queueing disciplines exhibited by Joe Taylor's
WSJT suite of amateur radio protocols.

The unexpected insight I was starting from was "Write it down. Make it real",
which I implicitly understood as "Writing something down [in the cryptoacoustic
transmission medium] makes it real [in that medium], now write this idea down
and make it real."  I was missing the phrases in brackets with only the vaguest
conception that I needed to create them to flesh out my concept. I had a clear
understanding of what I needed to do, but was highly uncertain of any details.

It was immediately clear that I needed to take Dan Friedman's wise advice that
"everytime you write a program to do something, you should write a program to
undo that thing" and adapt it to cryptographic hash functions in a novel way:
what I would eventually come to call "plaintext tags" needed to be recoverable
(i.e. "undoable") from a memory trace of the cryptographic hash function itself.

Furthermore, as an undergraduate at Case Western Reserve University, I had
written a toy stepping interpreter based on continuations, based on Friedman,
Wand, and Haynes "Essentials of Programming Languages, 2nd Ed.", which
quickly became my mental model for thinking about the problem.

And to make all that work, I knew I would need to learn and understand more of
the underlying structure of at least a few cryptographic constructions. Because
I was hoping to keep my cryptographic work compatible with contemporary versions
of WebCrypto, a goal that got yeeted away several months later, I set out to
learn HMAC-SHA256 and relearn PBKDF2 in this new context.

While in the process of understanding my eureka moment and formulating the
goals, I was obsessed about learning a little bit about loudspeaker design. I
didn't think much of it at the time, but as I finally formulated PHKDF and I
was writing acknowledgements I realized I needed to thank a deceased teacher
of mine, Dr. David Doiron, who I had for Optics at the Indiana Academy for
Science, Mathematics, and Humanities at Ball State University in Indiana.

In retrospect, that class was my introduction to signals and communication
theory. While I was unravelling this puzzle, I basically thought of the
plaintext tag as a signal, with the space of cryptographic state changes
as the transmission medium. I thought of a cryptographic hash function as some
sort of exotic modem capable of guaranteeing the delivery of messages exactly
in the most relevant situations and incapable of making any other guarantees
regarding delivery or non-delivery in other situations.

And yet, my concious mind was resolutely in denial about the connections
between what I was doing and communications theory. The penny finally dropped
when I had to finally admit to myself why I needed to acknowledge Dr. Doiron.

The art of encoding plaintext messages into cryptographic algorithms is an
important enough technique that it warrants a memorable name. I chose the name
"cryptoacoustics" because sound is the primary means of communication that
humans use to physically communicate with each other. It also honors my
deceased friend Duncan Lowne, who was a DJ interested in electronic music and
computer engineering and was a DPhil student at Oxford when he passed.

The analogy between cryptographic hash algorithms and communications theory is
not formalized in my mind, but I'm reasonably confident that time will prove
that it can be a reasonably deep and fruitful analogy.

For example, the decibel is a logarithmic scale, but is otherwise dimensionless.
Thus it is sensible and convenient to use decibels to talk about the overhead
inflicted on Craig by Alice and Eve when secure tag obfuscation attacks are
carried out via Homomorphic Encryption.

In particular, cryptoacoustic advantage is the overhead of the most efficient
tag obfuscation attack that is secure against the best reverse engineers on
their best days. I have no idea what the cryptoacoustic advantage of SHA256
or BLOWFISH-EXPAND might be, nor any idea of how one might even go about
answering that unknown.

On the other hand, existing implementations of Homomorphic Encryption do provide
a means of establishing an upper bound on cryptoacoustic advantage; I designed
the G3P under the assumption that it would be straightfoward to achieve an
overhead of "only" 100,000x, also known as 50 dB.  So I assumed the
cryptoacoustic advantage of anything I did was < 50 dB, and that an overhead
of 100x, or 20dB, was sort of at the minimum edge of viability.

Rigorously integrating a diversity of plausible cryptoacoustic constructions
allows me to carefully hedge my bets, thus increasing the likelihood of
achieving a good cryptoacoustic advantage.

Because the cryptoacoustic transmission medium is purely mathematical, it
cannot deliver messages. Instead, it creates constraints on real-world patterns
of communication. Much like a virus is dependent upon other forms of life for
reproduction, cryptoacoustics is dependent on physical methods of communication
to actually deliver its messages. Thus one could say that adversarially encoding
plaintext messages into algorithms is literally a mind virus.

Because Alice's mind virus cannot possibly be relevant to one's interests unless
one is interested in running Alice's algorithm, and cannot possibly be adversely
relevant to one's interests unless one is doing something nefarious to Alice,
that would seem to fit the _de facto_ usage of "woke".

And, in order to be effective, cryptoacoustics will need to impart something
not unlike an fingerprint or watermark[^unlike-a-watermark] that cannot be
removed or deleted from the result. Thus cryptoacoustics is a transmission
medium of indelible woke mind viruses.

As reporting the stolen password hashes back to your organization must be very
woke indeed, cryptoacoustics is a transmission medium of mind viruses intent on
zombifying woke Craigs into assisting the counterintelligence goals of your
organization.

# Deployment Considerations:

A deployment designer may notice that the Global Password Prehash Protocol ha
s 21 parameters. This may seem excessive, but the thing to remember
is that the G3P is carefully designed so that almost every parameter must be
an exact match. Any difference means the outputs will be cryptographically
independent to any efficient observer who isn't privy to enough of the inputs.

There are a few exceptions, but to the best of my knowledge they are all
documented: there are some trivial (but largely uninteresting) "collisions"
involving HMAC-SHA256 keys. This behavior is externally dictated by relevant
standards. Additionally, there are truncation and other gotchas associated with
the echo-header and echo-key parameters, which are used to tweak the final
output hash. All other collisions on the G3P are cryptographically non-trivial.

All parameters fall into one of five categories: things needed only _once_ near
the beginning of the computation, things needed _sporadically_ throughout a
computation, things needed _constantly_ throughout a computation, parameters
that determine how _expensive_ a key stretching phase will be to compute, and
parameters that can be used to efficiently _tweak_ the output after
key-stretching has been performed. Honestly, I suspect at least 8-12
parameters are necessary even for a more minimal design.

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
    by encrypting a cyclic extension of the salt. After this single key
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
    modified PHKDF key-stretching phase would literally be PBKDF2 instantiated
    with a tagged PRF, namely HMAC(key, msg + DomainTag)`.

    Assuming the domain tag is less than 20 bytes long, the only algorithmic
    change that PHKDF's key-stretching phase makes to PBKDF2 is that some of
    HMAC-SHA256's input bytes that were specified to be mostly null are now
    specified otherwise.

    In cases where the domain tag is 20 bytes or longer, this adds one or more
    additional SHA256 block computations per round, which shouldn't be a real
    issue. In fact, it should be extremely safe to compensate for longer tags
    by specifying a smaller number of PHKDF rounds.

[^minimal-continuation-phkdf]:
    During PHKDF key-stretching, every round provides a synchronization point.
    A minimal continuation would consist of the PHKDF generator state, the
    sum of states seen so far, the number of rounds performed, and all input
    parameters other than the Username, Password, and Credentials. The total
    transfer size is ~68 bytes in addition to the parameters, which will
    themselves often exceed 68 bytes.

    Note that transferring a continuation before PHKDF key stretching is
    complete means that the recipient will be able to compute the seed. If
    domain separation is needed for e.g. end-to-end encryption that the
    recipient must not be privy to, separation would need to be applied before
    PHKDF key stretching commences.

    Thus it's preferred to wait to outsource any computation until the bcrypt
    key-stretching phase, so that the seed need not be implicitly transferred
    along with everything else.

[^modified-bcrypt-memory-estimate]:
    Bcrypt's P-box is 72 bytes, Bcrypt's S-box is 4096 bytes, plus one SHA256
    accumulator context at 32 bytes, plus two 32 byte derived bcrypt keys, plus
    a 4-byte bcrypt round counter. This doesn't include space needed to store
    the salts needed throughout the process, and may be overlooking a few
    small sources of memory overhead.

[^minimal-continuation-bcrypt]:
    A minimal data package for transferring the bcrypt key-stretching
    continuation to another computer at one of these synchronization points
    would consist of the P-box, S-box, SHA256 accumulator, the number of rounds
    to be performed, and any necessary salt parameters. Ignoring the salts, this
    totals to ~4204 bytes, possibly less given that the number of rounds would
    typically be storable in one or two bytes instead of four.

[^not-blake3]:
    Blake3 is a notable exception, in that the input isn't processed
    block-by-block from start to end, but rather in a more complicated tree
    structure that allows for parallelism and for certain kinds of incremental
    updates.

[^extracting-entropy-with-sha256]:
    It is technically possible to use SHA256 to extract more than 256 bits of
    entropy from an input. Though one could split the input into pieces to be
    hashed separately, a preferred approach is to hash the original input
    multiple times in an way that is domain-separated from the outset. In fact
    HMAC-SHA256's key schedule does exactly this, however the G3P makes no
    attempt to extract more than 256 bits of entropy from a password.

    The G3P uses SHA256-based constructions capable of extracting more than
    256 bits of entropy from select parameters other than the password, but
    this is temporary and done to help protect against potential shenanigans.

    In particular, the G3P can extract more than 256 bits of entropy from the
    phkdf context tags, phkdf domain tag, and phkdf seguid in order to generate
    keyB and keyC, which start and end the bcrypt key-stretching phase.

    Also, the G3P can extract more than 256 bits of entropy from the bcrypt
    context tags, bcrypt domain tag,  bcrypt seguid, and parts of the bcrypt
    long tag in order to generate key0 and key1 which is an attempt to defend
    against hostile bcrypt long tags.

[^excludes-many-existing-password-hash-functions]:
    To emphasize how artificially narrow this definition is, it excludes many
    well-respected password hash functions such as the original bcrypt and
    PBKDF2-HMAC-SHA512. That doesn't matter for our argument, but do keep in
    mind that our definition is very narrowly tailored to our specific purpose
    of establishing that the number of password hash functions is indeed very
    large.

[^low-entropy-inputs]:
    Speculative partial evaluation provides a caveat to the self-documenting
    properties of leftover prefixed salt. If the subsequent input doesn't
    contribute enough entropy to the remainder of the SHA-256 block, then the
    plaintext of any leftover prefixed salt can be obscured.

    For example, if there is 63 bytes of leftover salt, and only one more byte
    is needed to complete the next block, Eve could simply generate 256
    different states for Craig to start from, one state for each possible last
    byte. If Eve knows that this last byte will be the first byte of a
    TupleHash length encoding, then Eve might be able to get away with providing
    Craig with only two or three speculative states.

    For this and other reasons, when the G3P intentionally makes use of
    leftover prefixed salt, the length of this leftover is usually 32 bytes
    long. There is one exception that is only 29 bytes.

[^seguids]:
    It is sometimes possible to communicate a message via a prefixed salt.
    This is more or less what self-documenting globally unique identifiers
    (seguids) were invented to do. However, relying on seguids for delivering
    a message to Craig requires more detective work and sophistication on
    Craig's part.

    Moreover, seguids are not suitable for account separation purposes, and
    good account separation practices can make it easier for Eve to hide
    prefixed seguids from Craig.

    The parameters that the G3P calls a "seguid" are actually HMAC keys, and
    HMAC keys are in effect both prefixed before and suffixed after an input
    message. It is the seguid construct that allows messages to be passed via
    HMAC keys, even though HMAC keys can always be partially evaluated into
    NMAC keys, a.k.a. precomputed HMAC keys. Thus the name was chosen to hint
    at the intended use of the parameter.

[^have-i-been-pwned]:
    Or at leat ensure that "Have I Been Pwned" would have in their possession
    sufficiently reliable information to be able to responsibly disclose
    specific password hash security events back to an organization that
    prepared sufficiently.

[^unlike-a-watermark]:
    Unlike a watermark, a cryptoacoustic tag is kind of sigil that cannot be
    read directly from a passsword hash, but rather represents a belief about
    its origin, thus preserving plausible deniability. This belief must be
    correct for that password hash to be both genuine and crackable.

[^domain-tag-length]:
    This assumes a short domain tag of less than 20 bytes. For example, a
    quarter of sha256 blocks didn't accrue before completion for domain
    tags 20-82 bytes long, etc.
