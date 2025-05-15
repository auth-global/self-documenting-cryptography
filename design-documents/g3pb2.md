# The Global Password Prehash Protocol (G3P), Version 2

(by Leon P Smith,  Auth Global)

This work is licensed under a Creative Commons Attribution-ShareAlike 4.0 International License.

# Introduction

The Global Password Prehash Protocol (G3P) version 2 (G3Pb2) is designed to
adversarially pass messages inside its algorithm via the mathematics of
game theory. It a slow password hash and key derivation function based on
HMAC-SHA256 and blowfish, using variants of PBKDF2, HKDF, and bcrypt that have
been minimally modified in order to better support the goal of self-documenting
cryptography. Also, the G3P is explicitly designed to support keying end-to-end
encryption (E2EE) off of the password, so long as the G3P is deployed as a
client-side prehash.

In this context, self-documenting cryptography aims to make password
hashes[^comparable-to-hashes] _traceable_ or _useless_ after they have been
stolen by an eavesdropper.

The basic idea is to add "this password is for Acme Corporation, Inc." as a
**tag**[^tag-definition] onto the end of every password before it is hashed.
This [domain separation](https://en.wikipedia.org/wiki/Domain_separation)
happens automatically and outside the control of the user, leaving an indelible
fingerprint on the resulting hash.

This fingerprint means that a password cracker must add on "this password is
for Acme Corporation, Inc." onto the end of every guess, otherwise they are
automatically guessing the wrong password. And if that is the cracker's guess,
then it should be possible for the cracker to contact Acme and say, "Hey, we
think we may have come across some of your stolen password hashes...".

This is an example of **Adversarial Literate Programming**: Alice is an IT
administrator who specifies a password hash function tagged with Acme's name.
Eve has stolen some of Acme's password hashes, and she wants to provide Craig
the ability to run Alice's algorithm on his own hardware, while denying Craig
access to Alice's documentation that the hashes come from Acme.

The security goal of Adversarial Literate Programming is to force Eve to
provide Craig a sporting chance of recovering the invitation to contact Acme
Corporation from Eve's instruction, or force Eve to give up on the idea of
letting Craig run Alice's algorithm himself.

## Example Scenarios

Here's a few examples how self-documenting password hash functions can help
your organization:

### The Muskian Cybercoup

When Mr. Big Balls parades into your organization's server room and copies all
of your password hashes, your self-documenting tags prevents him from usefully
giving your password hashes to his cybercriminal buddies at The Com
without being honest about where those hashes originally came from.

Here, Mr. Big Balls is acting as Eve, and The Com is acting as Craig.

If somebody among The Com were to betray the effort and report the stolen
hashes back to your organization, then they'd be acting as a friendly Craig.

### The Botnet Cracker

If The Com then decides to use a [botnet](https://arstechnica.com/security/2024/03/attack-wrangles-thousands-of-web-users-into-a-password-cracking-botnet/)
or [other stolen computing resources](https://www.reddit.com/r/aws/comments/x03vay/hacked_aws_account_is_facing_200000_in_charges/) in an attempt to
crack your passwords, then there is an unavoidable risk of the computation
being observed, and the payload given to a security analyst.

Thanks to self-documenting cryptography, the security analyst will be able to
take The Com's implementation of your password hash algorithm, and from it
reverse engineer your invitation to contact your organzation about the stolen
hashes.

Here, The Com is acting as Eve, and the stolen computing resource is acting as
Craig.

Also in this story, the stolen computing resource is acting as a kind of Eve,
and the security analyst is acting as a friendly Craig.

### The Professional Cracker

There are certainly legitimate use cases for password cracking. Without the use
of self-documenting tags to securely enforce the origin of password hashing
data, many who are involved in legitimate password cracking activities are at
risk of unknowingly participating in unethical and/or illicit activities.

For example, let's say you are a password cracking professional who wants to
stay above board, and a corporation wants to hire your services for legitimate
work. Today's password hashing technology does not itself impose any impediment
to a corrupt IT worker at that corporation who wishes to commingle outside
password hashes into the data being forwarded to you.

The best case scenario would be that self-documenting domain separation has
been applied to all the legitimate data to be cracked. These tags prevent all
outside data from getting in, greatly reducing the scope of abuse of your
legitimate password cracking services.

On the other hand, applying self-documenting domain separation to outside data
also prevents it from getting cracked by legitimate, professional crackers,
even if they cannot robustly restrict their efforts to only legitimate data in
a particular engagement. If you are the organzation that applied the tags,
then your password hashes cannot be usefully commingled without creating a
significant risk of discovery.

# Combinatorics of Cryptographic Continuations

How many password hash functions are there? Cryptographic hash functions
aspire to be a "good enough" approximation of an idealized random oracle.
Random oracles cannot exist in reality, but they provide a useful mathematical
model for analyzing cryptographic constructions.

An idealized random oracle is a pure function whose input space is all finite
strings, and whose output space is several hundred fair coin flips. As there
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
otherwise offers no practical way of distinguishing among the resulting random
oracles.

However this naive view is misleading: practical hash functions usually support
streaming input. For example, SHA256 uses a compression function that applies
an input block of 64 bytes to a state of 32 bytes, resulting in a new state.
This allows arbitrarily long inputs to be processed one block at a time, and
is more or less how most cryptographic hash functions are structured.[^not-blake]

Even if we assume the compression function is an idealized random oracle, this
structure reveals that with prefixed salts, finding a single collision on the
compression function is enough to produce an infinite family of collisions.
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
functionally distinct prefixed salts without leaving some salt prefixed in the
input buffer, or suffixing some salt after the password. Even though the input
space of prefixed salts is much larger than 256 bits, collisions on the
compression function propagate throughout the remainder of the computation.

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
password input. This forces the full plaintext of any suffixed salt to be
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

Moreover, colliding the function that results from this partial application is
highly implausible. Because the salts `Y` and `Z` must be distinct, just by
picking any choice of `x` a counterexample would be able to create a very large
number of cryptographically distinct collisions for free.

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
this is intimately tied to partial evaluation, and much of the design work
around the G3P revolves around understanding and controlling partial evaluation!

For example, we want to enhance the utility of legitimate forms of partial
evaluation, which is why the G3P adopts fully incremental key-stretching as a
design goal. Also, we want to prohibit the possibility of partially evaluating
away the plaintext of any tag, therefore prefixed salts cannot be tags, which
is the reason the G3P's "username" parameter doesn't have "tag" anywhere in
the name.[^username-padding]

**Observation:** Remember that our goal is to adversarially pass messages inside
algorithms via the mathematics of game theory. At least one of our primary
communications objectives is expected to typically be on the order of one
hundred to a few hundred bytes long, which is much longer than the 256-bit
SHA256 state machine.

We need to argue that our message is implied by the algorithm we specify. Thus
we should prefer to argue that our message describes a unique algorithm in a
space of up to 2^(2^264) hash functions rather than arguing that our message
describes some inscrutable equivalence class consisting of those inputs that
produce a single one of 2^256 possible SHA256 states.

We should prefer the former argument over the latter even if we are unlikely to
ever be able to explicitly find a collision, because it is a stronger argument.
The difference reminds me of the distinction between information-theoretic
versus computational security. Moreover, the act of making the latter argument
is (at the very least) a brown M&M suggesting that partial evaluation may be
possible, which we wish to prevent in the case of tags!

Salts suffixed after a password plausibly achieves the properties necessary to
make our preferred argument work, whereas prefixed salts clearly do not.
Furthermore, partial evaluation provides a method of obscuring (part of) a
prefixed salt, meaning that arbitrary messages cannot be robustly passed via
a prefixed salt alone.[^seguids]

On the other hand, prefixed salts are still useful, especially for account
separation purposes. This ensures that the password hash function has committed
to a particular account before the plaintext of the password can be processed.
In effect, the password serves as a tag relative to the prefixed salt.

This is the reason why the G3P uses "username" as the name of the prefixed
salt parameter; these parameter names do not prescribe a particular usage, but
they do suggest an intended usage.

# Overview of the G3P

This section is intended to give an accurate overview of the G3P's major
cryptographic constructions, but also tries to not get lost in the finer
details. Thus this section is not suitable as an implementation reference.

Note that any identifier written in `UpperCamelCase` is an external parameter
that must be filled in before hashing can be completed, any identifer written
in `lowerCamelCase` is some intermediate or final result of the password
hashing computation, and any identifier written in `ALL-CAPS` is a standard
cryptographic routine or a syntax-generating routine.

`+` is string concatination, except when it clearly refers to unsigned
machine-word arithmetic. Don't take concatination too literally as this
section elides certain auxiliary inputs and all length-related padding.

This length padding encodes the bitlength of every external argument, which
prevents shifting bytes between them in order to create cryptographically
trivial collisions. The length padding also repeats (parts of) the plaintext
of various tags as message filler.

Most input values and field lengths can be robustly decoded from the `HMAC`
input message alone, and those that cannot are either HMAC keys or can be
decoded from the inputs to BLOWFISH-EXPAND. Thus all collisions on the G3P
are cryptographically non-trivial.

The G3P operates on bitstrings. The syntax generators used never look at the
content of any bitstring, only it's length. Thus by [parametricity](https://en.wikipedia.org/wiki/Parametricity)
there cannot be any data-dependent truncations such as bcrypt's null byte. And,
with handful of documented exceptions[^truncations-in-the-G3P], most of the
bitstring inputs may be of arbitrary length and will never be truncated.

The G3P's maximum theoretical password length is very nearly SHA256's length
limit: 2.3 million terabytes. However, the password is prefixed with its length.
Being forced to commit to the exact length of a password up front limits
opportunities for streaming absurdly long passwords into the G3P, as would be
necessary in this case.

Also by parametricity, inspecting only the length implies that any reasonable
implementation of the G3P's syntax generators cannot be solely or directly
responsible for introducing data-dependent side-channels. With unavoidable
exceptions, significant effort was put into making the G3P take a constant
number of cryptographic operations regardless of the length of its bitstring
parameters.

## Iterated HMAC preprocessing

The key-stretching phase of the G3P is an iterated HMAC-SHA256 construction.
The first form of key-stretching is essentially PBKDF2.[^pbkdf2-tagged-hmac]
Here is PBKDF2's cryptographically secure pseudorandum number generator
(CSPRNG) on top, followed by the modified generator on bottom.  Both are
examples of a "KDF in feedback mode" from [NIST SP 800-108: Recommendation
for Key Derivation Using Pseudorandom Functions](https://csrc.nist.gov/pubs/sp/800/108/upd1/final)

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

These modifications take much inspiration from HKDF and [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869),
which inspired the name PHKDF. The most significant departure from
PBKDF2-HMAC-SHA256 is the addition of a counter and tag to salt every round of
PHKDF: this is literally just taking bytes that were specified as null, and
using them as supplemental salt in the same vein as HKDF's info parameter.

One of the more obvious differences is that the parameter that PBKDF2 calls the
"password" is now called the "seguid". Instead of using the actual password as
an HMAC key, the G3P recommends using a [self-documenting globally unique
identifer](seguid.md) as a supplemental salt that identifies the deployment,
and moves the password into the parameter that PBKDF2 calls the "salt".
Given that PBKDF2's standard mode of operation tweaks the salt repeatedly to
generate cryptographically independent output blocks, this should be a totally
safe thing to do.

A practical advantage to this alternate mode of operation for PBKDF2 is that
the password can be forgotten as soon as it has been hashed the first time,
which happens right at the start of the computation before key stretching.
This isn't true at all in classic bcrypt: the plaintext password must be known
up until the middle of the very last bcrypt round.

Using precomputed HMAC keys avoids the need to preserve the literal plaintext
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
possible about the original password. Because this continuation must include
all information necessary for computing the final hash, it necessarily provides
a cracking attack against the password, or worse.

Sometimes cracking isn't really necessary. In classic bcrypt, nearly any
continuation will reveal the plaintext of the password directly, as it is
needed throughout the key-stretching process. In other cases, such as PBKDF2's
classic mode of operation, such a continuation must reveal a hashed version of
the password with no key stretching applied.

A synchronization point is a continuation whose most efficient cracking attack
costs almost as much _per guess_ as the work required to create that
continuation in the first place. This property implies that a password hash
computation can transferred from one device to another with full credit for
key-stretching work already performed.

Neither classic bcrypt nor classic PBKDF2 have any useful synchronization
points. PHKDF has a synchronization point every round, and our modified bcrypt
has a synchronization point every super-round.

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

This seed is fed into a key derivation function (KDF) built around HMAC-SHA256,
which provides a last-minute opportunity for domain separation before final
output expansion. This function performs no additional key stretching, so
therefore it is very fast relative to computing the seed itself.

    keyL = HMAC ( SproutSeguid, "G3Pb2 delta" + seed + Role + "KEYL" + SproutTag )

    out0 = HMAC ( keyL + EchoKey, EchoHeader + INT_32_BE(EchoCounter) + EchoTag )
    out1 = HMAC ( keyL + EchoKey, out0 + INT_32_BE(EchoCounter + 1) + EchoTag )
    out2 = HMAC ( keyL + EchoKey, out1 + INT_32_BE(EchoCounter + 2) + EchoTag )
    ...

This final key derivation function resembles HKDF-SHA256, with the computation
of `keyL` corresponding to HKDF-Extract, and the output blocks corresponding
to HKDF-Expand.

However, there are a handful of mostly minor changes: we are using a
parameterized 4-byte counter before the domain tag, whereas HKDF uses a
hardcoded 1-byte counter after the info tag. Furthermore, this construction
also parameterizes of the right 32 bytes of the output key.

However, the most significant change by far is parameterizing the 32-byte
initial generator state. Note a trivial collision can be obtained by feeding an
output block back into the `EchoHeader` parameter and by incrementing the
counter by one, which is the same thing as the next output block.

Also, the `EchoHeader` parameter violates HKDF's strict principle of cleanly
separating entropy extraction and final output expansion. As a result,
important new secrets must _not_ be introduced via the `EchoHeader` alone
whenever more than one output block is revealed to an adversary. Doing so
allows a cracker to bypass the `EchoHeader`, re-revealing a cracking attack on
the original keying material alone.

Despite these issues and the fact it is truncated to 32 bytes, the `EchoHeader`
is not difficult to use safely. The default recommendation is to duplicate the
input to `EchoKey` and `EchoHeader`, which is one of several ways this issue
can be avoided.

The `EchoHeader` parameter exists to regularize timing side channels regarding
the length of the `EchoTag` parameter, because it can be a strategic location
to leave a plaintext tag, and because it could be potentially rather useful when
you want very efficient random-access output.

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

Our goal is to compute `bcryptOutput`, which is one or more fixed-length
binary blobs, each longer than 12 kiB, consisting of bcrypt's P-box and S-box
interspersed with portions of the bcrypt long tag. There is one blob for every
super-round, and one super-round for every 128 bcrypt rounds rounded up.

    msg   = (portions of BcryptLongTag)
    state = (classic bcrypt initial state based on digits of pi)

    for each super-round:
       key0   = HMAC
                 ( BcryptSeguid,
                   "G3Pb2 charlie" + keyB + msg +
                   BcryptContextTags + "KEY0" + BcryptDomainTag )
       key1   = HMAC
                 ( BcryptSeguid,
                   "G3Pb2 charlie" + keyB + msg + key0
                   BcryptContextTags + "KEY1" + BcryptDomainTag )
       msg   += (key1 then key0 interleaved with portions of BCryptLongTag)
       state := bcryptSuperRound ( state, key0, key1, BcryptLongTag )
       msg   += (state interleaved with portions of BCryptLongTag)

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

In actuality, the cyclic extension of `BcryptLongTag` is processed across
rounds, so that moderately long tags have their bytes processed more evenly,
and so that very long tags are truncated at `(rounds + 1) * 4136 + N` bytes
instead of `4136` bytes. However, the substring that affects a single round is
repeated verbatim in four different operations within that round.

This simplified overview demonstrates that the G3P's modifications to bcrypt
also requisitions previously unused null bytes, much in the same way that PHKDF
requisitions previously unused null bytes found in PBKDF2 for tagging purposes.

If two states collide, then the result of modifying that state with `XOR(x)`
will always be different than that same state modified by `XOR(y)` for distinct
`x` and `y`. This observation is also true of `BLOWFISH-EXPAND`.

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
computation, the counter guarantees the subsequent state _will_ be different
than all previous subsequent states.

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

The XOR operation of the initial round of a superround moves the incoming
`key0` from the left side of blowfish's P-box to the right side of the P-box.
Paired with using `key1` as the first 32 bytes of the salt to `BLOWFISH-EXPAND`,
this ensures that all 512 bits of the incoming keys are encoded relative to the
previous state in just four blowfish block operations.

The transitions between two super-rounds are designed to be synchronization
points, and it doesn't make much sense to transfer a bcrypt key-stretching
computation from one device to another outside these transitions.

In the middle of a super-round, key0 and key1 would need to be transferred.
These values must be computed before a super-round can begin, thus a cracker
could attack these keys directly and would not need to compute any portion of
the current super-round.

Also, the bcrypt state machine can be run in reverse. There is an efficient
implementation of `BLOWFISH-REVEXPAND` that will produce a starting state given
a final state. This computation can be shared across multiple guesses, meaning
that a cracker can instead attack the final bcrypt state of the previous
super-round. Compared to cracking `key0`, this saves a half-round of bcrypt and
more than 12 kilobytes of SHA256 input processing per guess.

These keys are forgotten as part of the transition between super-rounds, which
prevents moving backwards across every XOR. This act of forgetting enables the
key-stretching ratchet to make forward progress.

There is also an efficient implementation of `BLOWFISH-TRANSCODE` which takes
as input any single pair of starting and ending states, and produces the unique
transition code that can be used with `EXPAND` and `REVEXPAND` to move directly
between those two states. The existence of `BLOWFISH-TRANSCODE` demonstrates
that the salt being provided to `BLOWFISH-EXPAND` can be efficiently inferred
from any memory-tracing debugger that reveals the before-and-after states.

These three functions imply that the bcrypt state machine forms an efficiently
computable [quasigroup](https://en.wikipedia.org/wiki/Quasigroup) with 2^33334
elements. This algebraic structure demonstrates how to one can control the
final output state of this generalized bcrypt if one is allowed full control
over `BCRYPT-EXPAND`'s salt after looking at the other input parameters.

This is a pretty serious attack against the conventional cryptographic
properties of a generalized bcrypt. This informed these modifications in an
attempt to avoid these issues, in particular by not allowing the `BcryptLongTag`
to directly affect the first 32 bytes of the state, and by requiring that the
substring that affects any given round is repeated verbatim in two XOR
operations and two BLOWFISH-EXPAND operations within that round.

Of course, the intended use of the `BcryptLongTag` salt is that it is to be
chosen without looking at the incoming keys, which renders these concerns
moot. Furthermore, parts of this tag are mixed into the SHA256 function that
derives the incoming keys. This forms a local commitment scheme that ensures
that one cannot look at the incoming keys and then choose substrings of the
`BcryptLongTag` that affect the first one-and-a-half rounds and the last round
of a super-round.

# Deployment Considerations

A deployment designer may notice that the Global Password Prehash Protocol has
21 parameters. This may seem excessive, but the thing to remember is that the
G3P is carefully designed so that almost every parameter must be an exact match.
Any difference means the outputs will be cryptographically independent to any
efficient observer who isn't privy to enough of the inputs.

There are a few exceptions, but to the best of my knowledge they are all
documented: there are some trivial (but largely uninteresting) "collisions"
involving HMAC-SHA256 keys. This behavior is externally dictated by relevant
standards. Additionally, there are truncations of the `EchoHeader`, `EchoKey`,
and `BcryptLongTag` parameters. All other collisions on the G3P are
cryptographically non-trivial.

Also, introducing new secrets via the `EchoHeader` alone is not necessarily
secure, providing a slight caveat to the claim of cryptographic independence.

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
be replaced with two intermediate SHA256 states via partial evaluation, which
is why "tag" doesn't appear in "seguid".

Finally, I recommend taking a look at [MyCorpExample.hs](../g3p-hash/test/MyCorpExample.hs)
in the G3P's test suite, as it is a slowly-evolving example of what a typical
deployment might look like.

## Second Secrets

It is a good idea to officially support second secrets, akin to 1password's
2SKD. One of the primary intended purposes of the G3P's `Credentials` vector is
to support second secrets.

In this context, a second secret is basically a second password, though
often there's a connotation that is selected randomly for the user, instead
of something chosen by the user.

Second secrets should be optional. A security-minded user might choose to use a
reasonably long passphrase as a second secret, and then use a relatively short
and convenient passphrase as the password.

The user could persist the second secret to their device, and the user might
expect to type the password on a semi-regular basis. This gives significant
protection against shoulder-surfing attacks, while providing a modicum of
protection against software-based credential stealers.

Before it is persisted, the second secret should be hashed, key-stretched,
and domain separated, so that the only thing that the uncracked hash could
possibly be useful for is within the context of your deployment.

Thus, the G3P could be used to hash the second secret at about the same
cost as your chosen cost parameters for hashing the user's password.  That
hash could then be included in the G3P's `Credentials` vector to support 2SKD.

## Account Separation

### Public Salts

Assoming your deployment will have more than one user, your deployment should
almost certainly be applying a unique salt per account as domain separation,
and should do so up-front. This per-account salt achieves exactly the same
effect as what traditional salts achieve: in effect, every account gets to use
its own unique password hash function. Ideally this salt would be applied early
on in the hashing process, preferably before the password is even hashed.

Handling per-account salt is a significantly more complicated when client-side
prehashing is involved, as the client will have to somehow know which salt to
use. The remainder of this section should be understood within this prehashing
context.

There's two basic categories of approaches: transparently deriving a salt from
a login name, or storing a random salt directly in a database. In the former
scenario, there is an unbreakable connection between login names and derived
salts, which can be guessed offline. In the latter scenario, members of the
general public need to be able query the salt associated with a specific login
name via a public salt server.

In either case, security can be substantially improved by having login names
that are untethered (at least in part) from public identifiers. Otherwise, if
the password hash of a high-profile account gets leaked, it won't be difficult
for a cracker to find the login name from the salt alone no matter what approach
you take.

The simplest possible transparently-derived salt might use a normalized login
name as the input to the `Username` parameter only. The G3P ensures that the
entire plaintext of this parameter can be partially evaluated away, so in this
scenario it's always possible for an eavesdropper to give individual accounts
a modicum of privacy when they turn the hashes over to crackers.

However, this partial evaluation doesn't apply any key-stretching to the
login name, so it would be relatively inexpensive for a cracker to try to guess
the login name. Furthermore, the password and the login name could be cracked
one at a time.

One could apply key-stretching to the login name, possibly via the G3P, to
derive a salt in a transparent way. That derived salt should be included in
both the `Username` and `ContextTags` parameters, but probably omitted from the
`BcryptContextTags` parameter. This might make it much more expensive for
a cracker to guess a login name from a transparently-derived salt.

The advantage is that transparently derived salts avoid possibilities for
account existence attacks, account enumeration attacks, and other pitfalls of
running a public salt server. The downside is that a cracker who has obtained
one of your salts could crack the login name offline, without ever talking to
your public salt server.

Furthermore, you will probably want or need to normalize the login name in one
or more ways. For example, if you want to support case-insensitive login names,
you might choose to convert the login name to all lower case, or all upper case.
Supporting Unicode login names potentially brings its own normalization issues.

Transparently deriving a salt means you will will need to robustly apply these
normalization rules. Prehashing scenarios require that this normalization be
performed on the client, or at least as an RPC call to the server. Having the
option of verifying a normalization via RPC is highly recommend. Fortunately,
username normalization issues can be almost entirely avoided when setting
a password via dynamic testing.

On the other hand, if you use random salts, login names cannot possibly be
guessed from the salt without talking to your public salt server. Just like a
key-stretched username, this salt should be included in both the `Username`and
`ContextTags` parameters but not the `BcryptContextTags` parameter.

Futhermore, you wouldn't have to deal with login name normalization issues on
the client: this could be confined to server-side computations where you have a
lot more control over what ultimately happens. Moreover, this approach need not
carry a cryptographic commitment to your normalization scheme.

The downside of running a public salt server is that it could provide an
account existence oracle, or even worse, an account enumeration oracle, to
attackers. This is addition to the more generic attack surface that running an
online service represents.

A reasonable length for a random public salt might be 8-16 bytes. There's
no need for long salts if your database can enforce uniqueness. Moreover,
cross-domain collisions on this salt will not be an issue if you are using
deployment-identifying domain separation as well.

It is highly recommended that the public salts be sampled or derived from a
high-quality cryptographically secure source and stored directly in a database.
In particular, the public salt should not be derived from non-public seeds and
keys.[^ephemeral-derivations] This avoids any possibility of an eavesdropper
stealing that non-public information and using it as evidence to third parties
that they have actually compromised your infrastructure, preserving your
plausible deniability regarding the incident.

Handling queries for accounts that don't exist is the most complicated aspect
of running a public salt server. You should endeavor to hide the existence or
non-existence of an account from members of the general public, so you will need
to generate a fake answer for non-existent accounts. Moreover, this fake answer
needs to be stable over time, and we'd prefer not to have to maintain a large
database of non-existent random salts for every login name ever asked about.

The obvious solution is to compute something akin to `HMAC(SecretKey, Username)`
on the normalized, non-existent username. This requires essentially no storage,
and would be sufficient to provide a stable, consistent answer that could not
be distinguished from random strings as long as your key remains secret.

However, leaking this key would allow the existence or non-existence of any
account to be inferred via your public salt server, thus granting its holders
an account-existence oracle. Thus you need to be able to start a migration to a
new key without disturbing fake salts that have already been provided. This can
be accomplished using [bloom filters](https://en.wikipedia.org/wiki/Bloom_filter)[^bloom-example]
to avoid the need of storing every non-existent username ever asked about.
Perhaps there would be one or more bloom filters per key, each tracking the
nonexistent usernames that key has very likely seen.

### Private Salts

It's highly recommended that in addition to a public salt, that your deployment
also use some kind of unique _private_ salt per account.

Unlike public salts, these private salts would not normally be acknowledged as
belonging to your organization, therefore there is no downside to deriving
private salts from secrets and other non-public information.

In fact, it's recommended that you store a secret seed per account, maybe ~16-24
random bytes, and then use a relatively small number of secret keys stored
outside the database to derive an ephemeral private salt. Not only can this
decrease the storage requirements for your private salt database, it also can
make it harder to steal.

That way, if an eavesdropper steals your keys and not your seeds, then the
seeds prevent the disclosure of any of your private salts. If there wasn't a
secret per account, then the eavesdropper who steals your keys may have stolen
your entire private salt database, possibly including salts not yet in use!

Similarly, if a eavesdropper steals your database of seeds, but not your keys,
then the keys prevent the disclosure of your private salts. Given that database
exploits are shockingly common, this seems like a wise thing to do.

You need to be able to support multiple secret keys, because you need to be
able to start migrating away from existing keys to new keys at any time,
and you often won't be able to establish any specific timeframe after which
you can delete your existing keys.

It is highly recommended to apply self-documenting tags on the server side
as well as the client side. Unfortunately argon2 is not particularly secure
in the sense of Adversarial Literate Programming, as none of it's bytestring
inputs are required to compute its key-stretching phase.

Using the G3P, or it's simplified "foxtrot" variant, as a preprocessing
and/or postprocessing step to argon2 should be an adequate workaround for
those wanting to integrate argon2 into their password database.

## Dynamic Testing

There are many moving parts that go into a password hash implementation. If
something goes wrong with the hash computation when a password is set, this
can lead to a major inconvenience or even data loss. This may lead to the need
to reset the password in the case of a traditional website, or lead to the
inability to decrypt an end-to-end encrypted file.

Dynamic testing can greatly reduce the probability of this happening. Moreover,
failed tests build operational awareness of relevant implementation issues
affecting your deployment.

When the G3P is deployed as a client-side prehash, you often won't have full
control of the stack its running on. Thus a dynamically-generated dry-run test,
akin to a theatrical full dress rehearsal, is highly recommended whenever
setting or changing a password.

Here, every parameter should be as close as possible to what it will look like
in the actual password hash computation. In most cases, this means every
parameter other than the password and second secret should be exactly as it
will be for the actual computation.

The server should generate a random nonce, possibly encoded as a passphrase, to
use as the password and/or second secret inputs. This nonce should have at
least 128 bits of entropy, and it should be sampled or derived from a
cryptographically-secure source. The server then sends the password and say,
the first 16 bytes of the hash resulting from the test.

The client should then run the G3P on the password with the full number of
rounds, and then use the outputs as further inputs to the G3P and its key
derivation function. By chaining together outputs and inputs, one can
consolidate many test vectors into a single test vector.

After the first computation, key-stretching can and probably should be run with
a reduced number of rounds. Typical deployments should include a test with a
password input that is exactly 31 bytes long, a password that is exactly 32
bytes long, tests with and without a second secret if your deployment officially
supports 2SKD, and further tests of the final, fast key derivation function as
suited to your deployment.

Once a final hash has been computed, the client application can compare the
first 16 bytes to verify that it has passed this full dress rehearsal, and
sends the resulting hash in response to the server as part of the password
change process. The server can then use the last 16 bytes of the output hash to
verify that the client has indeed performed and passed its full dress rehearsal.

## Login Page Testing

It is a good idea to run a largely-static tech rehearsal of the G3P whenever a
user is trying to log in, in addition to a more fully-dynamic full dress
rehearsal as a prerequisite for setting a password.

A temporary login failure is typically much less consequential in the long term
than a failure when setting a password. For this reason, there's much less need
to test the G3P with the exact same parameters that will be used in an actual
production computation, outside of the user's actual inputs of course.

Even so, a quick self-test of the G3P can save the user potentially a lot of
confusion, frustration, and anger of not being to log in with their correct
password. Furthermore, the user's misdiagnoses could lead to unnecessary and
counterproductive "remedial" actions by that user, such as password resets,
possibly causing further harm. Finally, test failures build operational
awareness of implementation issues affecting your deployment.

A full dress rehearsal should include at least one test of the exact parameters
specified by the deployment for that specific account, including all salt and
cost parameters.

A login tech rehearsal should follow the same testing script, and should still
try to keep the parameters as close or at least as representative as possible
to what will actually be used, but there also isn't the need (or necessarily
ability) to include the user's exact public salt, for example. In particular,
I recommend running the G3P with a reduced number of rounds for this test.

## Passphrase Generation

It is highly recommended that you encourage your users to adopt [random
passphrases](https://www.eff.org/dice). One of the best ways you could do this
is to include a secure passphrase generator in any user interface that allows
you to set a password. I believe that passphrase generation should be a
standard feature expected of any form that sets a password.

The [EFF's Short Wordlist #1](https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt)
seems like a reasonable default choice of wordlists, however the user should be
allowed to select from a list of standard wordlists, and provide their own
should they choose to do so. A good default passphrase length would be about
five or six words in the case of this wordlist.

Moreover, setting a password entails dynamic testing of the G3P, which entails
sending a cryptographically-secure random nonce from the server to the client
as part of this full dress rehearsal. This should be reused to protect against
weaknesses in the client's source of cryptographically-secure randomness.

Substantial key-stretching is applied to this nonce as part of a full dress
rehearsal, and there and there is no reason not to use an output derived from
this key stretching computation. Then we sample data from the client's
cryptographically-secure random sources, and hash those samples with the
output. The result can be used to seed a CSPRNG, and all source material
needs to then be permanently forgotten.

The client should sample from whatever cryptographically secure random sources
are available. Ideally a client would sample both `/dev/urandom` (or comparable
on Windows) *and* employ `RdRand` or comparable CPU instructions if available.
On browsers, you'd be typically be limited to WebCrypto's `getRandomValues`.

## Passphrase Assistance

One of the downsides of random passphrases are that they are longer than a
comparably strong random string of letters and digits. This means there are
more opportunities to mistype your passphrase. On the other hand, experienced
typists find it easier to type familiar words than random letters. Futhermore,
the entropic redundancy also implies that we can apply useful levels of error
correction to a passphrase before it is hashed.

Following the principle of least suprise, the default should be to have no
assistance. Perhaps a checkbox that says "I use a passphrase and I want
misspellings corrected automatically", which would then reveal further UI
elements with some default wordlist selected, and the option to select from
among a few other standard wordlists or to provide your own.

Of course, the login page should offer a convenient and relatively obvious
way of saving these as defaults for the computer and/or account in question.
Futhermore, no spelling corrections should ever be automatically applied when
setting a password, though you can alert the user to the fact that there are
misspellings.

Also, one might consider using an external checksum on the second secret to
alert the users to most mistypings earlier, especially if they will type the
second secret before the password. Yet, we don't want our checksum to assume
anything about the form or content of the second secret, and we don't want the
existence of our external checksum to be able to speed up a cracking attack
against the second secret.[^have-i-been-pwned-lookup]

My suggestion is to apply some domain separation after key stretching to
obtain an external checksum, and then check that the first 12 bits are zero.
This automatically invalidates all but 1 out of 4096 passwords. "Mining" a
password by repeatedly trying enough different passwords until you get lucky is
the only practical way of finding something that passes this checksum. Another
output hash can then be derived from the seed to be used as an input to the
the G3P's `Credentials` vector.

Incidentally, external checksums can be used to solve the problem of users not
trusting their RNG, and system administrators not trusting the randomness of
their users. For particularly sensitive second secrets, one might use dice to
manually generate a partial passphrase, which is then run through a password
miner that inserts one or more words to complete that passphrase.

## On-screen keyboards

Passwords and passphrases have a nasty habit of appearing in the assistance
features of on-screen keyboards. Thus smartphone apps and webpages that handle
password inputs must take all reasonable precautions[^unreasonable-precautions]
to try to prevent this from happening.

## Virtual Memory

Passwords and have a nasty habit of showing up in swap files. Any program that
ever handles a password should endeavor to try to prevent this from happening.
Administrators of authentication servers need to be aware of this issue and
take steps to mitigate it.

Implementors can improve the situation by using `mlock` system call on Linux to
try to prevent certain memory pages from being written to swap, or whatever the
best solution is on modern Linux. There are presumably comparable features
offered by many other operating systems.

Administrators of authentication servers might consider disabling swap on that
server, or at least ensuring that it is encrypted with a truly ephemeral key.

I do realize that comprehensively tackling this issue isn't realistic in many
contemporary scenarios, especially when client-side devices or virtual machines
are involved, but this lamentable state of affairs can always be improved by
ensuring that passwords do not persist for long in memory, and are zeroed
out as soon as possible.

Thus the G3P is designed such that the password can be permanently forgotten
before 99.99% of the hashing algorithm has been computed. Professional password
handling  implementations should strongly consider adopting this approach.

# Tag Obfuscation Attacks

Our goal is to adversarially pass messages inside password hash algorithms via
the mathematics of game theory, in an attempt to solve the Adversarial Literate
Programming problem.

Alice from Acme gets to specify a password hash algorithm tagged with some
associated documentation, and Eve wants to allow Craig to run Alice's algorithm
while denying Craig access to Alice's tags.

Eve could simply instruct Craig to run a binary blob of her own choice. Using
any kind of straightforward, standard implementation technique means that
Craig could simply dump the strings and discover Alice's open invitation to
contact Acme Corporation.

But Eve could try to hide Alice's documentation in the binary using various
obfuscation techniques. The International Obfuscated C Code Contest is
particularly famous, but the techniques demonstrated there cannot defeat
a persistent reverse engineer attempting to recover the tags from an
implementation of the G3P.

In the G3P, the tags can be inferred by watching the transitions of the SHA256
and blowfish-expand state machines with a memory debugger. Thus, in order to be
secure against the best reverse engineers on their best days, Eve must
implement those machines in such a way that the state transitions cannot be
observed by those who are physically running the machines.

In theory it should be possible for Eve to use some flavor of Homomorphic
Encryption (HE) to conduct a secure  _tag obfuscation attack_. For example,
people have demonstrated being able to compute a few blocks of SHA-256 inside
Fully Homomorphic Encryption (FHE) within a few seconds.

While most forms of Homomorphic Encryption impose significant overhead, FHE is
in a class of its own. It is normally possible to compute millions of SHA256
blocks within a few seconds even on modest hardware. The overhead of even
state-of-the-art FHE is extreme, often increasing the time and resources needed
to perform a computation by a factor of a 100,000 or more.

However, the surprising existence of FHE, and the fact that it can in theory
obscure any computable algorithm whose output itself doesn't give away secrets,
suggests that it might not even be possible to stake Adversarial Literate
Programming's security goal on an asymptotic difference in the complexity of
algorithms.

Rather, Adversarial Literate Programming may be limited to a linear factor,
making its security margin relatively weak for cryptography. I would even say
that acheiving a traditionally-strong security margin in the context of
Adversarial Literate Programming seems implausible.

On the other hand, that linear factor is quite large, and password cracking is
sensitive to even modest overhead. In this context, FHE doesn't seem to be any
immediate threat to Adversarial Literate Programming based on standard
cryptographic primitives like SHA-256 and blowfish-expand.

While I don't know how much better future homomorphic encryption schemes might
be able to perform on SHA-256 and blowfish, I'm not expecting revolutionary
improvements in efficiency in the near future. I am expecting FHE will remain a
less-than-practical threat to the G3P for some time to come. On the other hand,
the threat of FHE is also significant enough that the design of the G3P needs
to take it into account.

In particular, in argon2, you can append tags to the end of passwords, and an
obfuscation attack would then require Homomorphic Encryption to be truly secure.
This provides effective domain separation, so argon2 alone should be sufficient
to protect a professional password cracker from illicitly commingled hashes, as
it would be unethical to knowingly run a password cracker that incorporates
homomorphic encryption.

However, a argon2-based suffixed salts are not particularly secure in the sense
of Adversarial Literate Programming. This is because in more adversarial
scenarios, such as password crackers running on botnets and other stolen
compting resources, it's very important to maximize the overhead inflicted
on Craig by Alice and Eve.

All of argon2's bytestring inputs are hashed in a single call to Blake2b[^argon2-spec],
and that resulting hash is the only thing needed to compute argon2's
key-stretching phase. Eve could simply hide Alice's tag and other parameters
inside an FHE-based implementation of this initial call to Blake2, and return
the plaintext hash needed for key-stretching.

Deploying FHE might inflate the cost on that initial Blake2 call from a few
microseconds to a second or two, and might inflate the otherwise trivial
memory consumption to a few hundred megabytes. However, that might be an
overall cost multiplier of 2 or 3 or so, as ideally argon2's key-stretching
computation should itself cost about one second and require a few hundred
megabytes of random-access memory.

That cost mulitplier does not seem nearly high enough to throughly dissuade
Eve from deploying a practical tag obfuscation attack, especially if it's
running on stolen resources!

Relative to the G3P, argon2 is desirable because it can be made to require  a
lot more RAM to compute. You could get the best of both worlds by using the
G3P, possibly with a reduced number of rounds, as a preprocessing and/or
postprocessing step for argon2. In fact, the reference implementation offers
a simplified `g3pFoxtrot` hash function intended for this purpose.

While it would be preferable to someday have an argon2 variant that carries
plaintext tags all the way through the key-stretching computation, combining
the G3P and argon2 is likely a more than adequate workaround for now. Catena
and yescrypt appear to have significant potential for being self-documenting
memory-hard password hash functions, though this appears to be accidental and
this potential could almost certainly be improved, much like the partial
cache-hardness of bcrypt.

In the argon2-only FHE scenario, Craig _might_ be able to still determine the
parameters hidden inside by computing a hash with a known password and then
cracking the unknowns. This approach can be facilitated when Craig is aware
of Alice's documentation but is not yet aware that Alice's documentation is
immediately relevant to the hash functin he is reverse engineering, so it
helps to be open and notorious about your deployments of self-documenting
cryptography.

However, this requires more sophistication and more computation on Craig's part
compared to reverse engineering Alice's documentation from Eve's implementation.
Furthermore, if the additional parameters hidden inside FHE include say, a
random 16-byte salt for account separation purposes, then this approach to
recovering Alice's documentation won't work.

For this reason, the G3P is designed such that Alice's documentation is
required throughout the entire key-stretching process. Ideally, the only way
for Eve to carry out a secure obfuscation attack would be to run the entire
key-stretching process in Fully Homomorphic Encryption, thus maximizing the
computational overhead inflicted on Craig by Alice and Eve.

# The Cryptoacoustic Transmission Medium

Passing messages adversarially inside cryptographic algorithms deserves a
memorable name, and I've chosen "cryptoacoustics".

Conventional cryptography ensures that you have access to the plaintext of the
key, then you can run the algorithm. Cryptoacoustics ensures that if you can
run the algorithm, then you have access to the plaintext of a tag. Thus
cryptoacoustics is a logical converse of cryptography, not unlike the way
statistics is a logical converse of probability.

Conventional cryptography cannot ignore the converse, but it is also filled with
concrete examples, including the HMAC construction, where the ability to run an
algorithm implies access only to something derived from the key, which often
isn't suitable for communicating messages.

Cryptoacoustics pays scrupulous attention to the converse. In the context of
the G3P, a the plaintext of any tag can be inferred from a memory trace of any
ordinary implementation of SHA256 and blowfish-expand. Thus any truly secure
tag obfuscation attack by Eve must incorporate some form of Homomorphic
Encryption to prevent Craig from using a memory debugger to see those traces.

If you can pass messages, then there must be some kind of transmission medium,
in this case it is the mathematics of game theory and cryptographic state
transitions. In late 2020 I had some insights that lead to the vaguest
conceptions that it should be possible to improve the service provided by
"Have I Been Pwned" by insourcing it[^have-i-been-pwned], and had clues that
salts could become indicators of compromise that would have to follow the
password hash around. My eureka moment came in July of 2022 shortly after
writing a trio of essays about [relevance logic](https://github.com/constructive-symmetry/constructive-symmetry/blob/master/T002_Tools_of_Math_Construction/Part02_Deconstructing_Bertrand_Russell.md),
[the early childhood math curriculum](https://github.com/constructive-symmetry/constructive-symmetry/blob/master/T002_Tools_of_Math_Construction/Part03_Aggregate_Theory.md#suggestions-for-further-study),
and another mentioning the [novel queueing disciplines](https://github.com/constructive-symmetry/constructive-symmetry/blob/master/T002_Tools_of_Math_Construction/Part04_Physics_and_Metaphones.md#physics-and-metaphones)
exhibited by Joe Taylor's WSJT suite of amateur radio protocols.

The unexpected insight I was starting from was "Write it down. Make it real",
which I implicitly understood as "Writing something down [in the cryptoacoustic
transmission medium] makes it real, now write this idea down and make it real."
I was missing the phrase in brackets with only the vaguest conception that I
needed to create it to flesh out my concept. I had a clear understanding of
what I needed to do, but I lacked the language to describe it and was highly
uncertain of any details.

It was immediately clear that I needed to take Dan Friedman's wise advice that
"everytime you write a program to do something, you should write a program to
undo that thing"[^math-education] and adapt it to cryptographic hash functions
in a novel way: what I would eventually come to call "plaintext tags" needed to
be recoverable (i.e. "undoable") from a memory trace of the cryptographic hash
function itself.

Furthermore, as an undergraduate at Case Western Reserve University, I had
written a toy stepping debugger implemented as a continuation-passing
interpreter, based on Friedman, Wand, and Haynes "Essentials of Programming
Languages, 2nd Ed.", which quickly became my mental model for thinking about
the problem.

I had been long aware of the existence and capabilities of Homomorphic
Encryption. I was immediately aware that cryptoacoustics and HE are natural
adversaries, even if I still don't have any deep understanding of HE itself.

And to make all that work, I knew I would need to learn and understand more of
the underlying structure of at least a few cryptographic constructions. Because
I was hoping to keep my cryptographic work compatible with contemporary versions
of WebCrypto, a goal that got yeeted away several months later, I set out to
learn HMAC-SHA256 and relearn PBKDF2 in this new context.

While in the process of understanding my eureka moment, teasing out plausible
solutions, and formulating the goals, I was obsessed about learning a little
bit about loudspeaker design. I didn't think much of it at the time, but as I
finally formulated PHKDF and I was writing acknowledgements I realized I needed
to thank a deceased teacher of mine, Dr. David Doiron, who I had for Optics at
the Indiana Academy for Science, Mathematics, and Humanities at Ball State
University in Indiana.

In retrospect, that class was my introduction to signals and communication
theory. While I was unravelling this puzzle, I basically thought of the
plaintext tag as a signal, with the space of cryptographic state changes
as the transmission medium. I thought of a cryptographic hash function as some
sort of exotic modem capable of guaranteeing the delivery of messages exactly
in the most relevant situations and incapable of making any other guarantees
regarding delivery or non-delivery in other situations.

And yet, my conscious mind was resolutely in denial about the connections
between what I was doing and communications theory. The penny finally dropped
when I had to finally admit to myself why I needed to acknowledge Dr. Doiron.

I chose the name "cryptoacoustics" because sound is the primary means of
communication that humans use to physically communicate with each other. It
also honors my deceased friend Duncan Lowne, who was a DJ interested in
electronic music and computer engineering and was a DPhil student at Oxford
when he passed.

The analogy between cryptographic hash algorithms and communications theory is
not formalized in my mind, but I'm reasonably confident that time will prove
that it can be a reasonably deep and fruitful analogy.

For example, the decibel is a logarithmic scale, but is otherwise dimensionless.
Thus it is sensible and convenient to use decibels to talk about overhead
inflicted on Craig by Alice and Eve when secure tag obfuscation attacks are
carried out via Homomorphic Encryption. For example, a 2x cost multiplier
corresponds to 3 dB, as the base-10 logarithm of 2 is approximately 0.3.

**Cryptoacoustic advantage**, often talked about in decibels, is the cost
multiplier of the most efficient tag obfuscation attack that is secure against
the best reverse engineers on their best days. I have no idea what the
cryptoacoustic advantage of SHA256 or BLOWFISH-EXPAND might be, nor any idea
of how one might even go about answering that unknown.

On the other hand, existing implementations of Homomorphic Encryption do provide
a means of establishing an upper bound on cryptoacoustic advantage; I designed
the G3P under the assumption that it would be straightfoward to achieve an
overhead of "only" 100,000x, also known as 50 dB.  So I assumed the
cryptoacoustic advantage of anything I did was < 50 dB, and that an overhead
of 100x, or 20dB, was sort of at the minimum edge of viability, but that an
overhead of 1000x, or 30dB, was a much more comfortable margin.

Rigorously integrating a diversity of plausible cryptoacoustic constructions
allows me to hedge my bets, increasing the likelihood of achieving a good
cryptoacoustic advantage. Depending on how you count, there are 2 to 4 notably
different tagging constructions in the G3P: seguids and suffixed salts applied
to HMAC-SHA256, and the XOR and BLOWFISH-EXPAND operations that make up the
state transitions in each modified bcrypt key-stretching round.

A topic of research in FHE is the construction of homomorphic transciphers,
which are alternative cryptographic primitives designed to be relatively
efficient when executed inside FHE. Perhaps alternative cryptographic
primitives designed to be particularly _inefficient_ when executed inside any
suitable method of homomorphic encryption should also be pursued as an
anti-problem.

Studying cryptoacoustics as an anti-problem could potentially offer insight
into homomorphic transciphers and/or homomorphic encryption. Password hashing
is something of a best-case scenario when it comes to trying to solve the
Adversarial Literate Programming problem.

While self-documenting domain separation seems a valuable thing to incorporate
into fast key derivation functions, some amount of key stretching seems
neccessary to convincingly tackle some of the more adversarial scenarios.
Primitive hash algorithms with enhanced cryptoacoustic advantage could
potentially reduce or eliminate the need for this key-stretching, thus
extending the applicability of cryptoacoustics.

Though cryptoacoustics and homomorphic encryption are in some sense
anti-problems and thus are natural adversaries, they could possibly be
allies too: it could be very useful if you were able to tag your instances of
homomorphically encrypted algorithms so that anybody who can run your
algorithm must have your contact information.

Fully homomorphic encryption already has high overhead, which would presumably
be greatly amplified by running inside a second layer of FHE. Thus like
password hashing, FHE also seems something of a best-case scenario for the
application of cryptoacoustics.

Because the cryptoacoustic transmission medium is purely mathematical, it
cannot deliver messages itself. Instead, it creates constraints on real-world
patterns of communication. Much like a virus is dependent upon other forms of
life for reproduction, cryptoacoustics is dependent on physical methods of
communication to actually deliver its messages. Thus one could say that
adversarially encoding plaintext messages into algorithms is literally
creating a mind virus.

Because Alice's mind virus cannot possibly be relevant to one's interests unless
one is interested in running Alice's algorithm, and cannot possibly be adversely
relevant to one's interests unless one is doing something nefarious to Alice,
that would seem to fit the _de facto_ usage of "woke".

And, in order to be effective, cryptoacoustics will need to impart something
not unlike an fingerprint or watermark[^unlike-a-watermark] that cannot be
removed or deleted from the result. Thus cryptoacoustics is a transmission
medium of indelible woke mind viruses.

As reporting stolen password hashes back to your organization must be very woke
indeed, cryptoacoustic tags are mind viruses intent on zombifying woke Craigs
into assisting the counterintelligence goals of your organization.

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

[^tag-definition]:
    Though the word "tag" has been used by others to refer to domain separation
    in cryptographic hashing, for the purposes of this document a "tag" is that
    and more: a tag is any kind of cryptographic key where the ability to
    compute the tagged algorithm implies knowledge of the plaintext of the tag
    itself. The phrase "plaintext tag" emphasizes this difference. A tag can be
    secret, but often is public knowledge.

[^truncations-in-the-G3P]:
    The `EchoHeader` and `EchoKey` are truncated at 32 bytes, and the
    `BcryptLongTag` is truncated at `(BcryptRounds + 1) * 4136` bytes.
    Technically an implementation may choose to return an error rather than
    perform any of these truncations.

[^pbkdf2-tagged-hmac]:
    Except for the addition of a counter that is incremented every round, the
    modified PHKDF key-stretching phase would literally be PBKDF2 instantiated
    with a tagged pseudorandom function, namely HMAC(key, msg + DomainTag)`.

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

[^not-blake]:
    Blake3 and the parallel variants of Blake2 are notable exceptions, in that
    the input isn't processed block-by-block from start to end, but rather in a
    more complicated structure that allows for parallelism and for certain
    kinds of incremental updates.

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

[^username-padding]:
     G3P insers some padding in between the username and password parameters
     to ensure that the username parameter can always be fully consumed
     by partial evaluation, and never leaves some leftover prefixed salt
     before the password.

[^seguids]:
    It is sometimes possible to communicate a message via a prefixed salt.
    This is more or less what self-documenting globally unique identifiers
    (seguids) were invented to do. However, relying on public seguids for
    delivering a message to Craig requires more detective work and
    sophistication on Craig's part.

    Moreover, public seguids are not suitable for account separation purposes,
    as that would reveal a list of active accounts. Futhermore, good account
    separation practices can make it easier for Eve to hide prefixed seguids
    from Craig.

    The parameters that the G3P calls a "seguid" are actually HMAC keys, and
    HMAC keys are in effect both prefixed before and suffixed after an input
    message. It is the seguid construct that allows messages to be passed via
    HMAC keys, even though HMAC keys can always be partially evaluated into
    NMAC keys, a.k.a. precomputed HMAC keys. Thus the name was chosen to hint
    at the intended use of the parameter.
 
[^ephemeral-derivations]:
    Do feel free to derive public salts from _ephemeral_ values, though,
    as long as they are quickly forgotten and include a high quality source of
    randomness. You could even apply self-documenting tags to this derivation.

[^bloom-example]:
    Bloom filters may be space-efficient data structures, but they also have
    rather high overhead, especially if you don't end up filling a filter up
    to near it's intended capacity.

    There are formulae for calculating the false positive rate of a given bloom
    filter, and it turns out that this is error rate is largely determined by
    the number of bytes per element that your ideally-loaded bloom filter would
    represent.

    For example, I think a reasonable target error rate is about one in ten
    million, which works out to be somewhat more than 4 bytes per non-existent
    login name. This seems reasonable if there are a relatively small number
    of bloom filters on your public salt server, but as you add more and more
    bloom filters, you may want an error rate of closer to one in billion, which
    works out to somewhat more than 5 bytes per username.

    However, bloom filters are created with a given table size, and cannot
    be resized without access to the plaintext of every element added to it
    thus far. Furthermore, it's convenient and efficient if all your bloom
    filters use the same hash function.

    Thus managing the overhead of bloom filters means picking a large enough
    table size to cut down on the proliferation of bloom filters, but a small
    enough table size that most tables are reasonably well utilized. One could
    even have more than one bloom filter associated with a given key, if that
    key's filter fills up before that key is rotated out of being assigned new
    incoming non-existent usernames.

    Multidimensional bloom filters offer efficient algorithms for searching
    large numbers of bloom filters, which may eventually become important
    for some public salt servers.

    Choosing an optimal size for a bloom filter depends upon the particular
    workloads experienced by a public salt server, which can vary from day
    to day as bots who try to scrape your public salts anyway come and go.

    A reasonable starting point might be to store 125,000 fake usernames in
    a 512 KiB table, achieving a error rate of about one in ten million.

    You might want to keep a long-term log of fake usernames and the keyed hash
    function that was used to generate the fake salt, so you can regenerate
    your bloom filters with different parameters. This backup would not need
    to exist on your public salt servers, reducing the chances of allowing
    an eavesdropper to enumerate your fake accounts.

[^have-i-been-pwned-lookup]:
    Notably, the lookup method to see if a given password is in Have I Been
    Pwned's password breach database does not exhibit this key-stretching
    security property: if an eavesdropper manages to capture the first few
    bytes of a sha256 hash of a plaintext password, and they know that a certain
    severely truncated fast hash is associated with a usefully long but much
    more expensive slow hash, then they can use the fast hash as a password
    prefilter to speed up their attacks on slow hash by orders of magnitude.

[^unreasonable-precautions]:
    You should likely be taking a few unreasonable precautions as well. I
    don't know how difficult solving this problem of on-screen keyboards
    learning passwords really is, as I'm not familiar with mobile development,
    but I do know the same situation with virtual memory is pretty horrendous.

    I don't expect the situation to be good, given that there are so many
    different on-screen keyboards. You should test against the most popular
    reputable keyboards, at least.
  
[^argon2-spec]:
    See [Argon2: the memory-hard function for password hashing and other applications](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf)
    by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich

[^have-i-been-pwned]:
    Or at leat ensure that "Have I Been Pwned" would have in their possession
    sufficiently reliable information to be able to responsibly disclose
    specific password hash security events back to an organization that
    is sufficiently prepared.

[^math-education]:
    I did literally mention in my math education essay that the first thing
    that came to my mind when Dan Friedman told me that was cryptographic
    hashing. To be honest, cryptographic hashing is (to some degree or another)
    a subtext of all three essays, as it was certainly among the things in the
    back of my mind when I was writing them.

[^unlike-a-watermark]:
    Unlike a watermark, a cryptoacoustic tag is kind of sigil that cannot be
    read directly from a password hash, but rather represents a belief about
    its origin, thus preserving plausible deniability. This belief must be
    correct for that password hash to be both genuine and crackable.

    Also, digital watermarks traditionally seek to covertly embed a signal into
    noise-tolerant data such as documents, pictures, video, and audio, whereas
    cryptoacoustics seeks to overtly embed a signal into the noise-intolerant
    medium of cryptographic state changes.

[^domain-tag-length]:
    This assumes a short domain tag of less than 20 bytes. For example, a
    quarter of sha256 blocks didn't accrue before completion for domain
    tags 20-82 bytes long, etc.
