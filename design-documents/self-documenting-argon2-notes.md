# Towards a self-documenting variant of Argon2

**Goal:** mix a plaintext tag into the argon2 key-stretching phase safely.

The biggest key to success here is to not introduce major weaknesses into the conventional
cryptographic properties of argon2.  Though the intended use case is that the plaintext
tag is chosen without any knowledge of other input parameters, we should endeavor to
preserve conventional cryptographic properties of hash functions such as collision and
preimage resistance even when the plaintext tag can be chosen in response to the exact state
it acts on.

**Subgoal:** minimize the modifications to the overall structure of argon2

This design needs to make it as easy as possible to understand why the modifications made to
argon2 are low-risk, high-reward changes.

I feel like both PHKDF and G3Pb2's modifications to bcrypt suceeded quite well in this
regard.  There are admittedly much more extensive changes to bcrypt than to PBKDF2.

**Subgoal:** minimize the run-time impacts of modifying argon2

A password hash function seeks to minimize the latency of a single computation, but maximize
the cost of parallelizing a large number of hash computations. Thus determining which
key-stretching computations are the most practical is a very complex topic which requires
a deep understanding of the design of hardware. Moreover, one needs to understand hardware
design both in general, and understand the specific design of existing hardware, especially
GPUs.

By making the modifications as small as possible, the low-level run-time performance
characteristics of our modified version should be very similar to the original, thus
benefitting from other people's expertise in this area.

**Subgoal:** try to optimize the plausible cryptoacoustic advantage

I don't really know how to do this, but sometimes heuristics does give us a way of saying
that one construction is very likely better or worse than the other.

The approach I followed in the G3P was basically adapting a repetition code from the theory
of error correction codes. I wanted it to be impossible to ever compute very much without
referring to the plaintext of some tag or another.

Perhaps the biggest illustration of this is the change in the G3P's bcrypt integration
from version 1 to version 2.

I've also tacitly assumed that cryptoacoustic repetitions of the exact same data are not
terribly useful without intervening non-linear operation.

**Subgoal?** Modified argon2 should be equivalent to the original when the added parameters are the empty string.

I'm not sure if this subgoal is particularly "worthy", but it might be worth pursuing.
However, less-useful goals can be refined into more-useful goals over time, in ways that
wouldn't have happened if you hadn't started out with these types of less-useful goals.

**Non-goal:** incremental key-stretching

Argon2 already supports incremental key stretching, but I don't think that's very relevant.
Requiring large amounts of memory makes the minimal continuation quite large, making it
relatively impractical to outsource a partial argon2 key-stretching computation to another
device. Parallelism is also antagonistic to transfers of in-progress computations.

Of course, argon2 need not be the only key-stretching mechanism used. in the context
of an appropriate deployment, it can be quite practical to outsource the *entire* argon2
computation to another semi-trusted device.

Thus the cost/benefit ratio of transferring argon2 mid-computation is poor, even though I
totally understand why somebody might want to outsource the _entire_ argon2 key-stretching
computation to a faster and more capable device. However, it's not too difficult to
design a deployment that supports this, without needing any kind of "native" support from
the underlying hash function.

Given _any_ hash function (such as argon2 or bcrypt) that incrementally overwrites a large
block of memory, it is difficult to understand how one could prevent a cracker from
avoiding most of the last overwrite when cracking an intermediate state. In effect, this
overwrite is "lost" when a partial computation is transferrred to a cracker's device.

This lost overwrite means that the difference between the work required to create a
continuation versus the work required to make a single cracking attempt against that
continuation is often impractically large when dealing with memory-hard hash functions.

In the case of argon2, the common deployment practice today is to use a very small number of
rounds, using the memory-cost parameter to largely control costs in both time and space. With
`t = 3`, there are three complete overwritings of memory. Losing an overwrite means it's
pointless to transfer a key-stretching computation before one has made it a substantial
way past `t = 1`, at which point you'd be losing more than half of your work. At `t = 2`,
you'd be two-thirds of the way through the key-stretching computation, and you'd still lose
nearly half of your key-stretching work.

It should be noted that parallelism is also antagonistic to the goal of being able to
usefully transfer a partial key-stretching computation between devices.

Password hashing is about finding a favorable tradeoff between low latency of a single
computation versus a high cost of parallelization across many computations. For this reason,
enabling parallelism in a single computation can at least in theory benefit legitimate users
while being of little to no benefit to password crackers.

However, if you care about transferring intermediate states between devices, parallelism has
some tendancy to lead to situations where it can be significantly more expensive to compute
a continuation than it is to make a single cracking attempt on it. Perhaps this subtlety
is avoidable to some degree, but I don't think argon2 does this.

Thus, while I think incremental key-stretching is a _wonderful_ idea for a password prehash
function, and I think it's a good idea for all password hash functions, incremental key
stretching seems much less directly relevant to memory-hard, parallelizable hash functions.

# Discussion

Now that I'm starting to understand the overall structure of argon2, a few comments:

1.  There is very little in the way of established parameter input space (often filled with
    zeros) that could be turned into tagging space.

    Modifying PBKDF2 was particularly easy because of the existence of HKDF, and the fact
    that there are no changes to the overall algorithmic structure if PBKDF2 is instantiated
    with `HMAC(key, msg + DomainTag)` if the domain tag is sufficiently short.

    Bcrypt was a little harder, because the parameter space for `BLOWFISH-EXPAND` was less
    obvious, but still used in the initial half-round, giving us a construction that has
    been well scrutinized.

    Argon2 is going to be significantly harder, because there's nothing comparable already
    there. Sure, we could easily add tags to the initialization of the first two blocks,
    essentially duplicating the changes introduced by PHKDF, but this doesn't last very deep
    into the key-stretching phase.

    Moreover, the conventional input parameters to argon2's compression function `G` are
    fully consumed by the intermediate blocks `B_i`

2.  Modifying argon2's compression function `G` into a personalized compression function `G'`
    that accepts a plaintext tag seems the [only plausible starting point](https://www.password-hashing.net/argon2-specs.pdf#subsection.3.2)
    for getting plaintext tags into the key-stretching phase.

    Adapting the approach that the G3Pb2 takes to modifying bcrypt, xor-ing the tag into the
    [input or output of argon2's compression function `G`](https://www.password-hashing.net/argon2-specs.pdf#subsection.3.4)
    seems like the a promising approach worth considering.

    Because argon2 uses non-invertible compression functions, and not the Blowfish block
    cipher like bcrypt, it seems rather unlikely that these modifications can obtain any
    kind of algebraic structure, like `BLOWFISH-EXPAND`'s quasigroup.

    This shouldn't be a problem in practice, but the quasigroup structure does make it
    "nice" to demonstrate that our bcrypt personalization tags are strongly non-colliding.
    This quasigroup also implies that by watching the state transitions with a memory
    debugger, the ability to decode a tag is much more persistent across time.

    It seems promising to consider xoring (part of) the plaintext tag into the `Q` values
    that are intermediate values of the `G` compression function.

    Perhaps every application of the personalized compression function `G'` would process
    64-128 bytes of plaintext tag, xoring that single part of the tag into each and every
    input to Blake2b's round compression function `P`.

    Even if one is allowed to choose the personalization tag after looking at the input
    to the compression function, it should be quite difficult to pull major shenanigans.
    The fact that you can't change the personalization tags between applications of the
    round function forms a 16x block design, and prevents control over the entire input
    space. Furthermore, if the tag length is limited to less 128 bytes, one would never
    have complete control over the input to any single function.

    As I feel like a self-documenting password hash function should support plaintext tags
    of at least a kilobyte in length, one would have to use different parts of this tag in
    different places. It'd probably be a good idea to introduce a secondary block structure
    that repeats part of the personalization tag across block compressions, and/or a local
    committment scheme that prevents looking at the inputs to a compression function and
    then picking the personalization tag.

3.  These modifications to argon2's compression function would probably be okay-ish, but
    there may well be significantly better and/or more principled solutions.

    While the first solution I proposed above is basically trying to apply the techniques
    I used to modify bcrypt to argon2. However, the quasigroup structure of `BLOWFISH-EXPAND`
    also gave me much more confidence that no individual bcrypt state is particularly
    "special", and thus allowing most of the bcrypt state to be adversarially overwritten
    by the first `XOR` operation in each round to any arbitrary value (such as all zeros)
    without too many worries about affecting the ultimate result in a nefarious way.

    Because argon2 uses a non-invertable compression function, there's no quasigroup, and
    thus the mathematical reasoning that argues that my first proposal doesn't completely
    break standard cryptographic properties if the personalization tag is misused, differ
    substantially between bcrypt and argon2.

    Of particular note is the fact that argon2's compression function uses a very minor
    variant of blake2b's round function and mixing function.

    Blake2b's compression function mixes the plaintext of a message block into the state a
    total of 12 times, once for each application of blake2b's round function. The
    modification of argon2's compression function proposed above mixes the plaintext of the
    personalization tag a total of 16 times.

    The only difference between argon2's mixing function and blake2b's mixing function is
    how the "inputs" are mixed in. However, argon2 already uses all of the the standard
    inputs to this mixing function.

    Another possibility might be to replace those inputs with the personalization tag,
    however removing a multiplication or two per mixing function application is a pretty
    significant run-time change.

    Thus maybe the mixing function would be better modified to be a blend of [argon2](https://www.password-hashing.net/argon2-specs.pdf#appendix.A)
    and [blake2b](https://datatracker.ietf.org/doc/html/rfc7693.html#section-3.1)'s mixing
    functions along with blake2b's message schedule [SIGMA](https://datatracker.ietf.org/doc/html/rfc7693.html#section-2.7).

    ```
    MIX(a,b,c,d,m,i,j) = do
       a := a + b + (2 * a_L * b_L) + m[SIGMA[i % 10][2*j]]
       d := (d ^ a) >>> 32
       c := c + d + (2 * c_L * d_L)
       b := (b ^ c) >>> 24
       a := a + b + (2 * a_L * b_L) + m[SIGMA[i % 10][2*j + 1]]
       d := (d ^ a) >>> 16
       c := c + d + (2 * c_L * d_L)
       b := (b ^ c) >>> 63
    ```

    Here, `a`, `b`, `c`, and `d` are 8-byte unsigned machine words.  `m` is a 128-byte message
q    block, considered as an array of 16 words, each 8 bytes long. `j` is an index that gets
    filled in by the blake2 round function `P`. Each application of `P` calls `MIX` exactly
    once for each `j ∈ [0..7]`. The compression function `G` then calls the round function
    `P` exactly once for each `i ∈ [0..15]`.

    This strikes me as being a much more principled approach that is far more likely to
    preserve existing analyses of `argon2` and `blake2b`.

    However, some analyses will likely need to be generalized. For example, the assumption
    that 'P' is [4-generalized-birthday-resistant](https://www.password-hashing.net/argon2-specs.pdf#subsection.5.3)
    may not be the most relevant assumption to make, especially when considering misuse
    of the personalization tag by allowing it to be chosen in response to knowing the precise
    argon2 state it is being applied to.  Here, blake2b's analyses are more likely to be
    relevant.

    This does leave open the issue of how to compute the message blocks from the
    personalization tag. Of course, we should use some sort of cyclic extension of the
    personalization tag, as the number of message blocks processed is determined
    by the cost parameters, not the length of the personalization tag.

    When the end is reached, the remainder of the message block should be filled with
    the beginning of the personalization tag, much like PHKDF does with the `DomainTag`,
    so that every application of the mixing function processes a significant quantity of
    interesting, potentially actionable information.

    Subsequent blocks could either start over at the beginning of the personalization tag,
    or possibly do something more like the G3P's modified bcrypt, and continue at the
    point that was reached after the previous block, forming a continuous cyclic extension.

    It probably doesn't much matter in terms of overall cryptographic properties.
    In terms of implementation, starting over at the beginning might be a bit simpler.

3.  Now time for skepticism: this type of change is much lower-level and much riskier than
    the changes made to either PBKDF2 or bcrypt. Blake2b's compression function uses the
    round function in an iterative way, whereas argon2 uses a similar round function in a
    non-iterative, wide-block mode of operation.

    blake2's [design document](https://www.blake2.net/blake2.pdf) doesn't discuss the design
    of the `SIGMA` message schedule, and it's quite possible that a particularly good message
    schedule in one context doesn't translate to a good message schedule in the other.

    argon2's design document discusses its [compression function](https://www.password-hashing.net/argon2-specs.pdf#subsection.6.3),
    mentioning that adversaries never have any direct control over any of its inputs.

    This story is more complicated with these proposed modifications: if used as intended,
    the personalization tag is never under the control of an adversary, and is never chosen
    with knowledge of the password it is being applied to. Furthermore, even if these usage
    conventions are violated, the personalization tag is included in argon2's initial call
    to blake2b and is mixed into generation of the first two argon2 blocks. This local
    commitment scheme means that changing the part of the tag provided to a compression
    function also changes all the other arguments to `G` that the tag is being applied to.

    From this perspective, the most important properties that a personalization tag should
    preserve is that there isn't any way to short-cut the computation, that differing tags
    creates pressure that forces the evolution of the argon2 states to diverge, and that no
    tag significantly changes the overall distribution on average.

    The proposed changes are likely to achieve these three critical objectives. Even so, we
    should strongly prefer a design where direct control over the part of the tag being
    fed into each and every application of the compression function `G` doesn't allow an
    adversary to pull any major shenanigans, beyond the unavoidable possibility of trying
    `N` different tags, which (on average) allows control over `log N` bits even in an
    idealized random oracle model.

    Basically, we should prefer the safety property to be local to the compression function
    instead of depending upon the larger context of having to commit to the tag before the
    other arguments to `G` can be examined, and not allowing an adversary to specify a
    personalization tag. We should prefer this even though we should also make use of local
    commitments and usage conventions as additional layers of safety.

    This safety property is much less plausible with these changes to argon2 than it is with
    the changes to PBKDF2 or bcrypt. It would thus be strongly preferable to apply
    differential and linear cryptanalyses to the modified compression function so that
    these changes can be evaluated and likely improved upon.