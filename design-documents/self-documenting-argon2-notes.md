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
    block, considered as an array of 16 words, each 8 bytes long. `j` is an index that gets
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

## Notes on Argon2's compression function

1.  Both argon2 and blake2 uses something that is close to (or the same as, from a
    point of view?) the Davies-Meyer construction to build a one-way compression function.
    The Davies-Meyer construction is used to turn block ciphers into one-way compression
    functions.

    This raises the question, are these mixing functions invertible?

2.  In blake2's case, the answer is "yes", unless you don't know the message that was mixed
    into the state.  (Very likely not reversable, if you don't know the message. But who
    would know the result of a mixing function without also knowing the message that was
    just mixed? The emphasis the G3P puts on being able to transfer partial key-stretching
    computations cannot be a sensible answer, because then it would be better to complete the
    few inexpensive operations remaining in the Davies-Meyer construction...)

    Also, blake2's message schedule SIGMA is a Latin rectangle. There are probably some
    deeper properties that can be sussed out.

3.  The invertibility of argon2's mixing function depends on how many solutions there are to
    `z = x + y + (2 * x_L * y_L)` given `y` and `z`, and how effiencently you can find `x`.
    Here `x`, `y`, and `z` are 64 bit integers and x_L and y_L are the respective least
    significant 32 bits.

    Rearranging, we find `x + (2 * y_L) x_L = z - y`. Note that `x = 2^32 * x_R + x_L`.
    Rearranging again, `2^32 * x_R + (2 * y_L + 1) * x_L = x - y`

    Because `(2 * y_L + 1)` is odd, the least signficant bit of `x_L` must be equal to the
    least signficant bit of `z - y`.  Let `b` be this bit, and `a` be `x_L` with this bit
    truncated.  Then `x_L = 2*a + b`, and then calculate
    `(2 * y_L + 1) * (2*a + b) = 4 * y_L * a + 2 * y_L * b + 2*a + b`

    Substituting and rearranging
    `2^32 * x_R +  4 * y_L * a + 2*a = x - y + 2 * y_L * b - b`

    As nothing on the left can contibute anything to the last two bits of the right
    except for `2*a`, we can compute the least signficant bit of `a`.

    Repeating this process, it should be possible to calculate `x_L` bit by bit, and then
    solve for `x_R`. There may be a faster and more elegant solution that calculates multiple
    bits of `x_L` using a handful of operations, but this is efficient enough for my purposes.

4.  Thus, both mixing functions are in effect some kind of block cipher. Argon2 uses the
    Davies-Meyer construction to provide non-invertibility, whereas Blake2 uses a modified
    Davies-Meyer construction.

    I don't think Blake2 can be viewed as an instance of Davies-Meyer proper, because its
    compression function doesn't allow the direct computation of fixpoints.

    In retrospect, I'm not at all surprised that the mixing functions are invertible; after
    all permutations makes it easy to argue that you preserve information entropy, and
    also makes it easy to demonstrate that any difference in inputs cause the resulting
    states to diverge from each other.

    This in turn gives me a great deal more confidence in my proposed design, in particular
    I understand much better why varying the personalization tag causes divergence in
    the argon state, and why it doesn't change the overall probability distribution
    on average.

    Though perhaps I should try to spend some time learning differential and linear
    cryptanalysis, I'm also feeling much more confident that these issues are basically
    already covered in existing analyses of Blake2 and Argon2.

5.  This does leave the issue of a good message schedule within a single application of
    the compression function `G`. I do intend to use a single 128-byte personalization tag
    block throughout all applications of the round function `P`, though this will be
    rotated between applications of `G` so that longer tags can be processed during
    key-stretching.

    Reusing Blake2's `SIGMA` is probably a reasonable-ish thing to do, however, due to the
    change in how the round function `P` is used to construct Blake2's compression function
    versus Argon2's compression function, it's well worth doing some Monte-Carlo simulations
    on the result.

    There's a reasonable chance we could use this to compare and contrast the efficacy of
    various message schedules. Perhaps a likely-better message schedule could be found.
    If this modified schedule simply added a few rows onto `SIGMA`, then the number of
    constants needed by an argon2 implementation would then be somewhat less.

## Notes on the proposed mixing function

Define

```
MIXL((a,b,c,d),x) = do
   a := a + b + (2 * a_L * b_L) + x
   d := (d ^ a) >>> 32
   c := c + d + (2 * c_L * d_L)
   b := (b ^ c) >>> 24
```

and

```
MIXR((a,b,c,d),y) = do
   a := a + b + (2 * a_L * b_L) + y
   d := (d ^ a) >>> 16
   c := c + d + (2 * c_L * d_L)
   b := (b ^ c) >>> 63
```

**Theorem 1** Given any starting state `S = (a,b,c,d)`, and any two distinct 64-bit words
`x ≠ y`, then `MIXL(S,x) ≠ MIXL(S,y)`, and `MIXR(S,x) ≠ MIXR(S,y)`. In fact, each
sub-component of the resulting states will be distinct.

**Proof:** Every step in each mixing function is invertible. Because we start out at `t = 0`
with identical versions of `a`, and identical versions of `b`, after one step the `a` that
results from `x` will be distinct from the `a` that results from `y`. This reasoning carries
through the remaining steps: since at `t = 1` both versions of `d` are still the same, but
the versions of `a` are guaranteed to be different, then at `t = 2` the `d` that results from
`x` must be different than the `d` that results from `y`, and so on.

**Theorem 2** Given any 64-bit word `x` and any two distinct starting states `S ≠ T`, then
  `MIXL(S,x) ≠ MIXL(T,x)`, and `MIXR(S,x) ≠ MIXR(T,x)`.

The proof is identical in overall structure as the one above, it's just that which component
is guaranteed to be the same, and which one is guaranteed to be different, is swapped.

A consequence of these first two thereoms is that either half of this modified mixing
function forms a Latin rectangle with `2^256` columns and `2^64` rows.

**Theorem 3** Choose any final state `T`. Then given any starting state `S` and key `x`
that results in `MIXL(S,x)=T`, the last three components of `S` are determined without any
reference to `x`. An analogous statement is true for `MIXR`.

The proof can be completed by simply reversing the last three steps of either mixing function.

Next, define:

```
MIX(S,x) = do
  MIXL(S,x_0)
  MIXR(S,x_1)
```

**Theorem 4** Given any starting state `S`, and any two distinct 128-bit messages `x ≠ y`,
  then `MIX(S, x) ≠ MIX(S, y)`.

**Proof:** As `x ≠ y`, then either `x_0 ≠ y_0`, `x_1 ≠ y_1`, or both. If only one is true,
the theorem follows immediately as a consequence of the previous theorems. The trickier
case is where both are true.

In this case, every component of the vectors `MIXL(S,x_0) = S_x` must be distinct from the
corresponding component of `MIXL(S,y_0) = S_y`. As the last three components must differ,
we cannot choose any combination of `x_1` and `y_1` to make `MIXR(S_x,x_1)` equal to
`MIXR(S_y,y_1)`.

At this step, it's fairly obvious that we lose the property that every component of the
resulting state vectors must differ: in fact given any `x_1`, it is easy to pick an `y_1`
that makes any single chosen component of the resulting state vector the same.

I believe it should be fairly straightforward to prove that the resulting state vectors can
agree on at most one component, and that at least three components will differ.

Theorem 4 means our full mixing function also forms a Latin rectangle, one with `2^256`
columns and `2^128` rows.

**Theorem 5** If first you pick a 64-bit word `x`, and then choose an initial state vector
over any probability distribution that is uniform on either the first component `a` or the
last component `d`, then the resulting probability distribution over `MIXL(S,x)` does not
depend upon the choice of `x`.

This follows from the group structure of `+` on 64-bit words. Since `a` and/or `d` have
been chosen uniformly at random, the distribution over `a + d + (a_L * d_L)` is uniform, and
thus the distribution `a + d + (a_L * d_L) + x` is uniform even if `x` is chosen by an
adversary.

Of course, if an adversary is allowed to peek at `a` and `d` before choosing `x`, then it is
trivial to skew the new distribution of `a` in any way desired, say by always ensuring the
result is zero.

**Discussion**

These theorems relate to the mixing's function ability to conserve entropy by not being a
source of collisions and by ensuring that, given different keys, the evolution of intermediate
states have a natural tendancy to diverge from each other. Any time there is such a collision,
the next state is *guaranteed* to be different, which then quickly decays into a probable
difference.

The group structure of `+` on 64-bit words also implies that even if a reverse engineer,
cannot directly observe the keys being fed into the mixing function due to some magical
obfuscation technique, the reverse engineer can still infer the keys being fed into the
mixing function by observing the before-and-after states of the
`a := a + d + (2 * a_L * d_L) + key` transitions, meaning that the magical obfuscation
techniques must also extend deeply into the modified argon2 algorithm.

This property is the real reason why we are making this effort: after all, argon2 already
supports adequate levels of domain separation, but its cryptoacoustic properties are poor.

The last theorem in particular is related to the notion that there is no such thing as
a "bad" key, as long as the key was chosenly honestly without knowledge of the other inputs.
However, the way that the mixing function is extended to blocks likely makes it much less
secure blake2b when keys are chosen adversarially with knowledge of other parameters.

For this reason, the entire personalization tag is committed to in the first call to blake2b.
Thus once the mixing function is applied, its key cannot be changed without recalculating the
state vector it is being applied to. Thus this approach ties the assumptions of Theorem 5
to the cryptographic properties of the blake2b hash function.

## Argon2's round function `P`

The only difference between argon2 and blake2b's round function is that the mixing function
adds in a multiplicative term to every other step, i.e. those steps that consist of addition.

The original argon2 does not support mixing a key into this stage, but blake2b does. Thus I'm
not too worried that adding back blake2b's features to the existing mixing function will
impact the internal structure of the round function too negatively.

However, the respective round functions are applied very differently: blake2b applies its
round function 12 times in an iterative fashion on a state of 128 bytes, whereas argon2 uses a
wide-block construction that applies its round function 16 times, but to transform a block of
1024 bytes. From starting state to ending state, the overall depth of the applications of `P`
is 12 in blake2b versus 2 in argon2.

I am somewhat concerned that the current proposal to blend blake2b's mixing function into
argon2 may not be a good match for the resulting compression function, due to these
differences. Better understanding some of the properties of the round function may be
important to understanding the impacts to th e compression function.

In particular, at least locally, this difference should make it relatively easy to achieve
some highly non-uniform behavior in the modified argon2 round function if one is freed of the
commitment to pick the key without knowledge of the current state, as is currently enforced
by blake2b in the proposed construction.

It should be possible to greatly reduce this non-uniformity by choosing a plausible-looking
block design specifically for applying tags to argon2's compression function, and only
processing 16, 32, or 64 bytes per application instead of 128. This would also make blake2b's
message schedule `SIGMA` irrelevant.

Processing 16 bytes of tag per application of the compression function would be safest, at
least from this (possibly limited) perspective. And at OWASP recommended minimums involve
plenty of applications of the compression function, so there is not any need to process more
than that to achieve a good result, unlike blake2b's need to efficiently compute the digests
of very long messages.

Regarding message schedule, I am tacitly assuming that we want to use differently-keyed
mixing functions at every stage of the compression function. There's only one reduced Latin
rectangle of two elements and more than one row, and that is the Latin Square `[[1 0][0 1]]`.
However, in this case we could potentially use the alternative presentation `[[0 1][1 0]]`,
and also possibly subtract some of the keys. Alternatively, we might choose to apply the same
8-byte key block to both arguments of the mixing function in some cases.

Between swapping the order of the sub-keys, and whether to add or subtract each of the
two sub-keys, that provides eight possibilities for keying the mixing function from two
64-bit words. As the round function involves eight applications of the mixing function,
maybe this is a good match?

Hmm, adding the bitwise complement seems like it should be somewhat better than subtracting.
This is equivalent to subtracting the `(key + 1)` instead of subtracting `key`, but the
complement does mean that the two variants have different effects for every key, whereas
subtracting means that +0 has the same effect as -0, likewise with +2^63 and -2^63.
This does make "compatibility" with old argon2 a bit more complicated, but I feel like
its time to yeet that design goal. I think it did help focus my attention at first, but
I also feel like it's outlived it's usefulness.

Honestly I'm leaning towards clear differentiation. I think I could do a (slightly) "better"
job with the variable length hash function, and perhaps also with the initial call. But
I'm not sure I care enough to adopt all of the corresponding features of G3Pb2.

Certain block designs should make it harder than others for anybody to achieve non-uniform
behavior from the compression function if they are allowed to look at the state before picking
the keys. The fact that only 16 bytes of tag are processed per application of the compression
function greatly reduces the degrees of freedom that adversarial use has to achieve
non-uniform behaviors. This means the block design wouldn't necessarily need to be as close
to optimal to be effective, compared to a design that processed 32 bytes or more
of tag per application of the compression function.

This block design should likely be tailored so that it admits particularly efficient
vectorized implementations.

However, these concerns are also well outside the intended use case of these modifications.
Usage conventions dictate that the personalization tag should be chosen without knowledge of
the user's password, and most typically would be a deployment-wide constant. Moreover,
blake2b is used to enforce that one cannot look at the state vector of the mixing function
and then select the key being applied to it.

# Prototype implementation strategy:

1.  Extend Haskell's FFI bindings to include the Ctx datatype. It's not too bad to simply
    construct this data structure in Haskell. Moreover, the key and associated data fields
    aren't otherwise accessible via the C api. (This should be contributed back to the
    original argon2 binding, and doing this first should make this a bit easier.)

2.  Extend the test suite to cover the newly-supported parameters.

3.  Add an `info` parameter to the context structure.

    *   consider removing the output parameter from the context structure, as it conflicts
        with const-correctness

4.  If the `info` parameter is non-empty, encode it onto the end of argon2's initial
    call to blake2b as a length-prefixed parameter.

    *   To achieve clear differentiation, maybe consider setting blake2b's salt or
        personalization argument to `argon36`.  Maybe reconsider a deeper redesign of
        the initial parameter block.

    *   With blake2b, there seems to be some benefit to cyclically extending a tag to cover
        an entire block, whereas the benefit of repeating a plaintext tag within a single
        SHA256 block seems more suspect.

    *   What if we only encoded it on the end of the variable-length hash function?  Maybe.

5.  If the `info` parameter is non-empty, encode 64 bytes of it at a time into the
    variable-length hash function that uses blake2b to generate the first two blocks.

    *   Should the cyclic extension be carried over across blocks, or should you just start
        over at the beginning of the tag on the next block after the cyclic extension is used?

        It shouldn't really matter that much one way or the other, but we do have to commit
        to a single choice. The former is a little more elegant and doesn't favor one part
        of the personalization tag over another. The latter should be a little bit simpler to
        implement in a particularly efficient and performant way, especially with respect to
        memory-alignment issues. I'm leaning towards the latter choice.

    *   Also, the very first call to blake2b in this case has a message length of 68 bytes
        instead of the usual 64 bytes.  Do we cut four bytes off the first block of the
        personalization tag, repeat the entire personalization tag, or do something else?

    *   Since argon2's variable-length hash function is also used to generate the final
        output, it would probably be a good idea to include the entire personalization tag in
        the first call that it makes to blake2b. This choice also implies that it wouldn't be
        strictly necessary to include the personalization tag in the initial parameter
        call to blake2b.

6.  Modify the compression function to mix the `info` tag in the key-stretching phase.

    *   It could be very useful to take the time to write commentary on `blamka-round*.h`

    *   Disable all vectorized implementations for now.

    *   Cyclically extend the `info` tag so that its length is a multiple of 16 bytes

    *   break up into blocks, then cycle those blocks.

    *   How should these blocks be distributed across applications to the round function?

    *   How should the round function break apart it's inputs for distribution to the
        mixing function?  (It shouldn't break anything apart, but repeat the same 16 bytes
        everywhere.)

    *   How should these blocks be distributed across applications to the mixing function?
        (Again, repeat the same 16 bytes everywhere)

7.  Extend the test suite to cover the `info` parameter.

# Production Ready TODO:

1.  Develop a test plan for all vectorized implementations

2.  Update each vectorized implementation

3.  Add new vectorized implementations, especially for ARM (Raspberry Pi, Phones)

    *   This could be useful, but also not a priority until we are seriously contemplating
        running argon2 on client devices, or have a project intended to be deployed on a
        Raspberry Pi server.