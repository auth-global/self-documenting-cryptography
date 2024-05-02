{-# LANGUAGE OverloadedStrings, ViewPatterns #-}

{- |

The [Global Password Prehash Protocol (G3P)](https://github.com/auth-global/self-documenting-cryptography/blob/prerelease/design-documents/g3p.md)
is a slow, attribution-armored password hash and key derivation function. It
supports [self-documenting deployments](https://www.cut-the-knot.org/Curriculum/Algebra/SelfDescriptive.shtml)
whose password hashes are /traceable/ or /useless/ after they have been /stolen/.
This secondary security goal seeks to use [/cryptoacoustics/](https://github.com/auth-global/self-documenting-cryptography/)
to provide [/embedded attributions/](https://joeyh.name/blog/entry/attribution_armored_code/)
that are as difficult as possible for an adversarial implementation to remove.

The G3P revisits the role of cryptographic salt, splitting the salt into the
cartesian product of the /seguid/, /username/, and /tag/ parameters. Any
parameter with "tag" as part of the name is an embedded attribution to anybody
providing the inputs to the /username/ or /password/ parameters. Tags are
themselves directly self-documenting embedded attributions, in the sense that
one cannot easily or efficiently replace the tag with anything else without
losing the ability to compute the correct hash function.

The /seguid/ corresponds to the key used for every call to HMAC-SHA256, right up
until final output expansion. In this way the G3P mimicks the construction of
HKDF, with the seguid corresponding to HKDF's /salt/ parameter. The G3P also
mimicks PBKDF2 used in an alternate mode of operation.

The seguid can be trivially replaced with a /precomputed HMAC key/, thus the
seguid is not a direct tag. However this precomputed key is a cryptographic
hash of the seguid, and for this reason the seguid is capable of serving as
an /indirect/ tag, which the Seguid Protocol is designed to utilize via
Self-Documenting Globally Unique Identifiers (seguids).

It is strongly recommend a deployment identify itself with a single 64-byte
(512-bit) seguid, and the deployment's choice of plaintext messages to be
delivered via tags. These salts can be constants across the entire deployment,
as the username is intended to be used as the final bit of salt within a
deployment.

In a traditional password hash function, the salt is a random bytestring
typically between 8 and 32 bytes long. One of its primary purposes is to
identifiy a unique hash function so that one cannot attempt to crack multiple
password hashes with a single key-stretching computation. Oftentimes this
is implemented by storing a salt per user.

However, in the context of a client-side prehash, storing a salt per user has
the potential to leak whether or not an account exists, or if a password has
changed. The G3P has the option to eliminate these complications, because
it is safe to use a plain username as the salt, in addition to the
deployment-identifying seguid and tags.

On the other hand, if one is aware of the potential issues surrounding the
implementation of a random per-user salt in a client-side hashing context, and
is willing to mitigate or live with them, then there are potential advantages
to using a random salt as the input to the G3P's @username@ parameter instead.

All parameter names are suggestive, not prescriptive. Usage is ultimately
defined by the deployment.

When somebody is guessing a username, they must also know (or guess) the
password. However, the username need not be revealed to somebody who is guessing
the password, as the raw username can always be replaced by a precomputed hash.
If this intentional feature is not desired, a deployment might choose to swap
the username and password, as these inputs are otherwise functionally identical.

The usage and interpretation(s) of any given parameter is always defined by the
deployment, and is never defined by offical G3P documentation or specifications.

The G3P always has room for more salt. It doesn't really make sense to inject
more than 256 bits of entropy into the username parameter, because when the G3P
is partially applied to a constant username, the raw input can be replaced with
a SHA256 state. This is not true of any of the tags: it doesn't matter how long
it is, the whole tag must be present for the hash computation to be correct.

Every parameter with the word _tag_ in its name exhibits this property.
Theoretically, one could specify a G3P-based hash function that requires
terabytes of salt to be hashed billions of times over. However it is unclear
what purpose such an impractical specification might serve.

This initial variant of the G3P employs a combination of PHKDF and bcrypt.
PHKDF serves as the primary cryptoacoustic component, and bcrypt serves as the
primary key-stretching component of the G3P. Both are secondarily used in the
alternate role as well, with the PHKDF adding a tiny bit of key stretching and
bcrypt providing significant additional cryptoacoustic plaintext repetitions.

1.  Every bit of every parameter matters. Every boundary between parameters
    matters. The presence and position of every null byte and every empty
    string matters. There aren't supposed to be any trivial collisions, the
    only exception being null-byte extension collisions on the seguid, which
    serves as an HMAC-SHA256 key.

2.  Except for the tweaks, any change to any parameter requires restarting the
    PHKDF key-stretching computation from somewhere in the very first call to
    HMAC.

3.  All input arguments are hardened against length-related timing side
    channels in various different ways.

    At one extreme, the username, password, and long tag have the most
    aggressive length hardening in the conventional sense, exhibiting no timing
    side channels except on multi-kilobyte inputs, after which the timing
    impacts are minimized.

    At another extreme, the domain tag exhibits severe yet predictable
    timing side channels transitioning from 19 to 20 bytes and every 64
    bytes thereafter.  However, the domain tag is otherwise free of
    timing-based side channels, so it too is hardened in its own way.

The design I converged upon employs fairly complicated data encoding
procedures. Unfortunately, this provides a fair bit of surface area for subtly
wrong implementations that work most of the time, but will return garbage on
certain lengths of inputs. I hope that this will eventually be remediated with
a more comprehensive suite of test vectors.

Note that the username, password, long-tag, and credentials vector are all
/horn-loaded inputs/ in the sense that they are consumed a constant number of
times near the beginning of the hashing protocol, and after each PHKDF
round, the hash with the least key-stretching applied is discarded.

This implies that particularly paranoid password-handling implementations can
eliminate the password from memory even before key-stretching is complete.
Additionally, assuming all the sensitive secrets are contained in horn-loaded
parameters, this implies the key-stretching computation can be relocated at
nearly any time with full credit for any key-stretching already performed.

One of the associated costs is that collisions on horn-loaded inputs can be
found over the entire G3P by "only" colliding the first call to HMAC-SHA256,
/G3Pb2 alfa/. If it were trivial to produce collisions on HMAC-SHA256, this
would very likely make collisions on the horn-loaded inputs trivial. However
such an attack would be unlikely to be able to immediately produce collisions
that vary any of the other inputs. This is because all the other inputs are
repeated elsewhere in the protocol, thus colliding /G3Pb2 alfa/ isn't enough
to collide the final output of the G3P.

This "cost" seems acceptable in the context of password-based authentication
flows, where collision resistance and second preimage resistance are not
directly relevant. What is crucially important is preimage resistance and
maximizing the cost of parallelizing multiple key-stretching computations while
minimizing the latency of a single key-stretching computation.

-}

module Crypto.G3P.V2
  ( G3PSalt(..)
  , G3PInputs(..)
  , G3PSeedInputs(..)
  , g3pHash
  , G3PSpark()
  , g3pSpark_init
  , g3pSpark_toSeed
  , G3PSeed()
  , g3pSeed_toSprout
  , G3PSprout()
  , g3pSprout_addArg
  , g3pSprout_addArgs
  , g3pSprout_toTree
  , G3PTree()
  , g3pTree_toKey
  , G3PKey()
  , g3pKey_toGen
  , g3pKey_toStream
  ) where

import           Data.Bits (xor)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Function((&))
import           Data.Word
import           Data.Stream (Stream(..))
import qualified Data.Stream as Stream
import           Data.Vector (Vector)
import qualified Data.Vector as V
import           Network.ByteOrder (word32, bytestring64)

import           Crypto.Encoding.PHKDF
                    ( add64WhileLt
                    , takeBs
                    , nullBuffer
                    )
import           Crypto.Encoding.SHA3.TupleHash
import           Crypto.PHKDF.HMAC
import           Crypto.PHKDF.Primitives
import           Crypto.PHKDF.Primitives.Assert
import           Crypto.G3P.BCrypt (bcryptXsFree)
import           Crypto.G3P.V2.Subtle

-- | These input parameters are grouped together because the envisioned use
--   for them is that they are constants (or near-constants) specified by
--   a deployment. User-supplied inputs would typically not go here.  In this
--   role, all these parameters function as salt.
--
--   The seguid parameter acts as a deployment-wide salt. Cryptographically
--   speaking, the most important thing a deployment can do is specify a
--   constant seguid.  It is highly recommended that the seguid input be a
--   genuine Self-Documenting Globally Unique Identifier attesting to the
--   parameters, purposes, and public playbook of the protocol for y'all
--   to follow to use the deployment to spec.
--
--   The remaining string parameters are all directly-documenting, embedded
--   attributions. A deployment can use these tags to encode a message into the
--   password hash function so that it must be known to whomever can compute it.
--   There are a variety of different parameters because there are different
--   lengths of messages that can be expressed for free, and there are different
--   incremental costs for exceeding that limit.
--
--   It is particularly important to include some kind of actionable message
--   in the @domainTag@ and @longTag@ parameter. Specifying an empty string
--   in either of these parameters means that a significant quantity of
--   cryptoacoustic messaging space will be filled with silence.
--
--   Especially useful messages include URIs, legal names, and domain names.



data G3PSalt = G3PSalt
  { g3pSalt_seguid :: !HmacKey
    -- ^ An HMAC-SHA256 key, usable as a high-repetition indirect tag via
    --   self-documenting globally unique identifiers (seguids).
  , g3pSalt_domainTag :: !ByteString
    -- ^ plaintext tag with one repetition per PHKDF round. 0-19 bytes are
    --   free, 20-82 bytes cost a additional sha256 block /per PHKDF round/,
    --   with 83-146 and every 64 bytes thereafter incurring a similar cost.
    --
    --   Tags up to 82 or maybe even 146 bytes long are reasonable in most
    --   contexts. In the case of long domain tags, it is strategically
    --   advantageous to ensure that the first 32 bytes are highly actionable,
    --   as these bytes are commonly used as filler padding.
    --
    --   This parameter provides [domain separation](https://csrc.nist.gov/glossary/term/domain_separation).
    --   A suggested value is a ICANN domain name controlled by the deployment.
    --   The name is also a bit of an homage to the "realm" parameter of HTTP
    --   basic authentication, which in part inspired it.
  , g3pSalt_longTag :: !ByteString
    -- ^ plaintext tag with 1x repetition, then cycled for roughly
    --   8 kilobytes.  Constant time on inputs up to nearly 5 kilobytes.
    --
    --   Overages incur one sha256 block per 64 bytes.
  , g3pSalt_contextTags :: !(Vector ByteString)
    -- ^ plaintext tags with 3x repetition. Constant-time on 0-63 encoded bytes,
    --   which includes the length encoding of each string. Thus 60 of those
    --   free bytes are usable if the tags vector is a single string, or less if
    --   it contains two or more strings.
    --
    --   Overages incur three sha256 blocks per 64 bytes.
    --
    --   This parameter is notable because it is the least expensive purely
    --   auxiliary input that is not horn-loaded. Thus if you want a very long
    --   salt input that provides a bit of extra collision resistance, this
    --   would be a logical candidate input location to consider.
  , g3pSalt_phkdfRounds :: !Word32
    -- ^ How expensive will the PHKDF component be? An optimal implementation
    --   computes exactly three SHA256 blocks per round if the domain tag is
    --   19 bytes or less, plus a reasonably large but constant number of
    --   additional blocks. I recommend at least 20,000 rounds, if not 40,000.
    --   You might consider adjusting that recommendation downward in the
    --   case of domain tags that exceed 19 bytes in length: 15,000 rounds
    --   of PHKDF with a domain tag that is 83 bytes long should cost about
    --   the same number of SHA256 blocks as 20,000 rounds of PHKDF with a
    --   domain tag that is 19 bytes long.
  } deriving (Eq)

-- | The username and password are grouped together because they are normally
--   expected to be supplied by users or other observers of a deployment.
--
--   Furthermore, the credentials vector is here because it is an ideal
--   location to include other user input. For example, one could implement
--   a Two-Secret Key Derivation (2SKD) scheme analogous to 1Password's.
--
--   A deployment can also specify additional constant tags as part of the
--   credentials vector.  As the plaintext of these tags is only ever hashed
--   into the output a single time, this alongside the bcrypt tag and long tag
--   are incrementally the least expensive options for plaintext tagging.
--
--   Note that the username and password are subjected to additional length
--   hardening. The G3P operates in a constant number of SHA256 blocks so long
--   as the combined length of the username and password is less than about
--   3 KiB,  or the combined length of the username, password, and long tag is
--   less than about 8 KiB. The actual numbers are somewhat less in both cases,
--   but this is a reasonable approximation. Note that the bcrypt tag can
--   subtract up to 113 bytes from the 8 KiB total, and don't effect the 3 KiB
--   total.
--
--   In the case of all of the inputs in this record, longer values incur one
--   SHA256 block per 64 bytes.

data G3PInputs = G3PInputs
  { g3pInputs_username :: !ByteString
  -- ^ constant time on 0-101 bytes, or if any of the other conditions are met.
  , g3pInputs_password :: !ByteString
  -- ^ constant time on 0-101 bytes, or if any of the other conditions are met.
  , g3pInputs_credentials :: !(Vector ByteString)
  -- ^ constant time on 0-90 encoded bytes. This includes a variable-length
  -- field that encodes the bit length of each string; this field itself
  -- requires two or more bytes per string.
  } deriving (Eq)

data G3PSeedInputs = G3PSeedInputs
  { g3pSeedInputs_bcryptKey :: !HmacKey
    -- ^ Key to used to generate keys for bcrypt superrounds and to soak up
    --   the entropy from bcrypt's state at the end of each superround.
    --   Duplicating the 'g3pSalt_seguid' is a good default choice.
  , g3pSeedInputs_bcryptRounds :: !Word32
    -- ^ How expensive will the bcrypt component be? 4000 rounds recommended,
    --   give or take a factor of 2 or so. Each bcrypt round is approximately
    --   as time consuming as 60 PHKDF rounds. Using the recommended cost,
    --   parameters, the cost should be dominated by bcrypt.
  , g3pSeedInputs_bcryptLongTag :: !ByteString
    -- ^ Be aware this is truncated to (rounds + 1) * 4176 bytes, but
    --   length still matters after that. The primary intended use is to
    --   duplicate 'g3pSalt_longTag' a very large number of times.
    --
    --   Also be aware that nobody should trust this parameter with arbitrary,
    --   potentially hostile input that is selected after all of the other
    --   inputs to the bcrypt comptuation are known. There are, however,
    --   a large number of ways to avoid any potential issues, including:
    --
    --   1.  Ensuring that this input is fully commited to before looking
    --       at all of the other input parameters /by convention/, which is
    --       true in the primary intended use case as an extended salt for
    --       password hashing.
    --
    --   2.  Ensure that this input has been committed to by including the
    --       entirety of its contents in the derivation of at least one other
    --       input parameter. Note that duplicating 'g3pSalt_longTag' is
    --       sufficient to meet this requirement, as is duplicating
    --       any other 'G3PSalt' parameter.
    --
    --   3.  Ensure that this input is less than 4448 bytes long. Local HMAC
    --       computations ensure at least this many bytes are automatically
    --       committed to before the bcrypt key stretching is allowed to
    --       move forward.
    --
    --   4.  Ensure that this input has some kind, any kind, of recognizable
    --       pattern. If this input is UTF8 encoded, it doesn't matter if the
    --       textual content is random gibberish, it's extremely doubtful that
    --       an attacker could achieve any particularly nefarious goal under
    --       this restriction.
    --
    --   Note that any single one of these conditions should be sufficient
    --   to avoid problems, and that the primary intended use case for this
    --   parameter meets all of them. After all, the entire point of this
    --   parameter is to ensure the delivery of plaintext salts from
    --   authentication database deployments to password crackers.
    --
    --   Failing all of that, there's still an attempt to make the G3P
    --   resistant to hostile inputs. Within each bcrypt round, the exact same
    --   longTag bytes are repeated twice in a combinatorial block design that
    --   ensures nonlinear effects.
    --
    --   I wouldn't want to rely on this design feature of last resort without
    --   careful study, which is likely to suggest further improvements.
    --   Yet this hedge doesn't cost anything with respect to the intended
    --   use case, and seems plausibly strong in situations that fall well
    --   outside anything intended.
    --
    --   Regarding condition 2, any of the 'G3PInput' parameters would also
    --   qualify. However, it would be rather silly to repeat the user's
    --   password here, as that would prevent the bcrypt key stretching
    --   computation from being securely outsourced to a semi-trusted device.
    --
    --   Regarding condition 3, the actual size of a parameter that is fully
    --   committed to via baked-in hashing is likely a bit more than 8352
    --   bytes, but this would require further verification.
  , g3pSeedInputs_bcryptDomainTag :: !ByteString
    -- ^ Used to derive the keys for a super round in bcrypt-xs-ctr mode.
    --   Duplicating the 'g3pSalt_domainTag' is a good default choice.
  , g3pSeedInputs_bcryptContextTags :: !(Vector ByteString)
    -- ^ Also used to derive super round keys for bcrypt. Leaving this
    --   empty is a good default choice. In particular, one /should not/
    --   default to duplicating anything between this parameter and
    --   the 'g3pSeed_contextTags' parameter.
    --
    --   For example, if your deployment uses a random per-user salt, then
    --   it's a good idea to include that salt in the 'username' and
    --   'contextTags' parameters, but exclude that salt from the
    --   'bcryptContextTags'. This means that if some or all of the bcrypt
    --   computation is outsourced to another device, that device cannot
    --   break even weak passwords without the salt.
    --
    --   Directly including that random per-user salt in the
    --   'bcryptContextTags' vector would require that this salt be known to
    --   the device performing the key-stretching computation, thus
    --   automatically obviating this possible line of defense.
    --
    --   Which things are forgotten and when are important details in
    --   cryptographic processes, and these choices imply strategic outcomes.
    --
    --   If some unusual deployment of the G3P accepts arbitrary external
    --   inputs into the 'bcryptLongTag', one possible way to handle this
    --   situation efficiently and safely would be to hash the entire input,
    --   and include that hash in this parameter.
  }

-- | The Global Password Prehash Protocol (G3P). Note that this function is very
--   intentionally implemented in such a way that the following idiom is
--   efficient.  It performs the expensive key stretching phase only once.
--
-- @
--  let mySprout = g3pHash salt inputs
--      myAuthKey = mySprout ["auth",ec8296b96e939f"] "user salt ec8296b96e939f"
--      myDiskKey = mySprout ["disk",longTag,"key","bf94facc27b76328"] "my.domain storage context"
--   in [ myKeyAuth (word32 "AUTH") "my.domain.example"
--      , myDiskAuth (word32 "DISK") "filename0.txt"
--      , myDiskAuth (word32 "DISK") "quarterly-report.pdf"
--      ]
-- @
--
--   In addition to sharing the main key-stretching computation among
--   all three independent output streams, this also shares the computation
--   of the 'G3PKey' among the two calls to @myDiskAuth@.  However, the
--   savings in this latter context is relatively miniscule, but might
--   also be relevant in certain contexts.
--
--   In the case that you want or need to persist or serialize the intermediate
--   intermediate structures then the plain-old-datatypes 'G3PSeed',
--   'G3PSprout', 'G3PTree', and 'G3PKey' and their associated functions
--   are more relevant.

-- Oof, I didn't actually succeed in my claim in the first release of G3Pb1.
-- I now have a deeper appreciation for point-less programming.
g3pHash :: Foldable f
        => G3PSalt -- ^ All the parameters needed throughout the entire key-stretching computation.
        -> G3PInputs -- ^ All the parameters that can be forgotten as soon as they are hashed once.
        -> G3PSeedInputs -- ^ All the parameters needed for bcrypt-based key stretching
        -> HmacKey -- ^ Sprout Seguid. A good default is to duplicate 'g3pSalt_seguid'.
        -> f ByteString -- ^ Sprout Role, an arbitrary number of bytestring parameters.
        -> ByteString -- ^ Sprout Tag. A good default is to duplicate 'g3pSalt_domainTag'.
        -> ByteString -- ^ echo key right
        -> ByteString -- ^ echo header
        -> Word32 -- ^ echo counter
        -> ByteString -- ^ echo tag. A good default is to duplicate the sprout's tag.
        -> Stream ByteString -- ^ An unbounded stream of 32-byte output blocks.  Use as many or as few as you want. NIST SP 800-108 recommends never looking at more than 137.4 GB of output, though this is an extremely cautious recommendation. On the other hand, if you really want that much CSPRNG data, you are better off using this function to generate keys for another, faster CSPRNG.
g3pHash salt inputs seedInputs seguid role tag ekey ehdr ectr etag =
    g3pSpark_init salt inputs &
    g3pSpark_toSeed seedInputs &
    g3pSeed_toSprout seguid &
    g3pSprout_addArgs role &
    g3pSprout_toTree tag &
    g3pTree_toKey ekey &
    g3pKey_toStream ehdr ectr etag

myDrop' :: Word32 -> Stream a -> Stream a
myDrop' = go
  where
    go 0 s = s
    go n (Cons x s) = x `seq` go (n-1) s

xorBS :: ByteString -> ByteString -> ByteString
xorBS = B.packZipWith xor

data PairBS = PairBS !ByteString !ByteString

xorScan :: Stream ByteString -> Stream PairBS
xorScan = Stream.tail . Stream.scan' f (PairBS blankChunk blankChunk)
  where f (PairBS acc old) new = PairBS (xorBS acc old) new
        blankChunk = B.replicate 32 0

g3pSpark_init :: G3PSalt -> G3PInputs -> G3PSpark
g3pSpark_init salt inputs = spark
  where
    -- Explicitly unpack everything for the unused variable warnings.
    -- i.e. It's relatively easy to check that we've unpacked every
    -- field, then we can rely on unused variable warnings to ensure
    -- we have in fact made use of everything.
    domainTag = g3pSalt_domainTag salt
    seguid = g3pSalt_seguid salt
    longTag = g3pSalt_longTag salt
    contextTags = g3pSalt_contextTags salt
    phkdfRounds = g3pSalt_phkdfRounds salt

    username = g3pInputs_username inputs
    password = g3pInputs_password inputs
    credentials = g3pInputs_credentials inputs

    headerAlfa = [ "G3Pb2 alfa username", username ]

    usernamePadLen = a
      where
        al = encodedVectorByteLength headerAlfa
        a  = add64WhileLt (349 - al) 32

    usernamePadding = B.concat $
      takeBs (fromIntegral (usernamePadLen - 32)) (cycle [longTag, "\x00"]) ++
      takeBs 32 [domainTag, "\x00", "password G3Pb2", nullBuffer]

    headerUsername = headerAlfa ++ [ usernamePadding ]

    -- password will go here

    headerLongTag =
      [ longTag
      , B.concat
          [ bareEncode phkdfRounds, "\x00"
          , "Global Password Prehash Protocol bcrypt(XS) v2 G3Pb2", "\x00"]
      ]

    passwordPadLen = c
      where
        al = encodedVectorByteLength headerLongTag
        a  = add64WhileLt (8605 - al) 4429
        bl = encodedVectorByteLength headerUsername
        b  = add64WhileLt (a - bl) 328
        cl = encodedByteLength password
        c  = add64WhileLt (b - cl) 32

    longPadding =
      takeBs (fromIntegral (passwordPadLen - 32)) (cycle [longTag, "\x00"]) ++
      takeBs 32 [domainTag, "\x00", "creds G3Pb2", nullBuffer]

    credsPadLen = a
      where
        al = encodedVectorByteLength credentials
        a  = add64WhileLt (318 - al) 32

    credsPadding =
      takeBs (fromIntegral (credsPadLen - 29)) (cycle [longTag, "\x00"]) ++
      takeBs 29 [domainTag, "\x00", "tags G3Pb2", nullBuffer]

    (PairBS alfaSum alfaExt) =
        phkdfCtx_init seguid &
        phkdfCtx_addArgs headerUsername &
        phkdfCtx_assertBufferPosition' 32 &
        phkdfCtx_addArg  password &
        phkdfCtx_addArgs headerLongTag &
        phkdfCtx_addArgConcat longPadding &
        phkdfCtx_assertBufferPosition' 32 &
        phkdfCtx_addArgs credentials &
        phkdfCtx_addArgConcat credsPadding &
        phkdfCtx_assertBufferPosition' 29 &
        phkdfCtx_addArgs contextTags &
        phkdfCtx_addArg (bareEncode (V.length contextTags)) &
        phkdfCtx_finalizeStream endPadding
           (word32 "go\x00\x00" + 2024) domainTag &
        xorScan & myDrop' 1 & -- ensure that the sum is not filled with nulls
        myDrop' phkdfRounds & -- do the requested number of additional rounds
        Stream.head

    endPadding = B.concat . flip takeBs (cycle [longTag, "\x00"]) . fromIntegral

    bravo = "G3Pb2 bravo"

    headerBravo =
        [ bravo, alfaExt ] ++ takeBs 53 (cycle [longTag, "\x00"]) ++
        [ alfaSum ]

    -- keyB: key bravo begins bcrypt (and key bullshit baffles brains)
    -- keyB was generated by the call to G3Pb2 bravo, and starts bcrypt
    -- keyB is used to generate a prefixed hmac key to bcrypt,
    --   which is used to generate round keys for bcrypt, as well
    --   to summarize bcrypt's pBox and sBox

    ("",prefixBravo) = hmacKeyPrefixed_init seguid &
                       hmacKeyPrefixed_feeds headerBravo

    bravoKeyPad b = B.concat $
        takeBs 31 [domainTag, "\x00", bravo, nullBuffer] ++ [b]

    keyB = phkdfCtx_initPrefixed (bravoKeyPad "B") prefixBravo &
           phkdfCtx_addArgs contextTags &
           phkdfCtx_finalize endPadding (word32 "KEYB") domainTag

    -- keyC, charlie's continuation control key
    --   It's inclusion (or omission) is a fundamental design tradeoff.

    --   This key allows a low-power device to outsource (part of) the
    --   bcrypt computation without losing control of the continuation
    --   that leads to the seed.

    --   The downside is that keyC has less key stretching than the bcrypt
    --   computation, and cannot be forgotten until after the bcrypt key
    --   stretching is complete, or the computation is abandoned.

    --   Given that this is already at PBKDF2-level key stretching,
    --   and that many password hash functions have historically not
    --   cared about how soon (and often) their computation becomes
    --   unreversable, I think this is a good tradeoff in the
    --   primary intended context of a client-side prehash function.

    keyC = phkdfCtx_initPrefixed (bravoKeyPad "C") prefixBravo &
           phkdfCtx_addArgs contextTags &
           phkdfCtx_finalize endPadding (word32 "KEYC") domainTag

    spark = G3PSpark
       { g3pSpark_beginKey = keyB
       , g3pSpark_contKey  = keyC
       , g3pSpark_contextTags = contextTags
       , g3pSpark_domainTag   = domainTag
       }

g3pSpark_toSeed :: G3PSeedInputs -> G3PSpark -> G3PSeed
g3pSpark_toSeed inputs spark = G3PSeed seed
  where
    beginKey = g3pSpark_beginKey spark
    contKey = g3pSpark_contKey spark
    contextTags = g3pSpark_contextTags spark
    domainTag = g3pSpark_domainTag spark

    bSeguid = g3pSeedInputs_bcryptKey inputs
    bRounds = g3pSeedInputs_bcryptRounds inputs
    bLongTag = g3pSeedInputs_bcryptLongTag inputs
    bDomainTag = g3pSeedInputs_bcryptDomainTag inputs
    bContextTags = g3pSeedInputs_bcryptContextTags inputs

    charlie = "G3Pb2 charlie"

    charlieHeader = charlie : beginKey : takeBs 19 [domainTag, nullBuffer]

    ("", charliePrefix) =
      hmacKeyPrefixed_init bSeguid &
      hmacKeyPrefixed_feeds charlieHeader

    bcryptName = B.concat
      [ "G3Pb2 bcrypt-xs-free"
      , bytestring64 (8 * fromIntegral (B.length bLongTag))
      ]

    (_, charlieCont) =
      bcryptXsFree id bcryptName bLongTag bContextTags bDomainTag
                   bRounds charliePrefix

    contPad = B.concat $ takeBs 32 [domainTag, "\x00", charlie, nullBuffer]

    ("", endCont) = hmacKeyPrefixed_feeds [contPad, contKey] charlieCont

    seed = phkdfCtx_initPrefixed contPad endCont &
           phkdfCtx_addArgs contextTags &
           phkdfCtx_finalize endPadding (word32 "SEED") domainTag

    endPadding = B.concat . flip takeBs (cycle [domainTag, "\x00"]) . fromIntegral

g3pSeed_toSprout :: HmacKey -> G3PSeed -> G3PSprout
g3pSeed_toSprout key (G3PSeed seed) = G3PSprout ctx
  where
    delta = "G3Pb2 delta"
    ctx = phkdfCtx_init key &
          phkdfCtx_addArg (delta <> seed)

g3pSprout_addArg :: ByteString -> G3PSprout -> G3PSprout
g3pSprout_addArg x = G3PSprout . phkdfCtx_addArg x . g3pSprout_phkdfCtx

g3pSprout_addArgs :: Foldable f => f ByteString -> G3PSprout -> G3PSprout
g3pSprout_addArgs xs = G3PSprout . phkdfCtx_addArgs xs . g3pSprout_phkdfCtx

g3pSprout_toTree :: ByteString -> G3PSprout -> G3PTree
g3pSprout_toTree domainTag (G3PSprout ctx) = G3PTree key
  where
    key = phkdfCtx_finalize endPadding (word32 "KEYZ") domainTag ctx
    endPadding = B.concat . flip takeBs (cycle [domainTag, "\x00"]) . fromIntegral

g3pTree_toKey :: ByteString -- ^ This @echo key@ is the right half of the output key.  It is truncated to 32 bytes.
              -> G3PTree -> G3PKey
g3pTree_toKey echoKeyR (G3PTree echoKeyL) = G3PKey (hmacKeyHashed key)
  where
    keyR = takeBs 32 [echoKeyR, "\x00", "G3Pb2 echo key right padding", nullBuffer]
    -- Note that echoKeyL should already be 32 bytes, so this should be id:
    keyL = takeBs 32 [echoKeyL, nullBuffer]
    key = B.concat (keyL ++ keyR)

-- | Variant of 'g3pKey_toStream' that returns plain old data.

g3pKey_toGen
  :: ByteString -- ^ echo header
  -> Word32 -- ^ echo counter
  -> ByteString -- ^ echo tag
  -> G3PKey -> PhkdfGen
g3pKey_toGen echoHeader echoCtr echoTag (G3PKey key) = gen
  where
    hdr = B.concat $
      takeBs 32 [echoHeader, "\x00", "G3Pb2 echo header padding", nullBuffer]
    gen = phkdfGen_initHashed key hdr echoCtr echoTag

-- | Turn a secret, derived 'HmacKeyHashed' into an unbounded
--   stream of 32-byte output blocks.

g3pKey_toStream
  :: ByteString
  -- ^ The @echo header@ is truncated to 32 bytes.
  --
  -- As the initial state of the output stream generator, if more than one
  -- block of the resulting output stream is ever examined, then this
  -- parameter must not include any new secrets. Otherwise the old secrets
  -- are potentially still crackable from the relationship between output
  -- stream blocks.
  --
  -- This problem can be avoided by ensuring at least one of these are true:
  --
  --     1.  sticking to anodyne messages that aren't too specific to
  --         this specific password attempt, like a company name
  --
  --     2.  including data that's already been included elsewhere in the
  --         derivation of the Merkle tree.
  --
  --     3.  duplicating the content of this parameter in the @echo key@
  --         and/or @echo tag@ parameters.
  -> Word32
  -- ^ The @echo counter@, functionally a bonus HKDF info parameter.
  -> ByteString
  -- ^ The @echo tag@, functionally identical to HKDF's info parameter.
  -> G3PKey -> Stream ByteString
g3pKey_toStream hdr ctr tag key =
  phkdfGen_finalizeStream (g3pKey_toGen hdr ctr tag key)

