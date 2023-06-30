{-# LANGUAGE OverloadedStrings #-}

{- |

The Global Password Prehash Protocol (G3P) is a slow, self-documenting
cryptographic hash function.  It is self-documenting in the sense that its
password hashes are supposed to be /traceable/ or /useless/ after they have
been /stolen/. This secondary security goal seeks to use /cryptoacoustics/
to make it impractically expensive to hide the target of a password cracking
attack from those providing the resources to carry it out. In doing so, offline
attacks on password hashes cannot be outsourced without also knowing exactly
where to report those password hashes as stolen.

The G3P revisits the role of cryptographic salt, in order to be both
self-documenting and particularly well-suited to deployment as a client-side
prehash function. In a traditional password hash function, the salt is a random
bytestring typically between 8 and 32 bytes long. It identifies a unique hash
function so that one cannot attempt to crack multiple password hashes with a
single key-stretching computation.  Oftentimes this is implemented by storing
a salt per user.

However, in the context of a deployment of the G3P as a client-side prehash,
storing a salt per user has the potential to leak whether or not an account
exists, or if a password has changed. The G3P eliminates these complications,
because these random per-user salts have been replaced with @username@, the
@seguid@, and the @domainTag@ and other plaintext tags. We recommend a single
64-byte (512-bit) seguid for the deployment, and deployment's choice of
plaintext messages to be delivered via cryptoacoustic tags.

If a deployment wants to add their own random per-user salt, the G3P always has
room to do so. Theoretically, one could specify a G3P-based hash function that
requires terabytes of salt to be hashed billions of times over. However it is
unclear what purpose such an impractical specification might serve.

This initial variant of the G3P employs a combination of PHKDF and bcrypt.
PHKDF serves as the primary cryptoacoustic component, and bcrypt serves as the
primary key-stretching component of the G3P. Both are secondarily used in the
alternate role as well, with the PHDKF adding a tiny bit of key stretching and
bcrypt providing significant additional cryptoacoustic plaintext repetitions.

1.  Every bit of every parameter matters. Every boundary between parameters
    matter. The presence and position of every empty string matters. There
    aren't supposed to be any trivial collisions, the only exception being
    null-byte extension collisions on the seguid, which serves as an
    HMAC-SHA256 key.

2.  Except for the tweaks, any change to any parameter requires restarting the
    PHKDF key-stretching computation from somewhere in the very first call to
    HMAC.

3.  All input arguments are hardened against length-related timing side
    channels in various different ways.

    At one extreme, the username, password, and long tag have the most
    aggressive length hardening in the conventional sense, exhibiting no timing
    side channels except on multi-kilobyte inputs, after which the timing
    impacts are minimzed.

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
/horn-loaded parameters/ in the sense that they are consumed a constant
number of times near the beginning of the hashing protocol, and after each PHKDF
round, the hash with the least key-stretching applied is discarded.

This implies that particularly paranoid password-handling implementations can
eliminate the password from memory even before key-stretching is complete.
Additionally, assuming all the sensitive secrets are contained in horn-loaded
parameters, this implies the key-stretching computation can be relocated at
nearly any time with full credit for any key-stretching already performed.

The cost associated with horn-loaded parameters is that collisions on these
parameters over the entire G3P can be found by "only" colliding the first call
to HMAC-SHA256, /G3Pb1 alfa/. If it were trivial to produce collisions on
HMAC-SHA256, this would very likely make collisions on the horn-loaded
parameters trivial. However such an attack would be unlikely to immediately
extend to the overall G3P and be able to produce collisions that vary any of
the other parameters. This is because all the other parameters are repeated
elsewhere in the protocol, thus colliding /G3Pb1 alfa/ isn't enough to collide
the final result.

In the context of password-based authentication flows, this cost seems perfectly
acceptable. After all, collision resistance and second preimage resistance is
irrelevant in this context. What is crucially important is preimage resistance
and maximizing the cost of parallelizing multiple key-stretching computations
while minimizing the latency of a single key-stretching computation.

-}

module Crypto.G3P where

import           Control.Exception(assert)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Function((&))
import           Data.Word
import           Data.Stream (Stream(..))
import qualified Data.Stream as Stream
import           Data.Vector (Vector)
import qualified Data.Vector as V
import           Network.ByteOrder (word32)

import           Crypto.Encoding.PHKDF
import           Crypto.Encoding.SHA3.TupleHash
import           Crypto.PHKDF.Primitives
import           Crypto.PHKDF.Primitives.Assert
import           Crypto.G3P.BCrypt

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
--   to follow.
--
--   In more concrete cryptographic terms, the seguid parameter is the constant
--   HMAC key used by the protocol right up until the final output exansion.
--   This design is closely modelled on the HKDF construction. As such, adding
--   null bytes onto the ends of seguids that are less than 64 bytes long
--   should be the only source of trivial collisions in the entire protocol.
--
--   The remaining string parameters are all directly-documenting,
--   cryptoacoustic plaintext tags. A deployment can use these tags to encode
--   a message into the password hash function so that it must be known to
--   whomever can compute it.  There are a variety of different parameters
--   because there are different lengths of messages that can be expressed
--   for free, and there are different incremental costs for exceeding that
--   limit.
--
--   It is particularly important to include some kind of actionable message
--   in the @domainTag@, @longTag@, @bcryptTag@, and @bcryptSaltTag@
--   parameters. Specifying an empty string in any of these parameters
--   means that a significant quantity of cryptoacoustic messaging space will
--   be filled with silence.

data G3PInputBlock = G3PInputBlock
  { g3pInputBlock_seguid :: !ByteString
    -- ^ HMAC-SHA256 key, usable as a high-repetition indirect tag via
    --   self-documenting globally unique identifiers (seguids).
  , g3pInputBlock_domainTag :: !ByteString
    -- ^ plaintext tag with one repetition per PHKDF round. 0-19 bytes are
    --   free, 20-83 bytes cost a additional sha256 block per round, with every
    --   64 bytes thereafter incurring a similar cost.
  , g3pInputBlock_longTag :: !ByteString
    -- ^ plaintext tag with 1x repetition, then cycled for roughly
    --   8 kilobytes.  Constant time on inputs up to nearly 5 kilobytes.
  , g3pInputBlock_tags :: !(Vector ByteString)
    -- ^ plaintext tag with 3x repetition. Constant-time on 0-63 encoded bytes,
    --   which includes the length encoding of each string. Thus 60 of those
    --   free bytes are usable if the tags vector is a single string, or less if
    --   it contains two or more strings.
  , g3pInputBlock_phkdfRounds :: !Word32
    -- ^ How expensive will the PHKDF component be? An optimal implementation
    --   computes exactly three SHA256 blocks per round if the domain tag is
    --   19 bytes or less, plus a reasonably large but constant number of
    --   additional blocks. I recommend at least 20,000 rounds. You might
    --   consider adjusting that recommendation downward in the case of domain
    --   tags that exceed 19 bytes in length: 15,000 rounds of PHKDF with
    --   a domain tag that is 83 bytes long should cost about the same number
    --   of SHA256 blocks as 20,000 rounds of PHKDF with a domain tag that
    --   is 19 bytes long.
  , g3pInputBlock_bcryptRounds :: !Word32
    -- ^ How expensive will the bcrypt component be? 4000 rounds recommended,
    --   give or take a factor of 2 or so. Each bcrypt round is way more
    --   expensive than a PHKDF round. Using the recommended parameters, the
    --   cost should be dominated by bcrypt.
  , g3pInputBlock_bcryptTag :: !ByteString
    -- ^ One repetition of the first 56 bytes per bcrypt round, plus one
    --   repetition of the full tag in PHKDF. When combined with the
    --   @bcryptSaltTag@, 0-118 encoded bytes are constant-time in PHKDF.
  , g3pInputBlock_bcryptSaltTag :: !ByteString
    -- ^ One repetition of the first 56 bytes per bcrypt round, plus one
    --   repetition of the full tag in PHKDF. When combined with the
    --   @bcryptTag@, 0-118 encoded bytes are constant-time in PHKDF.
  } deriving (Eq, Ord, Show)

-- | The username and password are grouped together because they are normally
--   expected to be supplied by users or other observers of a deployment.
--
--   Furthermore, the credentials vector is here because it is an ideal
--   location to include other user input. For example, one could implement
--   a Two-Secret Key Derivation (2SKD) scheme analogous to 1Password's.
--
--   A deployment can also specify additional constant tags as part of the
--   credentials vector.  As the plaintext of these tags is only ever hashed
--   into the output a single time, this is the least expensive
--   pay-as-you-go option for plaintext tagging.
--
--   The credentials vector is constant time on 0-100 encoded bytes, incurring
--   one additional SHA256 block every 64 bytes thereafter. This includes
--   a variable-length field that encodes the bit length of each string; this
--   field itself requires 2 or more bytes.
--
--   The username and password are constant time as long as their encoded
--   lengths add up to less than roughly 3 kilobytes, or the username,
--   password, and domain tag add up to less than roughly 8 kilobytes.
--   The actual numbers are somewhat less in both cases, but this is a
--   good approximation.

data G3PInputArgs = G3PInputArgs
  { g3pInputArgs_username :: !ByteString
  , g3pInputArgs_password :: !ByteString
  , g3pInputArgs_credentials :: !(Vector ByteString)
  } deriving (Eq, Ord, Show)

-- | These parameters are used to tweak the final output, without redoing any
--   expensive key stretching.  A possible use case is including a high entropy
--   secret in the role itself that isn't available until after a successful
--   stage of authentication.
--
--   Since these parameters are processed in a context that could conceivably be
--   performance sensitive, we don't apply any length padding or side-channel
--   hardening.  Instead we opt for maximizing free tagging space.  Thus we
--   want to avoid incurring additional SHA256 block computations, one of the
--   favorite techniques employed by the key-stretching phase of the G3P
--   to harden against timing side-channels.
--
--   A deployment could conceivably harden this expansion phase against timing
--   side channels themselves, if the were sufficiently inclined. There are
--   several techniques. For starters, a deployment could ensure that these
--   parameters themselves are constant-length.  Alternatively, a deployment
--   could specify an additional variable-length string in the role vector,
--   used to control the ending position relative to the SHA256 buffer.

data G3PInputTweak = G3PInputTweak
  { g3pInputTweak_role :: !(Vector ByteString)
  , g3pInputTweak_tags :: !(Vector ByteString)
  } deriving (Eq, Ord, Show)
=
-- | A plain-old-data explicit representation of the intermediate 'g3pHash'
--   computation after the 'G3PInputBlock' and 'G3PInputArgs' have been
--   processed and key stretching has been completed, but before the tweaks
--   have been applied and the final output generated.
--
--   If you ever need to serialize or persist a seed, you probably want this.
--
--   Intended to be generated by 'g3pHash_seedInit' and then consumed
--   without modification by 'g3pHash_seedFinalize'.

data G3PSeed = G3PSeed
  { g3pSeed_seguid :: !ByteString
  , g3pSeed_seguidKey :: !HmacKey
  , g3pSeed_domainTag :: !ByteString
  , g3pSeed_secret :: !ByteString
  } deriving (Eq)

-- | The Global Password Prehash Protocol (G3P). Note that this function is very
--   intentionally implemented in such a way that the following idiom is
--   efficient, and only performs the expensive key stretching phase once:
--
-- @
--  let mySeed = g3pHash block args
--   in [ mySeed tweak1, mySeed tweak2, mySeed tweak3 ]
-- @
--
--   However in the case that you want or need to persist or serialize the
--   intermediate seed, then the plain-old-datatype 'G3PSeed' and its
--   companion functions 'g3pHash_seedInit' and 'g3pHash_seedFinalize'
--   are likely to be more appropriate.

g3pHash :: G3PInputBlock -> G3PInputArgs -> G3PInputTweak -> Stream ByteString
g3pHash block args = g3pHash_seedInit block args & g3pHash_seedFinalize

-- | This generates a seed, which encapsulates the expensive key-stretching
--   component of 'g3pHash' into a reusable, tweakable cryptographic value.
--   This function is way slower than it's companion, 'g3pHash_seedFinalize'.
--   Broadly comparable to @HKDF-Extract@, though with key stretching built-in.

g3pHash_seedInit :: G3PInputBlock -> G3PInputArgs -> G3PSeed
g3pHash_seedInit block args =
    G3PSeed {
      g3pSeed_seguid = seguid,
      g3pSeed_seguidKey = seguidKey,
      g3pSeed_domainTag = domainTag,
      g3pSeed_secret = secret
    }
  where
    protoPad = cycleByteStringWithNull 52 "global-password-prehash-protocol seguid G3Pb1"
    userProtoPad = "username\x00" <> protoPad
    passProtoPad = "password\x00" <> protoPad

    -- Explicitly unpack everything for the unused variable warnings.
    -- i.e. It's relatively easy to check that we've unpacked every
    -- field, then we can rely on unused variable warnings to ensure
    -- we have in fact made use of everything.
    domainTag = g3pInputBlock_domainTag block
    seguid = g3pInputBlock_seguid block
    longTag = g3pInputBlock_longTag block
    seedTags = g3pInputBlock_tags block
    phkdfRounds = g3pInputBlock_phkdfRounds block
    bcryptRounds = g3pInputBlock_bcryptRounds block
    bcryptTag = g3pInputBlock_bcryptTag block
    bcryptSaltTag = g3pInputBlock_bcryptSaltTag block

    user = g3pInputArgs_username args
    pass = g3pInputArgs_password args
    creds = g3pInputArgs_credentials args

    phkdfTag = expandDomainTag domainTag

    bcryptTagLen = encodedByteLength bcryptTag
                 + encodedByteLength bcryptSaltTag

    headerAlfa =
      [ "G3Pb1 alfa"
      , user, userProtoPad
      , pass, passProtoPad
      , bareEncodeFromBytes (B.length domainTag)
      , bareEncode phkdfRounds
      , bareEncode bcryptRounds
      ]

    -- FIXME: This briefly uses more memory than strictly necessary
    -- (on the order of 8 kilobytes)
    headerPadding =
      [ longTag
      , longPaddingBytes 8346 headerAlfa longTag
      ]

    headerBravo = "G3Pb1 bravo\x00" <> domainTag

    bcryptHeader = [bcryptTag, bcryptSaltTag]

    credsPadding = cycleByteStringWithNull padLen domainTag
      where
        bcryptHeaderLen = sum (map encodedByteLength bcryptHeader)
        extent = add64WhileLt (253 - bcryptHeaderLen) 135
        credsLen = encodedVectorByteLength creds
        padLen = add64WhileLt (extent - credsLen) 32

    seguidKey = hmacKey_init seguid

    secretStream =
        phkdfCtx_initFromHmacKey seguidKey &
        phkdfCtx_addArgs headerAlfa &
        phkdfCtx_addArgs headerPadding &
        phkdfCtx_assertBufferPosition' 29 &
        phkdfCtx_addArgs bcryptHeader &
        phkdfCtx_addArgs creds &
        phkdfCtx_addArg  credsPadding &
        phkdfCtx_assertBufferPosition' 29 &
        phkdfCtx_addArgs seedTags &
        phkdfCtx_addArg (bareEncode (V.length seedTags)) &
        phkdfSlowCtx_extract
            (word32 "go\x00\x00" + 2023) phkdfTag
            headerBravo phkdfRounds &
        phkdfSlowCtx_assertBufferPosition' 32 &
        phkdfSlowCtx_addArgs seedTags &
        phkdfSlowCtx_finalizeStream

    (Cons phkdfHash (Cons bcryptInput _)) = secretStream

    (bKeyInput, bSaltInput) = B.splitAt 16 bcryptInput

    bKey = bKeyInput <> cycleByteStringWithNull 56 bcryptTag
    bSalt = bSaltInput <> cycleByteStringWithNull 56 bcryptSaltTag

    bcryptHash = assert (B.length bKey == 72 && B.length bSalt == 72) $
                 bcryptRaw bKey bSalt bcryptRounds

    headerCharlie = B.concat [
        "G3Pb1 charlie", phkdfHash, bcryptHash,
        cycleByteStringWithNull 24 domainTag
      ]
    secret =
        phkdfCtx_initFromHmacKey seguidKey &
        phkdfCtx_addArg headerCharlie &
        phkdfCtx_assertBufferPosition'  32 &
        phkdfCtx_addArgs seedTags &
        phkdfCtx_finalize (word32 "SEED") phkdfTag

-- | This consumes a seed and tweaks to produce the final output stream.
-- This function is the output expansion phase of 'g3pHash'.  This function
-- is way faster than it's companion 'g3pHash_seedInit'.  Broadly comparable to
-- HKDF-Expand.

g3pHash_seedFinalize :: G3PSeed ->  G3PInputTweak -> Stream ByteString
g3pHash_seedFinalize seed tweak = echo
  where
    -- seguid = g3pSeed_seguid seed
    seguidKey = g3pSeed_seguidKey seed
    domainTag = g3pSeed_domainTag seed
    secret = g3pSeed_secret seed

    role = g3pInputTweak_role tweak
    echoTags = g3pInputTweak_tags tweak

    phkdfTag = expandDomainTag domainTag

    headerDelta = "G3Pb1 delta" <> secret

    secretKey =
        phkdfCtx_initFromHmacKey seguidKey &
        phkdfCtx_addArg  headerDelta &
        phkdfCtx_addArgs role &
        phkdfCtx_addArgs echoTags &
        phkdfCtx_finalize (word32 "KEY\x00") phkdfTag

    echo = phkdfCtx_init secretKey &
           phkdfCtx_addArgs echoTags &
           phkdfCtx_finalizeStream (word32 "OUT\x00") phkdfTag
