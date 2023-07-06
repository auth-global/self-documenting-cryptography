{-# LANGUAGE OverloadedStrings #-}

-- | The Password Hash Key Derivation Function (PHKDF) is a unification,
--   synthesis, and distillation of PBKDF2, HKDF, and TupleHash. It was
--   designed as a building block for implementing a variety of
--   self-documenting cryptographic constructions.
--
--   This module is intended more as a demonstration of and cookbook for
--   what can be done with the PHKDF primitives.  For actual deployments,
--   consider if the Global Password Prehash Protocol (G3P) is more
--   appropriate for your needs.  The G3P is a variant of 'phkdfPass' that
--   additionally integrates bcrypt as the primary key-stretching component.
--
--   These examples also serve as design studies that help informally justify
--   the G3P. Within my design framework, I've tried to maximize the benefits
--   while managing implementation costs.
--
--   1. Every bit of every parameter matters. Every boundary between
--      parameters matter. There aren't supposed to be any trivial collisions,
--      the only exception being null-extension collisions on the seguid.
--
--   2. Except for the tweaks, any change to any parameter requires restarting
--      the PHKDF key-stretching computation from somewhere in the very first
--      call to HMAC.
--
--   3. All input arguments are hardened against length-related timing side
--      channels in various different ways.
--
--      At one extreme, the username, password, and long tag have the most
--      aggressive length hardening in the conventional sense, exhibiting no
--      timing side channels except on multi-kilobyte inputs, after which
--      the timing impacts are minimzed.
--
--      At another extreme, the domain tag exhibits severe yet predictable
--      timing side channels transitioning from 19 to 20 bytes and every 64
--      bytes thereafter.  However, the domain tag is otherwise free of
--      timing-based side channels, so it too is hardened in its own way.
--
--   The design I converged upon employs fairly complicated data encoding
--   procedures. Unfortunately, this provides a fair bit of surface area
--   for subtly wrong implementations that work most of the time, but will
--   return garbage on certain lengths of inputs. I hope that this will
--   eventually be remediated with a more comprehensive suite of test vectors.

module Crypto.PHKDF where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Function((&))
import           Data.Word
import           Data.Stream (Stream)
import           Data.Vector (Vector)
import qualified Data.Vector as V
import           Network.ByteOrder (word32)

import           Crypto.Encoding.PHKDF
import           Crypto.Encoding.SHA3.TupleHash
import           Crypto.PHKDF.Primitives
import           Crypto.PHKDF.Primitives.Assert

-- | These input parameters are grouped together because the envisioned use
--   for them is that they are constants (or near-constants) specified by
--   a deployment. User-supplied inputs would typically not go here.
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
--   The remaining parameter strings are all directly-documenting plaintext
--   tags. A deployment can use these tags to encode a message into the password
--   hash function so that it must be known to whomever is hashing a password
--   of their choice.
--
--   Finally, the rounds parameter determines the latency of the function.
--   At least 250,000 rounds are recommended if PHKDF is used as the sole key
--   stretching component of a password hash database.
--
--   Unfortunately PHKDF is inexpensively parallelized, so large investments
--   here aren't a good expenditure of a user's latency budget. This is why
--   the G3P integrates bcrypt, and cuts the suggested rounds down to 20,000
--
--   For comparison, @n@ rounds of PHKDF is approximately equivalent to
--   @(1.5 + dtl)*n + c@ rounds  of PBKDF2, where @dtl@ is related to the domain
--   tag length, and c is a bit larger than 130 or so.
--
--   Here, @dtl@ is 0 when the domain tag is between 0 and 19 bytes long, 0.5
--   when the domain tag is between 20 and 83 bytes long, and an additional 0.5
--   for every 64 bytes thereafter.  Thus these functions exhibit extreme
--   timing side channels on the length of the domain tag.
--
--   By contrast, the long tag is hardened against timing side channels up to
--   a bit less than 5 kilobytes in length.  However, an extremely long tag
--   does reduce the headroom provided to masking the length of the username
--   and password fields,  however the minimum headroom allocated to the
--   username and password fields is a bit less than 3 kilobytes.
--
--   As an alternate tagging location, consider the 'phkdfInputArgs_credentials'
--   vector, which can be used as an inexpensive, pay-as-you-go plaintext
--   tagging location.
--
--   If the total encoded byte length of 'phkdfInputBlock_tags' is between 0-63
--   bytes, then these hash protocols operate in a constant number of SHA256
--   blocks.  Every additional 64 bytes incurs the computation of two or three
--   additional SHA256 blocks, because these tags are hashed into the result
--   two times in the case of 'phkdfPass', and three times in the case of
--   'phkdfSimple' (and @g3pHash@).

data PhkdfInputBlock = PhkdfInputBlock
  { phkdfInputBlock_seguid     :: !ByteString
    -- ^ HMAC-SHA256 key, usable as a high-repetition indirect tag via
    --   self-documenting globally unique identifiers (seguids).
  , phkdfInputBlock_domainTag  :: !ByteString
    -- ^ plaintext tag with one repetition per round.  0-19 bytes are free,
    --   20-83 bytes cost a additional sha256 block per round, with every
    --   64 bytes thereafter incurring a similar cost.
  , phkdfInputBlock_longTag    :: !ByteString
    -- ^ plaintext tag with 1x repetition, then cycled for roughly
    --   8 kilobytes.  Constant time on inputs up to nearly 5 kilobytes.
  , phkdfInputBlock_tags       :: !(Vector ByteString)
    -- ^ plaintext tag with 2x repetition ('phkdfPass') or 3x repetition
    --   ('phkdfSimple'). Constant-time on 0-63 encoded bytes, which includes
    --   the length encoding of each string. Thus 60 of those bytes are usable
    --   if the tags vector is a single string, or less if it contains two or
    --   more strings.
  , phkdfInputBlock_rounds     :: !Word32
    -- ^ how expensive will this hash function be? An optimal implementation
    --   computes exactly three SHA256 blocks per round if the domain tag is
    --   19 bytes or less.  It is not recommended that phkdf be used as the
    --   primary key-stretching component of a deployment, but if it is used
    --   this way, we recommend at least 250,000 rounds.  This can be adjusted
    --   downward in the case of domain tags longer than 19 bytes.
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
--   The credentials vector is constant time on 0-63 encoded bytes, incurring
--   one additional SHA256 block every 64 bytes thereafter. This includes
--   a variable-length field that encodes the bit length of each string; this
--   field itself requires 2 or more bytes.
--
--   The username and password are constant time as long as their encoded
--   lengths add up to less than roughly 3 kilobytes, or the username,
--   password, and domain tag add up to less than roughly 8 kilobytes.
--   The actual numbers are somewhat less in both cases, but this is a
--   good approximation.

data PhkdfInputArgs = PhkdfInputArgs
  { phkdfInputArgs_username    :: !ByteString
  -- ^ The name of this parameter is suggestive, but this parameter is
  --   functionally identical to a second password. The only difference
  --   is the fact that a password can be cracked without knowledge of the
  --   plaintext username. By contrast, the password acts as a plaintext tag
  --   if one provides the username: guessing the username implies plaintext
  --   knowledge of the password.
  , phkdfInputArgs_password    :: !ByteString
  , phkdfInputArgs_credentials :: !(Vector ByteString)
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
--   favorite techniques employed by the key-stretching phase of 'phkdfPass'
--   to harden against timing side-channels.
--
--   A deployment could conceivably harden this expansion phase against timing
--   side channels themselves, if the were sufficiently inclined. There are
--   several techniques. For starters, a deployment could specify an additional
--   variable-length string in the role vector, used to control its relative
--   ending position inside the SHA256 buffer.

data PhkdfInputTweak = PhkdfInputTweak
  { phkdfInputTweak_role :: !(Vector ByteString)
  , phkdfInputTweak_tags :: !(Vector ByteString)
  } deriving (Eq, Ord, Show)

-- | A plain-old-data explicit representation of the intermediate 'phkdfPass'
--   computation after the 'PhkdfInputBlock' and 'PhkdfInputArgs' have been
--   processed and key stretching has been completed, but before the tweaks
--   have been applied and the final output generated.
--
--   If you ever need to serialize or persist a seed, you probably want this.
--
--   Intended to be generated by 'phkdfPass_seedInit' and then consumed
--   without modification by 'phkdfPass_seedFinalize'.

data PhkdfSeed = PhkdfSeed
  { phkdfSeed_seguid :: !ByteString
  , phkdfSeed_seguidKey :: !HmacKey
  , phkdfSeed_domainTag :: !ByteString
  , phkdfSeed_secret :: !ByteString
  } deriving (Eq)

-- | A non-tweakable, complete password prehash protocol

phkdfSimple :: PhkdfInputBlock -> PhkdfInputArgs -> Stream ByteString
phkdfSimple block args = echo
  where
    -- Explicitly unpack everything for the unused variable warnings.
    -- i.e. It's relatively easy to check that we've unpacked every
    -- field, then we can rely on unused variable warnings to ensure
    -- we have in fact made use of everything.
    domainTag = phkdfInputBlock_domainTag block
    seguid = phkdfInputBlock_seguid block
    longTag = phkdfInputBlock_longTag block
    tags = phkdfInputBlock_tags block
    rounds = phkdfInputBlock_rounds block

    username = phkdfInputArgs_username args
    password = phkdfInputArgs_password args
    credentials = phkdfInputArgs_credentials args

    phkdfTag = expandDomainTag domainTag

    cycleBS = cycleByteStringWithNull

    headerExtract = [ "phkdf-simple0 username", username ]

    usernamePadding
      =  cycleBS (a-32) domainTag
      <> cycleBS    32  domainTag
      where
        al = encodedVectorByteLength headerExtract
        a = add64WhileLt (157 - al) 32

    headerExtractUsername = headerExtract ++ [ usernamePadding ]

    -- password field goes here

    headerLongTag =
      [ longTag
      , B.concat
        [ "password-hash-key-derivation-function phkdf-simple0\x00"
        , leftEncodeFromBytes (B.length domainTag)
        , bareEncode rounds
        ]
      ]

    longPadding
      =  cycleBS (c-32) longTag
      <> cycleBS    32  domainTag
      where
        al = encodedVectorByteLength headerLongTag
        a  = add64WhileLt (8413 - al) 3238
        bl = encodedVectorByteLength headerExtractUsername
        b  = add64WhileLt (a - bl) 134
        cl = encodedByteLength password
        c  = add64WhileLt (b - cl) 32

    credentialsPadding
      =  cycleBS (a-29) longTag
      <> cycleBS    29  domainTag
      where
        al = encodedVectorByteLength credentials
        a  = add64WhileLt (122 - al) 32

    secretKey =
        phkdfCtx_init seguid &
        phkdfCtx_addArgs headerExtractUsername &
        phkdfCtx_assertBufferPosition 32 &
        phkdfCtx_addArg  password &
        phkdfCtx_addArgs headerLongTag &
        -- FIXME: fusing addArg and longPadding can save ~ 8 KiB RAM
        phkdfCtx_addArg  longPadding &
        phkdfCtx_assertBufferPosition 32 &
        phkdfCtx_addArgs credentials &
        phkdfCtx_addArg  credentialsPadding &
        phkdfCtx_assertBufferPosition 29 &
        phkdfCtx_addArgs tags &
        phkdfCtx_addArg (bareEncode (V.length tags)) &
        phkdfSlowCtx_extract
            (word32 "go\x00\x00" + 2023) phkdfTag
            ("phkdf-simple0 compact\x00" <> domainTag) rounds &
        phkdfSlowCtx_assertBufferPosition 32 &
        phkdfSlowCtx_addArgs tags &
        phkdfSlowCtx_finalize

    -- Harden the tags vector against length-based timing side-channels
    echoHeader = cycleByteStringWithNull 30 "phkdf-simple0 expand echo"

    echo = phkdfCtx_init secretKey &
           phkdfCtx_addArg echoHeader &
           phkdfCtx_assertBufferPosition 32 &
           phkdfCtx_addArgs tags &
           phkdfCtx_finalizeStream (word32 "OUT\x00") phkdfTag

-- | A tweakable, complete prehash protocol.   Note that this function is very
--   intentionally implemented in such a way that the following idiom is
--   efficient, and only performs the expensive key stretching phase once:
--
-- @
--  let mySeed = phkdfPass block args
--   in [ mySeed tweak1, mySeed tweak2, mySeed tweak3 ]
-- @
--
--   However in the case that you want or need to persist or serialize the
--   intermediate seed, then the plain-old-datatype 'PhkdfSeed' and its
--   companion functions 'phkdfPass_seedInit' and 'phkdfPass_seedFinalize'
--   are likely to be more appropriate.

phkdfPass :: PhkdfInputBlock -> PhkdfInputArgs -> PhkdfInputTweak -> Stream ByteString
phkdfPass block args = phkdfPass_seedInit block args & phkdfPass_seedFinalize

-- | This generates a seed, which encapsulates the expensive key-stretching component of 'phkdfPass' into a reusable, tweakable cryptographic value.  This function is way slower than it's companion, 'phkdfPass_seedFinalize'.  Broadly comparable to HKDF-Extract, though with key stretching built-in.

phkdfPass_seedInit :: PhkdfInputBlock -> PhkdfInputArgs -> PhkdfSeed
phkdfPass_seedInit block args =
    PhkdfSeed {
      phkdfSeed_seguid = seguid,
      phkdfSeed_seguidKey = seguidKey,
      phkdfSeed_domainTag = domainTag,
      phkdfSeed_secret = secret
    }
  where
    domainTag = phkdfInputBlock_domainTag block
    seguid = phkdfInputBlock_seguid block
    longTag = phkdfInputBlock_longTag block
    seedTags = phkdfInputBlock_tags block
    rounds = phkdfInputBlock_rounds block

    username = phkdfInputArgs_username args
    password = phkdfInputArgs_password args
    credentials = phkdfInputArgs_credentials args

    phkdfTag = expandDomainTag domainTag

    cycleBS = cycleByteStringWithNull

    headerExtract = [ "phkdf-pass-v0 username", username ]

    usernamePadding
      =  cycleBS (a-32) domainTag
      <> cycleBS    32  domainTag
      where
        al = encodedVectorByteLength headerExtract
        a = add64WhileLt (157 - al) 32

    headerExtractUsername = headerExtract ++ [ usernamePadding ]

    -- password field goes here

    headerLongTag =
      [ longTag
      , B.concat
        [ "password-hash-key-derivation-function phkdf-pass-v0\x00"
        , leftEncodeFromBytes (B.length domainTag)
        , bareEncode rounds
        ]
      ]

    longPadding
      =  cycleBS (c-32) longTag
      <> cycleBS    32  domainTag
      where
        al = encodedVectorByteLength headerLongTag
        a  = add64WhileLt (8413 - al) 3238
        bl = encodedVectorByteLength headerExtractUsername
        b  = add64WhileLt (a - bl) 134
        cl = encodedByteLength password
        c  = add64WhileLt (b - cl) 32

    credentialsPadding
      =  cycleBS (a-29) longTag
      <> cycleBS    29  domainTag
      where
        al = encodedVectorByteLength credentials
        a  = add64WhileLt (122 - al) 32

    seguidKey = hmacKey_init seguid

    secret =
        phkdfCtx_initFromHmacKey seguidKey &
        phkdfCtx_addArgs headerExtractUsername &
        phkdfCtx_assertBufferPosition 32 &
        phkdfCtx_addArg  password &
        -- FIXME: fusing addArg and longPadding can save ~ 8 KiB RAM
        phkdfCtx_addArgs headerLongTag &
        phkdfCtx_addArg  longPadding &
        phkdfCtx_assertBufferPosition 32 &
        phkdfCtx_addArgs credentials &
        phkdfCtx_addArg  credentialsPadding &
        phkdfCtx_assertBufferPosition 29 &
        phkdfCtx_addArgs seedTags &
        phkdfCtx_addArg (bareEncode (V.length seedTags)) &
        phkdfSlowCtx_extract
            (word32 "go\x00\x00" + 2023) phkdfTag
            ("phkdf-pass-v0 compact\x00" <> domainTag) rounds &
        phkdfSlowCtx_assertBufferPosition 32 &
        phkdfSlowCtx_addArgs seedTags &
        phkdfSlowCtx_finalize

-- | This consumes a seed and tweaks to produce the final output stream.
-- This function is the output expansion phase of 'phkdfPass'.  This function
-- is way faster than it's companion 'phkdfPass_seedInit'.  Broadly comparable to
-- HKDF-Expand.

phkdfPass_seedFinalize :: PhkdfSeed ->  PhkdfInputTweak -> Stream ByteString
phkdfPass_seedFinalize seed tweak = echo
  where
    seguidKey = phkdfSeed_seguidKey seed
    domainTag = phkdfSeed_domainTag seed
    secret = phkdfSeed_secret seed

    role = phkdfInputTweak_role tweak
    echoTags = phkdfInputTweak_tags tweak

    phkdfTag = expandDomainTag domainTag

    headerCombine = "phkdf-pass-v0 combine" <> secret
    secretKey =
        phkdfCtx_initFromHmacKey seguidKey &
        phkdfCtx_addArg  headerCombine &
        phkdfCtx_addArgs role &
        phkdfCtx_addArgs echoTags &
        phkdfCtx_finalize (word32 "KEY\x00") phkdfTag

    echo = phkdfCtx_init secretKey &
           phkdfCtx_addArgs echoTags &
           phkdfCtx_finalizeStream (word32 "OUT\x00") phkdfTag
