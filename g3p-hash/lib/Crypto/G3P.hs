{-# LANGUAGE OverloadedStrings #-}

module Crypto.G3P where

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

data G3PInputBlock = G3PInputBlock
  { g3pInputBlock_seguid :: !ByteString
  , g3pInputBlock_domainTag :: !ByteString
  , g3pInputBlock_longTag :: !ByteString
  , g3pInputBlock_tags :: !(Vector ByteString)
  , g3pInputBlock_phkdfRounds :: !Word32
  , g3pInputBlock_bcryptRounds :: !Word32
  , g3pInputBlock_bcryptTag :: !ByteString
  , g3pInputBlock_bcryptSaltTag :: !ByteString
  } deriving (Eq, Ord, Show)

data G3PInputArgs = G3PInputArgs
  { g3pInputArgs_username :: !ByteString
  , g3pInputArgs_password :: !ByteString
  , g3pInputArgs_credentials :: !(Vector ByteString)
  } deriving (Eq, Ord, Show)

data G3PInputTweak = G3PInputTweak
  { g3pInputTweak_role :: !(Vector ByteString)
  , g3pInputTweak_tags :: !(Vector ByteString)
  } deriving (Eq, Ord, Show)

data G3PSeed = G3PSeed
  { g3pSeed_seguid :: !ByteString
  , g3pSeed_seguidKey :: !HmacKey
  , g3pSeed_domainTag :: !ByteString
  , g3pSeed_secret :: !ByteString
  } deriving (Eq)

g3pHash :: G3PInputBlock -> G3PInputArgs -> G3PInputTweak -> Stream ByteString
g3pHash block args = g3pHash_seedInit block args & g3pHash_seedFinalize

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

    -- Make room for the bcrypt tags to maintain a consistent
    -- relative starting position in the SHA256 buffer for the
    -- credentials vector
    paddedLength = defaultLongPaddingBytes - bcryptTagLen `mod` 64

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
      , longPaddingBytes paddedLength headerAlfa longTag
      , bcryptTag, bcryptSaltTag
      ]

    headerBravo = "G3Pb1 bravo\x00" <> domainTag

    seguidKey = hmacKey_init seguid

    secretStream =
        phkdfCtx_initFromHmacKey seguidKey &
        phkdfCtx_addArgs headerAlfa &
        phkdfCtx_addArgs headerPadding &
        phkdfCtx_assertBufferPosition' 59 &
        phkdfCtx_addArgs creds &
        phkdfCtx_addArg (shortPadding creds domainTag) &
        phkdfCtx_assertBufferPosition' 29 &
        phkdfCtx_addArgs seedTags &
        phkdfCtx_addArg (bareEncode (V.length seedTags)) &
        phkdfSlowCtx_extract
            headerBravo
            phkdfRounds
            (word32 "go\x00\x00" + 2023)
            phkdfTag &
        phkdfSlowCtx_assertBufferPosition' 32 &
        phkdfSlowCtx_addArgs seedTags &
        phkdfSlowCtx_finalizeStream

    (Cons phkdfHash (Cons bcryptInput _)) = secretStream

    bKey = bcryptInput <> cycleByteStringWithNull 40 bcryptTag
    bSalt = cycleByteStringWithNull 16 bcryptSaltTag

    -- only fails if the length of bKey or bSalt is wrong
    (Just bcryptHash) = bcryptRaw bKey bSalt bcryptRounds

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
