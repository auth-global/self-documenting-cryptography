-- | Plain-old-data explicit representations of intermediate 'g3pHash'
--   computations.

module Crypto.G3P.V2.Subtle where

import Data.ByteString(ByteString)
import Data.Vector(Vector)
import Crypto.PHKDF.HMAC(HmacKeyHashed)
import Crypto.PHKDF.Primitives(PhkdfCtx)

-- | Represents the completion of the PBKDF2-like key stretching computation,
--   and ready for bcrypt.

data G3PSpark = G3PSpark
  { g3pSpark_beginKey    :: !ByteString
  , g3pSpark_contKey     :: !ByteString
  , g3pSpark_contextTags :: !(Vector ByteString)
  , g3pSpark_domainTag   :: !ByteString
  } deriving (Eq)

-- | A plain 32-byte hash that represents the completion of both phkdf and
--   bcrypt key stretching phases.

newtype G3PSeed = G3PSeed
  { g3pSeed_seedKey :: ByteString
  } deriving (Eq)

-- | Represents a partially applied HMAC call that is used for
--   domain separation after key stretching is complete.

newtype G3PSprout = G3PSprout
  { g3pSprout_phkdfCtx :: PhkdfCtx
  }

-- | A plain 32-byte hash that represents the leftmost bytes of the output
--   hmac key.

newtype G3PTree = G3PTree
  { g3pTree_echoKeyL :: ByteString -- ^ This is expected to be a 32-byte hash value
  } deriving (Eq)

-- | A precomputed hmac key, represented by two 32-byte hashes.

newtype G3PKey = G3PKey
  { g3pKey_streamKey :: HmacKeyHashed
  } deriving (Eq)
