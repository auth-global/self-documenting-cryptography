-- | Plain-old-data explicit representations of intermediate 'g3pHash'
--   computations.

module Crypto.G3P.V2.Subtle where

import Data.ByteString(ByteString)
import Data.Vector(Vector)
import Crypto.PHKDF.HMAC(HmacKeyHashed)
import Crypto.PHKDF(PhkdfCtx)

-- | Represents the completion of the PBKDF2-like key stretching computation,
--   and ready for bcrypt.  Technically, a partial evaluation at the
--   completion of @G3Pb2 bravo@, ready for @G3Pb2 charlie@ 

data G3PSpark = G3PSpark
  { g3pSpark_beginKey    :: !ByteString
  , g3pSpark_contKey     :: !ByteString
  , g3pSpark_contextTags :: !(Vector ByteString)
  , g3pSpark_domainTag   :: !ByteString
  } deriving (Eq)

-- | A plain 32-byte hash that represents the completion of both phkdf and
--   bcrypt key stretching phases. Technically, a partial evaluation at
--   the completion of @G3Pb2 charlie@, ready for @G3Pb2 delta@.

newtype G3PSeed = G3PSeed
  { g3pSeed_seedKey :: ByteString
  } deriving (Eq)

-- | Represents a partial evaluation of @G3P delta@, initialized with
--   the Sprout Seguid and possibly commited to part of the role argument.
--   This comes before the Sprout Domain Tag, and in fact can be finalized
--   with that parameter at any time.

newtype G3PSprout = G3PSprout
  { g3pSprout_phkdfCtx :: PhkdfCtx
  }

-- | A plain 32-byte hash that represents the leftmost bytes of the output
--   hmac key. Technically, a partial evaluation ending at @G3Pb2 delta@
--   and ready for the right half of the echo key, as needed to begin the
--   evaluation of @G3Pb2 echo@

newtype G3PTree = G3PTree
  { g3pTree_echoKeyL :: ByteString -- ^ This is expected to be a 32-byte hash value
  } deriving (Eq)

-- | A precomputed hmac key, represented by two 32-byte hashes.  Technically,
--   a partial evaluation of the HMAC-SHA256 construction.

newtype G3PKey = G3PKey
  { g3pKey_streamKey :: HmacKeyHashed
  } -- deriving (Eq)
