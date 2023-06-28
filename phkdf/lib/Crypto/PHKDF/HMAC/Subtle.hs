{- |

"Internal" data structures representing precomputed HMAC keys and partial HMAC
contexts, supporting incremental computation and backtracking.

-}

module Crypto.PHKDF.HMAC.Subtle
  ( HmacCtx(..)
  , HmacKey(..)
  , hmacKey_ipad
  , hmacKey_opad
  ) where

import qualified Crypto.Hash.SHA256 as SHA256

-- | Fixed-size context representing the state of a partial HMAC computation
--   with a complete HMAC key and a partial message parameter.

data HmacCtx = HmacCtx
  { hmacCtx_ipad :: !SHA256.Ctx
  , hmacCtx_opad :: !SHA256.Ctx
  } deriving (Eq)

-- | A precomputed HMAC key. Computing an HMAC key costs two SHA256 blocks.
--
-- No additional blocks are incurred for keys that are 64 bytes or less in
-- length.  Keys that are longer than 64 bytes long must be first hashed
-- with SHA256 before the key can be derived, incurring extra blocks.
--
-- It is not uncommon that implementations of PBKDF2, HKDF, etc unnecessarily
-- redo this computation even though a single HMAC key is used repeatedly.
--
-- TODO: FIXME: this data structure is way larger than it should be.  We can
-- pack this into a single 64-byte bytestring, but right now it's 208 bytes
-- of data plus extra overhead.
--
-- On the other hand, this approach may actually be more efficient for the
-- core PHKDF algorithm as currently implemented.  Reducing the size of this
-- data structure while maintaining tight code involves some additional work
-- on cryptohash-sha256

newtype HmacKey = HmacKey { hmacKey_run :: HmacCtx } deriving (Eq)

hmacKey_ipad :: HmacKey -> SHA256.Ctx
hmacKey_ipad (HmacKey ctx) = hmacCtx_ipad ctx

hmacKey_opad :: HmacKey -> SHA256.Ctx
hmacKey_opad (HmacKey ctx) = hmacCtx_opad ctx
