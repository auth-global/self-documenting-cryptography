module Crypto.PHKDF.Primitives.Subtle
  ( PhkdfCtx(..)
  , phkdfCtx_unsafeFeed
  , PhkdfSlowCtx(..)
  , phkdfSlowCtx_lift
  ) where

import           Prelude hiding (null)
import qualified Crypto.Hash.SHA256 as SHA256
import           Crypto.PHKDF.HMAC (HmacKey)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Foldable(foldl', null)
import           Data.Word

-- I should be using the counter inside the sha256 ctx, but this is a Proof of Concept

-- TODO: should phkdfCtx_length count bytes, or bits? Double-check how SHA256 internal counter
-- works. Decide how this should work. Then export it from Primitives module.
-- For truly bulletproof code, we probably need to be returning (Maybe Ctx), so that we don't
-- overflow SHA256's internal counter. This would be a bit of a conceptual problem with the
-- cryptohash-style interface I'm mimicking, not to mention the cryptohash implementation I
-- am depending upon.

-- note that there's an offset error w.r.t the sha256 internal counter and phkdfCtx_length, but
-- it's always 64 bytes.  As the internals of this module only care about the internal counter
-- modulo 64, this doesn't matter.  However we should probably export the SHA256 counter itself

data PhkdfCtx = PhkdfCtx
  { phkdfCtx_byteLen :: !Word64
  , phkdfCtx_state :: !SHA256.Ctx
  , phkdfCtx_hmacKey :: !HmacKey
  }

data P = P !Word64 !SHA256.Ctx

phkdfCtx_unsafeFeed :: Foldable f => f ByteString -> PhkdfCtx -> PhkdfCtx
phkdfCtx_unsafeFeed strs ctx0 =
  if null strs then ctx0
  else ctx0 {
    phkdfCtx_byteLen = byteLen',
    phkdfCtx_state = state'
  }
  where
    delta (P len ctx) str = P (len + (fromIntegral (B.length str))) (SHA256.update ctx str)

    p0 = P (phkdfCtx_byteLen ctx0) (phkdfCtx_state ctx0)

    P byteLen' state' = foldl' delta p0 strs

data PhkdfSlowCtx = PhkdfSlowCtx
  { phkdfSlowCtx_phkdfCtx :: !PhkdfCtx
  , phkdfSlowCtx_counter :: !Word32
  , phkdfSlowCtx_tag :: !ByteString
  }

phkdfSlowCtx_lift :: (PhkdfCtx -> PhkdfCtx) -> PhkdfSlowCtx -> PhkdfSlowCtx
phkdfSlowCtx_lift f ctx = ctx {
    phkdfSlowCtx_phkdfCtx = f (phkdfSlowCtx_phkdfCtx ctx)
  }
