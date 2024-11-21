module Crypto.PHKDF.Primitives.Subtle
  ( PhkdfCtx(..)
  , phkdfCtx_byteLen
  , phkdfCtx_unsafeFeed
  , PhkdfSlowCtx(..)
  , phkdfSlowCtx_lift
  , PhkdfGen(..)
  ) where

import           Prelude hiding (null)
import           Crypto.Sha256 as Sha256
import           Crypto.PHKDF.HMAC (HmacKeyLike)
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
  { phkdfCtx_state :: !Sha256Ctx
  , phkdfCtx_hmacKeyLike :: !HmacKeyLike
  }

phkdfCtx_byteLen :: PhkdfCtx -> Word64
phkdfCtx_byteLen = sha256_byteCount . phkdfCtx_state

data P = P !Word64 !Sha256Ctx

phkdfCtx_unsafeFeed :: Foldable f => f ByteString -> PhkdfCtx -> PhkdfCtx
phkdfCtx_unsafeFeed strs ctx0 =
  if null strs then ctx0
  else ctx0 {
    phkdfCtx_state = sha256_feeds strs (phkdfCtx_state ctx0)
  }

data PhkdfSlowCtx = PhkdfSlowCtx
  { phkdfSlowCtx_phkdfCtx :: !PhkdfCtx
  , phkdfSlowCtx_counter :: !Word32
  , phkdfSlowCtx_tag :: !ByteString
  }

phkdfSlowCtx_lift :: (PhkdfCtx -> PhkdfCtx) -> PhkdfSlowCtx -> PhkdfSlowCtx
phkdfSlowCtx_lift f ctx = ctx {
    phkdfSlowCtx_phkdfCtx = f (phkdfSlowCtx_phkdfCtx ctx)
  }

data PhkdfGen = PhkdfGen
  { phkdfGen_hmacKeyLike :: !HmacKeyLike
  , phkdfGen_extTag :: !ByteString
  , phkdfGen_counter :: !Word32
  , phkdfGen_state :: !ByteString
  , phkdfGen_initCtx :: !(Maybe Sha256Ctx)
  }
