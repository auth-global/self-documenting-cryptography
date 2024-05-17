module Crypto.PHKDF.Subtle
  ( PhkdfCtx(..)
  , phkdfCtx_unsafeFeed
  , PhkdfGen(..)
  ) where

import           Prelude hiding (null)
import qualified Crypto.Hash.SHA256 as SHA256
import           Crypto.PHKDF.HMAC (HmacKeyLike)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Foldable(foldl', null)
import           Data.Word

-- I should be using the counter inside the sha256 ctx.
-- While this project is rapidly approaching maturity, it's still somewhat
-- proof of concept.  See the new SHA256 bindings WIP.

data PhkdfCtx = PhkdfCtx
  { phkdfCtx_byteCount :: !Word64
  , phkdfCtx_state :: !SHA256.Ctx
  , phkdfCtx_hmacKeyLike :: !HmacKeyLike
  }

data P = P !Word64 !SHA256.Ctx

phkdfCtx_unsafeFeed :: Foldable f => f ByteString -> PhkdfCtx -> PhkdfCtx
phkdfCtx_unsafeFeed strs ctx0 =
  if null strs then ctx0
  else ctx0 {
    phkdfCtx_byteCount = byteCount',
    phkdfCtx_state = state'
  }
  where
    delta (P len ctx) str = P (len + (fromIntegral (B.length str))) (SHA256.update ctx str)

    p0 = P (phkdfCtx_byteCount ctx0) (phkdfCtx_state ctx0)

    P byteCount' state' = foldl' delta p0 strs

data PhkdfGen = PhkdfGen
  { phkdfGen_hmacKeyLike :: !HmacKeyLike
  , phkdfGen_extTag :: !ByteString
  , phkdfGen_counter :: !Word32
  , phkdfGen_state :: !ByteString
  , phkdfGen_initCtx :: !(Maybe SHA256.Ctx)
  }
