-------------------------------------------------------------------------------
-- |
-- Module:      Crypto.PHKDF.Subtle
-- Copyright:   (c) 2024 Auth Global
-- License:     Apache2
--
-------------------------------------------------------------------------------

module Crypto.PHKDF.Subtle
  ( PhkdfCtx(..)
  , phkdfCtx_unsafeFeed
  , PhkdfGen(..)
  ) where

import           Prelude hiding (null)
import           Crypto.Sha256 as Sha256
import           Crypto.PHKDF.HMAC (HmacKeyLike)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Foldable(foldl', null)
import           Data.Word

-- I should be using the counter inside the sha256 ctx.
-- While this project is rapidly approaching maturity, it's still somewhat
-- proof of concept.  See the new SHA256 bindings WIP.

data PhkdfCtx = PhkdfCtx
  { phkdfCtx_state :: !Sha256Ctx
  , phkdfCtx_hmacKeyLike :: !HmacKeyLike
  }

data P = P !Word64 !Sha256Ctx

phkdfCtx_unsafeFeed :: Foldable f => f ByteString -> PhkdfCtx -> PhkdfCtx
phkdfCtx_unsafeFeed strs ctx =
  if null strs then ctx
  else ctx {
    phkdfCtx_state = sha256_feeds strs (phkdfCtx_state ctx)
  }

data PhkdfGen = PhkdfGen
  { phkdfGen_hmacKeyLike :: !HmacKeyLike
  , phkdfGen_extTag :: !ByteString
  , phkdfGen_counter :: !Word32
  , phkdfGen_state :: !ByteString
  , phkdfGen_initCtx :: !(Maybe Sha256Ctx)
  }
