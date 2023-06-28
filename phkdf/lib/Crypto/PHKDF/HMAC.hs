{- |

An alternate implementation of HMAC in terms of cryptohash-sha256, because
the HMAC implementation provided there doesn't support precomputed keys or
streaming inputs.  TODO: prepare a patch for cryptohash-sha256.

-}


module Crypto.PHKDF.HMAC
  ( HmacCtx
  , HmacKey
  , hmacKey_init
  , hmacKey_run
  , hmacCtx_init
  , hmacCtx_initFromHmacKey
  , hmacCtx_update
  , hmacCtx_updates
  , hmacCtx_finalize
  ) where

import qualified Crypto.Hash.SHA256 as SHA256
import           Data.Bits(xor)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B

import           Crypto.PHKDF.HMAC.Subtle

-- | Precompute an HMAC key for some literal HMAC key.

hmacKey_init :: ByteString -> HmacKey
hmacKey_init = HmacKey . hmacCtx_init

-- | Initialize a new empty HMAC context from a literal HMAC key.

hmacCtx_init :: ByteString -> HmacCtx
hmacCtx_init key =
    HmacCtx { hmacCtx_ipad = tweak 0x36, hmacCtx_opad = tweak 0x5c }
  where
    tweak c = SHA256.update SHA256.init $ B.map (xor c) k2
    k1 = if B.length key > 64 then SHA256.hash key else key
    k2 = B.append k1 (B.replicate (64 - B.length k1) 0)

-- | Initialize a new empty HMAC context from a precomputed HMAC key.

hmacCtx_initFromHmacKey :: HmacKey -> HmacCtx
hmacCtx_initFromHmacKey = hmacKey_run

-- | Append a bytestring onto the end of the message argument to HMAC.

hmacCtx_update ::  ByteString -> HmacCtx -> HmacCtx
hmacCtx_update b (HmacCtx ic oc) = HmacCtx (SHA256.update ic b) oc

-- | Append zero or more bytestrings onto the end of the message argument to
--   HMAC.

hmacCtx_updates :: [ByteString] -> HmacCtx -> HmacCtx
hmacCtx_updates bs (HmacCtx ic oc) = HmacCtx (SHA256.updates ic bs) oc

-- | Finish computing the final 32-byte hash for an HMAC context.

hmacCtx_finalize :: HmacCtx -> ByteString
hmacCtx_finalize (HmacCtx ic oc) = outer
  where
    inner = SHA256.finalize ic
    outer = SHA256.finalize (SHA256.update oc inner)
