module Crypto.PHKDF.HMAC.Subtle
  ( HmacCtx(..)
  , HmacKey(..)
  , hmacKey_ipad
  , hmacKey_opad
  ) where

import qualified Crypto.Hash.SHA256 as SHA256

data HmacCtx = HmacCtx
  { hmacCtx_ipad :: !SHA256.Ctx
  , hmacCtx_opad :: !SHA256.Ctx
  } deriving (Eq)

newtype HmacKey = HmacKey { hmacKey_run :: HmacCtx } deriving (Eq)

hmacKey_ipad :: HmacKey -> SHA256.Ctx
hmacKey_ipad (HmacKey ctx) = hmacCtx_ipad ctx

hmacKey_opad :: HmacKey -> SHA256.Ctx
hmacKey_opad (HmacKey ctx) = hmacCtx_opad ctx