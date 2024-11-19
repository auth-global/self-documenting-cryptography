{- |

"Internal" data structures and functions for hmac

-}
module Crypto.Sha256.Hmac.Subtle
  ( HmacKey(..)
  , hmacKey_ipad
  , hmacKey_ipadCtx
  , hmacKey_opad
  , hmacKey_opadCtx
  , HmacKeyLike(..)
  , hmacKeyLike_ipadCtx
  , hmacKeyLike_opad
  , hmacKeyLike_opadCtx
  , HmacKeyHashed(..)
  , hmacKeyHashed_ipadCtx
  , hmacKeyHashed_opadCtx
  , HmacKeyPrefixed(..)
  , hmacKeyPrefixed_opadCtx
  , HmacCtx(..)
  ) where

import Crypto.Sha256.Hmac.Implementation