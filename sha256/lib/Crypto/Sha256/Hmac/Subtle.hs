-------------------------------------------------------------------------------
-- |
-- Module:      Crypto.Sha256.Hmac.Subtle
-- Copyright:   (c) 2024 Auth Global
-- License:     Apache2
--
-- "Internal" data structures and functions for hmac
--
-------------------------------------------------------------------------------

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
  , hmacKeyLike_runIpadCtx
  , hmacKeyLike_runOpadCtx
  , HmacKeyHashed(..)
  , hmacKeyHashed_ipadCtx
  , hmacKeyHashed_opadCtx
  , hmacKeyHashed_runIpadCtx
  , hmacKeyHashed_runOpadCtx
  , HmacKeyPrefixed(..)
  , hmacKeyPrefixed_opadCtx
  , hmacKeyPrefixed_runIpadCtx
  , hmacKeyPrefixed_runOpadCtx
  , HmacCtx(..)
  ) where

import Crypto.Sha256.Hmac.Implementation