-------------------------------------------------------------------------------
-- |
-- Module:      Crypto.Sha256.Hkdf.Subtle
-- Copyright:   (c) 2024 Auth Global
-- License:     Apache2
--
-------------------------------------------------------------------------------

module Crypto.Sha256.Hkdf.Subtle where

import Data.ByteString.Short(ShortByteString)
import Data.Word
import Crypto.HashString
import Crypto.Sha256.Hmac

-- | Context type for incremental @hkdfExtract@

newtype HkdfCtx = HkdfCtx {
    hkdfCtx_hmacCtx :: HmacCtx
  } deriving (Eq, Ord)

-- | Plain-old-data representation of the generator for @hkdfExpand@

data HkdfGen = HkdfGen
  { hkdfGen_info :: !ShortByteString
  , hkdfGen_key :: !HmacKey
  , hkdfGen_counter :: !Word8
  , hkdfGen_state :: !HashString
  }
