module Crypto.Sha256.Hkdf where

hkdf :: HmacKey -> ByteString -> ByteString -> Stream HashString

hkdfExtract :: HmacKey -> ByteString -> HmacKey

hkdfExpand :: HmacKey -> ByteString -> [HashString]

hkdfExpand_toGen :: HmacKey -> ByteString -> HkdfGen

hkdfExpand_toStream :: HmacKey -> ByteString -> Stream HashString

-- | Context type for incremental hkdfExtract

newtype HkdfCtx = HkdfCtx {
    hkdfCtx_hmacCtx :: HmacCtx
  }

-- TODO: put standard Ctx_* functions here

-- | Plain-old-data contextual type for hkdfExpand

data HkdfGen = HkdfGen {
    hkdfGen_key :: !HmacKey,
    hkdfGen_counter :: !Word8,
    hkdfGen_state :: !HashString,
    hkdfGen_info :: !ShortByteString
  }

hkdfGen_init :: HmacKey -> ShortByteString -> HkdfGen

hkdfGen_read :: HkdfGen -> (HashString, HkdfGen)

hkdfGen_peek :: HkdfGen -> Maybe HashString
