module Crypto.Sha256.Hkdf
  ( hkdf
  , hkdfExtract
  , hkdfExpand
  , hkdfExpand_toGen
  , hkdfExpand_toStream
  , HkdfCtx()
  , hkdfCtx_init
  , hkdfCtx_feed, hkdfCtx_feeds
  , hkdfCtx_update, hkdfCtx_updates
  , hkdfCtx_finalize
  , HkdfGen()
  , hkdfGen_init
  , hkdfGen_read
  , hkdfGen_peek
  , hkdfGen_toStream
  ) where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as SB
import           Data.Function((&))
import           Data.Stream (Stream(..))
import qualified Data.Stream as Stream
import           Crypto.HashString ( HashString )
import qualified Crypto.HashString as HS
import           Crypto.Sha256.Hmac
import           Crypto.Sha256.Hkdf.Subtle

hkdf :: HmacKey -- ^ salt
     -> ByteString -- ^ initial keying material
     -> ByteString -- ^ info
     -> [HashString]
hkdf salt = hkdfExpand . hkdfExtract salt

hkdfExtract
    :: HmacKey -- ^ salt
    -> ByteString -- ^ initial keying material
    -> HmacKey -- ^ pseudorandom key
hkdfExtract salt = hkdfCtx_finalize . hkdfCtx_update (hkdfCtx_init salt)

hkdfExpand
    :: HmacKey -- ^ pseudorandom key
    -> ByteString -- ^ info
    -> [HashString]
hkdfExpand prk = Stream.take 255 . hkdfExpand_toStream prk

hkdfExpand_toGen
    :: HmacKey -- ^ pseudorandom key
    -> ByteString -- ^ info
    -> HkdfGen
hkdfExpand_toGen prk = hkdfGen_init prk . SB.toShort

hkdfExpand_toStream
    :: HmacKey -- ^ pseudorandom key
    -> ByteString -- ^ info
    -> Stream HashString
hkdfExpand_toStream prk = hkdfGen_toStream . hkdfExpand_toGen prk

hkdfCtx_init :: HmacKey -> HkdfCtx
hkdfCtx_init key = HkdfCtx (hmacCtx_init key)

hkdfCtx_feeds :: Foldable f => f ByteString -> HkdfCtx -> HkdfCtx
hkdfCtx_feeds bs (HkdfCtx ctx) = HkdfCtx (hmacCtx_feeds bs ctx)

hkdfCtx_feed :: ByteString -> HkdfCtx -> HkdfCtx
hkdfCtx_feed bs (HkdfCtx ctx) = HkdfCtx (hmacCtx_feed bs ctx)

hkdfCtx_updates :: Foldable f => HkdfCtx -> f ByteString -> HkdfCtx
hkdfCtx_updates (HkdfCtx ctx) bs = HkdfCtx (hmacCtx_updates ctx bs)

hkdfCtx_update :: HkdfCtx -> ByteString -> HkdfCtx
hkdfCtx_update (HkdfCtx ctx) bs = HkdfCtx (hmacCtx_update ctx bs)

hkdfCtx_finalize :: HkdfCtx -> HmacKey
hkdfCtx_finalize (HkdfCtx ctx) = hmacKey (HS.toByteString (hmacCtx_finalize ctx))

hkdfGen_init :: HmacKey -> ShortByteString -> HkdfGen
hkdfGen_init key info = HkdfGen
   { hkdfGen_info = info
   , hkdfGen_key = key
   , hkdfGen_counter = 1
   , hkdfGen_state = HS.fromShort SB.empty
   }

hkdfGen_read :: HkdfGen -> (HashString, HkdfGen)
hkdfGen_read gen = (state',gen')
 where
   info = hkdfGen_info gen
   key = hkdfGen_key gen
   counter = hkdfGen_counter gen
   state = hkdfGen_state gen
   counter' = counter + 1
   state' = hmacCtx_init key &
            hmacCtx_feed (HS.toByteString state) &
            hmacCtx_feed (SB.fromShort info) &
            hmacCtx_finalizeBits (B.singleton counter) 8
   gen' = HkdfGen
     { hkdfGen_info = info
     , hkdfGen_key = key
     , hkdfGen_counter = counter'
     , hkdfGen_state = state'
     }

hkdfGen_peek :: HkdfGen -> Maybe HashString
hkdfGen_peek gen =
    if (SB.null (HS.toShort st))
    then Nothing
    else Just st
  where
    st = hkdfGen_state gen

hkdfGen_toStream :: HkdfGen -> Stream HashString
hkdfGen_toStream = Stream.unfold hkdfGen_read
