-------------------------------------------------------------------------------
-- |
-- Module:      Crypto.Sha256.Hkdf
-- Copyright:   (c) 2024 Auth Global
-- License:     Apache2
--
--
-- Implementation of HKDF-SHA256 supporting key reuse, backtracking, streaming,
-- and more.
--
-------------------------------------------------------------------------------

module Crypto.Sha256.Hkdf
  ( hkdf
  , hkdf'
  , hkdfList
  , hkdfList'
  , hkdfGen
  , hkdfExtract
  , hkdfExpand
  , hkdfExpand'
  , hkdfExpandList
  , hkdfExpandList'
  , hkdfExpandGen
  , HkdfCtx()
  , hkdfCtx_init
  , hkdfCtx_feed, hkdfCtx_feeds
  , hkdfCtx_update, hkdfCtx_updates
  , hkdfCtx_finalize
  , HkdfGen()
  , hkdfGen_init
  , hkdfGen_read
  , hkdfGen_read'
  , hkdfGen_peek
  ) where

import           Control.Arrow((***))
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as SB
import           Data.Function((&))
import qualified Data.List as List

import           Crypto.HashString ( HashString )
import qualified Crypto.HashString as HS
import           Crypto.Sha256.Hmac
import           Crypto.Sha256.Hkdf.Subtle

hkdf :: HmacKeyPlain -- ^ salt
     -> ByteString -- ^ initial keying material
     -> ByteString -- ^ info tag
     -> Int -- ^ desired output length
     -> ByteString
hkdf = (fmap . fmap . fmap . fmap $ HS.toByteString) hkdf'

hkdf' :: HmacKeyPlain -- ^ salt
      -> ByteString -- ^ initial keying material
      -> ByteString -- ^ info tag
      -> Int -- ^ desired output length
      -> HashString
hkdf' = (fmap . fmap . fmap $ \gen len ->
           mconcat (HS.takeBytes len (hkdfGen_toList' gen))
        ) hkdfGen

hkdfList
  :: HmacKeyPlain -- ^ salt
  -> ByteString -- ^ initial keying material
  -> ByteString -- ^ info tag
  -> [ByteString]
hkdfList = (fmap . fmap . fmap $ hkdfGen_toList) hkdfGen

hkdfList'
  :: HmacKeyPlain -- ^ salt
  -> ByteString -- ^ initial keying material
  -> ByteString -- ^ info tag
  -> [HashString]
hkdfList' = (fmap . fmap . fmap $ hkdfGen_toList') hkdfGen


hkdfGen
  :: HmacKeyPlain -- ^ salt
  -> ByteString -- ^ initial keying material
  -> ByteString -- ^ info tag
  -> HkdfGen
hkdfGen = fmap hkdfExpandGen . hkdfExtract . hmacKey_hashed

hkdfExtract
    :: HmacKey -- ^ salt
    -> ByteString -- ^ initial keying material
    -> HmacKey -- ^ pseudorandom key
hkdfExtract = fmap hkdfCtx_finalize . hkdfCtx_update . hkdfCtx_init

hkdfExpand
    :: HmacKey -- ^ pseudorandom key
    -> ByteString -- ^ info tag
    -> Int -- ^ desired length
    -> ByteString
hkdfExpand = (fmap . fmap . fmap $ HS.toByteString) hkdfExpand'

hkdfExpand'
    :: HmacKey -- ^ pseudorandom key
    -> ByteString -- ^ info tag
    -> Int -- ^ desired length
    -> HashString
hkdfExpand' =
  (fmap . fmap $ \gen len ->
      mconcat (HS.takeBytes len (hkdfGen_toList' gen))
  ) hkdfExpandGen

hkdfExpandList
    :: HmacKey -- ^ pseudorandom key
    -> ByteString -- ^ info tag
    -> [ByteString] -- ^ infinite lazy list of output blocks
hkdfExpandList = fmap hkdfGen_toList . hkdfExpandGen

hkdfExpandList'
    :: HmacKey -- ^ pseudorandom key
    -> ByteString -- ^ info tag
    -> [HashString] -- ^ infinite lazy list of output blocks
hkdfExpandList' = fmap hkdfGen_toList' . hkdfExpandGen

hkdfExpandGen
    :: HmacKey -- ^ pseudorandom key
    -> ByteString -- ^ info tag
    -> HkdfGen
hkdfExpandGen prk = hkdfGen_init prk . SB.toShort

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

hkdfGen_read' :: HkdfGen -> (HashString, HkdfGen)
hkdfGen_read' gen = (state',gen')
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

hkdfGen_read :: HkdfGen -> (ByteString, HkdfGen)
hkdfGen_read = (HS.toByteString *** id) . hkdfGen_read'

hkdfGen_peek :: HkdfGen -> Maybe HashString
hkdfGen_peek gen =
    if (SB.null (HS.toShort st))
    then Nothing
    else Just st
  where
    st = hkdfGen_state gen

hkdfGen_toList' :: HkdfGen -> [HashString]
hkdfGen_toList' = List.unfoldr (Just . hkdfGen_read')

hkdfGen_toList :: HkdfGen -> [ByteString]
hkdfGen_toList = List.unfoldr (Just . hkdfGen_read)
