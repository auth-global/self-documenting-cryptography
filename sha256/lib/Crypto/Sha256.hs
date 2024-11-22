{-# LANGUAGE MagicHash, UnboxedTuples, OverloadedStrings, ScopedTypeVariables,
             BangPatterns, LambdaCase #-}

module Crypto.Sha256
  ( hash
  , hash'
  , HashString(..)
  , hashString_toShort
  , hashString_toShortBase16
  , hashString_fromShort
  , hashString_toByteString
  , hashString_fromByteString
  , hashString_toBase16
  , Sha256Ctx()
  , sha256_init
  , sha256_update,  sha256_feed
  , sha256_updates, sha256_feeds
  , sha256_byteCount
  , sha256_blockCount
  , sha256_bufferLength
  , sha256_state
  , sha256_finalize    , sha256_finalize_toByteString
  , sha256_finalizeBits, sha256_finalizeBits_toByteString
  ) where

import           Data.Base16.Types
import           Data.Bits((.&.), shiftR)
import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B
import           Data.ByteString.Internal (w2c, c2w, unsafeCreate)
import           Data.ByteString.Short.Internal(ShortByteString(..))
import qualified Data.ByteString.Short as SB
import qualified Data.ByteString.Short.Base16 as SB
import           Data.ByteString.Unsafe(unsafeUseAsCString, unsafeUseAsCStringLen)
import qualified Data.Char as Char
import           Data.Foldable(foldl')
import           Data.Function((&))
import           Data.Monoid
import           Data.String
import           Data.Word
import           GHC.Exts
import           GHC.IO

import           Crypto.Sha256.Subtle

hashString_toShort :: HashString -> ShortByteString
hashString_toShort = unHashString

hashString_fromShort :: ShortByteString -> HashString
hashString_fromShort = HashString

hashString_toByteString :: HashString -> ByteString
hashString_toByteString = SB.fromShort . unHashString

hashString_fromByteString :: ByteString -> HashString
hashString_fromByteString = HashString . SB.toShort

-- FIXME! replace this with algorithms that are constant time independent of content
-- Perhaps this would be a reasonable option:

-- https://github.com/Sc00bz/ConstTimeEncoding

-- TODO: add decoding, and support for Base64

-- TODO: add instance IsString HashString

hashString_toShortBase16 :: HashString -> ShortByteString
hashString_toShortBase16 = extractBase16 . SB.encodeBase16' . hashString_toShort

hashString_toBase16 :: HashString -> ByteString
hashString_toBase16 = SB.fromShort . hashString_toShortBase16

-- | e.g. "0x0123456789abcdef", arbitrary-length hexadecmial literals prefixed with "0x"

instance IsString HashString where
  fromString = \case
      ( '0' : 'x' : xs )
        | all Char.isHexDigit xs ->
	    HashString (SB.decodeBase16Lenient (SB.pack (map c2w xs)))
        | otherwise ->
	    error "fromString :: HashString -> String  --  base16 syntax error"
      _ ->  error "fromString :: HashString -> String  --  no valid syntax found"

instance Show HashString where
  show (HashString xs) = '"':'\\':'x': enc xs ++ ['"']
    where
      enc = map w2c . SB.unpack . extractBase16 . SB.encodeBase16'

-- TODO: there are a number of magic literals scattered throughout that
-- really ought to refer to a symbolic constant of some sort

hash :: ByteString -> ByteString
hash x = sha256_init & sha256_finalizeBits_toByteString x maxBound

hash' :: ByteString -> HashString
hash' x = sha256_init & sha256_finalizeBits x maxBound

sha256_init :: Sha256Ctx
sha256_init =
  unsafePerformIO . IO $ \st ->
    let !(# st0, a #) = newByteArray# 40# st
        !(# st1, _ #) = unIO (c_sha256_init_ctx a) st0
        !(# st2, b #) = unsafeFreezeByteArray# a st1
     in (# st2, Sha256Ctx b #)

sha256_byteCount :: Sha256Ctx -> Word64
sha256_byteCount (Sha256Ctx ctx) = c_sha256_get_count ctx

sha256_blockCount :: Sha256Ctx -> Word64
sha256_blockCount ctx = sha256_byteCount ctx `shiftR` 6

sha256_bufferLength :: Sha256Ctx -> Word8
sha256_bufferLength ctx = fromIntegral (sha256_byteCount ctx .&. 0x3F)

encodeB16 :: ShortByteString -> String
encodeB16 = map w2c . SB.unpack . extractBase16 . SB.encodeBase16'

sha256_state :: Sha256Ctx -> HashString
sha256_state = sha256state_encode . sha256state_fromCtxInplace

sha256_update :: Sha256Ctx -> ByteString -> Sha256Ctx
sha256_update ctx0@(Sha256Ctx ctx) bytes
  | B.null bytes = ctx0
  | otherwise =
    unsafePerformIO $ do
      let count = c_sha256_get_count ctx + fromIntegral (B.length bytes)
      let !(I# bufLen#) = 40 + fromIntegral (count .&. 0x3F)
      unsafeUseAsCStringLen bytes $ \(bp,bl) -> IO $ \st ->
        let !(# st0, a #) = newByteArray# bufLen# st
            !(# st1, _ #) = unIO (c_sha256_update_ctx ctx bp (fromIntegral bl) a) st0
            !(# st2, b #) = unsafeFreezeByteArray# a st1
         in  (# st2, Sha256Ctx b #)

sha256_updates :: Foldable f => Sha256Ctx -> f ByteString -> Sha256Ctx
sha256_updates = foldl' sha256_update

sha256_feed :: ByteString -> Sha256Ctx -> Sha256Ctx
sha256_feed = flip sha256_update

sha256_feeds :: Foldable f => f ByteString -> Sha256Ctx -> Sha256Ctx
sha256_feeds = flip sha256_updates

sha256_finalize :: Sha256Ctx -> HashString
sha256_finalize = sha256_finalizeBits B.empty 0

sha256_finalize_toByteString :: Sha256Ctx -> ByteString
sha256_finalize_toByteString = sha256_finalizeBits_toByteString B.empty 0

sha256_finalizeBits :: ByteString -> Word64 -> Sha256Ctx -> HashString
sha256_finalizeBits bits bitlen0 (Sha256Ctx ctx) =
    unsafePerformIO . unsafeUseAsCString bits $ \bp -> IO $ \st ->
      let !(# st0, a #) = newByteArray# 32# st
          !(# st1, () #) = unIO (c_sha256_finalize_ctx_bits_ba ctx bp bitlen a) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in (# st2, HashString (SBS b) #)
  where
    bitlen = min (fromIntegral (B.length bits) * 8) bitlen0

sha256_finalizeBits_toByteString :: ByteString -> Word64 -> Sha256Ctx -> ByteString
sha256_finalizeBits_toByteString bits bitlen0 (Sha256Ctx ctx) =
    unsafeCreate 32 $ \rp ->
      unsafeUseAsCString bits $ \bp ->
        c_sha256_finalize_ctx_bits ctx bp bitlen rp
  where
    bitlen = min (fromIntegral (B.length bits) * 8) bitlen0
