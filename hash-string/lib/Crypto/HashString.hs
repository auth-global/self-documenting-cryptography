{-# LANGUAGE MagicHash, UnboxedTuples, CApiFFI, UnliftedFFITypes, BangPatterns, LambdaCase #-}

module Crypto.HashString
     ( HashString(..)
     , hashString_toShortBase16
     , hashString_fromShortBase16
     , hashString_toShortBase64
     , hashString_fromShortBase64
     ) where

import           Data.Bits((.&.))
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.ByteString.Internal(c2w, w2c)
import           Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import           Data.ByteString.Short.Internal (ShortByteString(..))
import qualified Data.ByteString.Short as SB
import qualified Data.Char as Char
import           Data.Maybe
import           Data.Word
import           Foreign.C
import           Foreign.Ptr
import           GHC.Exts
import           GHC.IO

import           Crypto.HashString.FFI

newtype HashString = HashString { unHashString :: ShortByteString }

instance Eq HashString where
  x == y = compare x y == EQ

instance Ord HashString where
  compare (HashString xsbs@(SBS x)) (HashString ysbs@(SBS y)) =
      compare (c_const_memcmp_ba x y minlen) 0
        <> compare xlen ylen
    where
      xlen = SB.length xsbs
      ylen = SB.length ysbs
      minlen = fromIntegral (min xlen ylen)

instance IsString HashString where
  fromString = \case
      ( 'b' : '1' : '6' : ' ' : xs ) -> doBase16 xs
      ( 'b' : '6' : '4' : ' ' : xs ) -> doBase64 xs
      xs -> doBase16 xs
    where
      doBase16 = fromMaybe err . hashString_fromShortBase16 . SB.pack . map myConv
        where
          err = error "fromString :: String -> HashString  --  base16 syntax error"
          myConv x = if Char.isHexDigit x then c2w x else err

      doBase64 = fromMaybe err . hashString_fromShortBase64 . SB.pack . map myConv
        where
          err = error "fromString :: String -> HashString  --  base64 syntax error"
          myConv x = if Char.isAscii x then c2w x else err

instance Show HashString where
  show xs = '"': enc xs ++ ['"']
    where
      enc = map w2c . SB.unpack . hashString_toShortBase16

hashString_fromShortBase16 :: ShortByteString -> Maybe HashString
hashString_fromShortBase16 str@(SBS ptr)
  | odd ptrlen = Nothing
  | otherwise =
    unsafePerformIO . IO $ \st ->
      let !(I# outlen) = ptrlen `div` 2
          !(# st0, a #) = newByteArray# outlen st
          !(# st1, err #) = unIO (c_hexDecode_ba a ptr (fromIntegral ptrlen)) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in if err /= 0
          then (# st2, Nothing #)
          else (# st2, Just (HashString (SBS b)) #)
  where
    ptrlen = SB.length str

hashString_toShortBase16 :: HashString -> ShortByteString
hashString_toShortBase16 (HashString str@(SBS ptr)) =
    unsafePerformIO . IO $ \st ->
      let !(I# outlen) = ptrlen * 2
          !(# st0, a #) = newByteArray# outlen st
          !(# st1, () #) = unIO (c_hexEncode_ba a ptr (fromIntegral ptrlen)) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in  (# st2, SBS b #)
  where
    ptrlen = SB.length str

hashString_fromShortBase64 :: ShortByteString -> Maybe HashString
hashString_fromShortBase64 str@(SBS ptr)
  | odd ptrlen = Nothing
  | otherwise =
    unsafePerformIO . IO $ \st ->
      let !(I# outlen) = ptrlen `div` 2
          !(# st0, a #) = newByteArray# outlen st
          !(# st1, err #) = unIO (c_base64Decode_ba a ptr (fromIntegral ptrlen)) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in if err /= 0
          then (# st2, Nothing #)
          else (# st2, Just (HashString (SBS b)) #)
  where
    ptrlen = SB.length str

hashString_toShortBase64 :: HashString -> ShortByteString
hashString_toShortBase64 (HashString str@(SBS ptr)) =
    unsafePerformIO . IO $ \st ->
      let !(I# outlen) = ptrlen * 2
          !(# st0, a #) = newByteArray# outlen st
          !(# st1, () #) = unIO (c_base64Encode_ba a ptr (fromIntegral ptrlen)) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in  (# st2, SBS b #)
  where
    ptrlen = SB.length str