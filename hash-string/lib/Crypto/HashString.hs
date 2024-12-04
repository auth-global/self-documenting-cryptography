{-# LANGUAGE MagicHash, UnboxedTuples, CApiFFI, UnliftedFFITypes, BangPatterns, LambdaCase, GeneralizedNewtypeDeriving #-}

module Crypto.HashString
     ( HashString(..)
     , fromShort
     , fromShortBase16
     , fromShortBase64
     , toShort
     , toShortBase16
     , toShortBase64
     , fromByteString
     , fromBase16
     , fromBase64
     , toByteString
     , toBase16
     , toBase64
     , toBase16Builder
     , toBase64Builder
     , xorLeft
     , xorMin
     , xorMax
     ) where

import           Data.Bits((.&.))
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.ByteString.Builder (Builder, shortByteString)
import           Data.ByteString.Internal(c2w, w2c, unsafeCreate)
import           Data.ByteString.Unsafe (unsafeUseAsCString, unsafeUseAsCStringLen)
import           Data.ByteString.Short.Internal (ShortByteString(..))
import qualified Data.ByteString.Short as SB
import qualified Data.Char as Char
import           Data.Maybe
import           Data.Monoid
import           Data.Word
import           Foreign.C
import           Foreign.Ptr
import           GHC.Base
import           GHC.Exts
import           GHC.IO

import           Crypto.HashString.FFI

-- | Type intended to represent short-ish cryptographic values, say up to 128
--   bytes or so. Supports constant-time comparisons (i.e. run time depends on
--   length of the inputs but is otherwise independent of content), as well as
--   constant-time base16 and base64 conversions.

newtype HashString = HashString { unHashString :: ShortByteString } deriving (Semigroup, Monoid)

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
      doBase16 = fromMaybe err . fromShortBase16 . SB.pack . map myConv
        where
          err = error "fromString :: String -> HashString  --  base16 syntax error"
          myConv x = if Char.isHexDigit x then c2w x else err

      doBase64 = fromMaybe err . fromShortBase64 . SB.pack . map myConv
        where
          err = error "fromString :: String -> HashString  --  base64 syntax error"
          myConv x = if Char.isAscii x then c2w x else err

instance Show HashString where
  show xs = '"': enc xs ++ ['"']
    where
      enc = map w2c . SB.unpack . toShortBase16

-- | Xor two hashstrings. The length of the result is always the same as the
--   length of the left argument; bytes are either removed from or added to the
--   end of the right argument as needed to match length.

xorLeft :: HashString -> HashString -> HashString
xorLeft (HashString strl@(SBS ptrl)) (HashString strr@(SBS ptrr))
  | compareInt# 0# (unsafePtrEquality# ptrl ptrr) /= EQ = HashString (SB.replicate (SB.length strl) 0)
  | otherwise =
    unsafePerformIO . IO $ \st ->
      let !lenl0@(I# lenl) = SB.length strl
          !lenr0@(I# lenr) = SB.length strr
          !(# st0, a #) = newByteArray# lenl st
          !(# st1, () #) = unIO (c_xorleft_ba ptrl (fromIntegral lenl0) ptrr (fromIntegral lenr0) a) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in  (# st2, HashString (SBS b) #)

-- | Xor two hashstrings. The length of the result is always the same as the
--   length of the shorter argument, removing bytes from the end of the longer
--   string as needed to match length.

xorMin :: HashString -> HashString -> HashString
xorMin (HashString strl@(SBS ptrl)) (HashString strr@(SBS ptrr))
  | compareInt# 0# (unsafePtrEquality# ptrl ptrr) /= EQ = HashString (SB.replicate (SB.length strl) 0)
  | otherwise =
    unsafePerformIO . IO $ \st ->
      let !minlen0@(I# minlen) = min (SB.length strl) (SB.length strr)
          !(# st0, a #) = newByteArray# minlen st
          !(# st1, () #) = unIO (c_xormin_ba ptrl ptrr (fromIntegral minlen0) a) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in  (# st2, HashString (SBS b) #)

-- | Xor two hashstrings.  The length of the result is always the same as the
--   length of the longer argument, adding null bytes onto the end of the
--   shorter string as needed to match length.

xorMax :: HashString -> HashString -> HashString
xorMax (HashString strl@(SBS ptrl)) (HashString strr@(SBS ptrr))
  | compareInt# 0# (unsafePtrEquality# ptrl ptrr) /= EQ = HashString (SB.replicate (SB.length strl) 0)
  | otherwise =
    unsafePerformIO . IO $ \st ->
      let !lenl = SB.length strl
          !lenr = SB.length strr
          !(I# maxlen) = max lenl lenr
          !(# st0, a #) = newByteArray# maxlen st
          !(# st1, () #) = unIO (c_xormax_ba ptrl (fromIntegral lenl) ptrr (fromIntegral lenr) a) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in  (# st2, HashString (SBS b) #)

fromShortBase16 :: ShortByteString -> Maybe HashString
fromShortBase16 str@(SBS ptr) =
  case base16DecodeLength ptrlen of
    Nothing -> Nothing
    Just !(I# outlen) ->
      unsafePerformIO . IO $ \st ->
        let !(# st0, a #) = newByteArray# outlen st
            !(# st1, err #) = unIO (c_hexDecode_ba a ptr (fromIntegral ptrlen)) st0
            !(# st2, b #) = unsafeFreezeByteArray# a st1
         in if err /= 0
            then (# st2, Nothing #)
            else (# st2, Just (HashString (SBS b)) #)
  where
    ptrlen = SB.length str

toShortBase16 :: HashString -> ShortByteString
toShortBase16 (HashString str@(SBS ptr)) =
    unsafePerformIO . IO $ \st ->
      let !(I# outlen) = ptrlen * 2
          !(# st0, a #) = newByteArray# outlen st
          !(# st1, () #) = unIO (c_hexEncode_ba a ptr (fromIntegral ptrlen)) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in  (# st2, SBS b #)
  where
    ptrlen = SB.length str

fromShortBase64 :: ShortByteString -> Maybe HashString
fromShortBase64 str@(SBS ptr) =
  case base64DecodeLength ptrlen of
    Nothing -> Nothing
    Just !(I# outlen) ->
      unsafePerformIO . IO $ \st ->
        let !(# st0, a #) = newByteArray# outlen st
            !(# st1, err #) = unIO (c_base64Decode_ba a ptr (fromIntegral ptrlen)) st0
            !(# st2, b #) = unsafeFreezeByteArray# a st1
         in if err /= 0
            then (# st2, Nothing #)
            else (# st2, Just (HashString (SBS b)) #)
  where
    ptrlen0 = SB.length str
    ptrlen  = ptrlen0 - fromIntegral (c_base64PadLength_ba ptr (fromIntegral ptrlen0))

toShortBase64 :: HashString -> ShortByteString
toShortBase64 (HashString str@(SBS ptr)) =
    unsafePerformIO . IO $ \st ->
      let !(I# outlen) = base64EncodeLength ptrlen
          !(# st0, a #) = newByteArray# outlen st
          !(# st1, () #) = unIO (c_base64Encode_ba a ptr (fromIntegral ptrlen)) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in  (# st2, SBS b #)
  where
    ptrlen = SB.length str

toShort :: HashString -> ShortByteString
toShort = unHashString

fromShort :: ShortByteString -> HashString
fromShort = HashString

toByteString :: HashString -> ByteString
toByteString = SB.fromShort . unHashString

fromByteString :: ByteString -> HashString
fromByteString = HashString . SB.toShort

toBase16 :: HashString -> ByteString
toBase16 (HashString str@(SBS ptr)) =
    unsafeCreate (base16EncodeLength ptrlen) $ \out ->
      c_hexEncode_bs_ba out ptr (fromIntegral ptrlen)
  where
    ptrlen = SB.length str

toBase64 :: HashString -> ByteString
toBase64 (HashString str@(SBS ptr)) =
    unsafeCreate (base64EncodeLength ptrlen) $ \out ->
      c_base64Encode_bs_ba out ptr (fromIntegral ptrlen)
  where
    ptrlen = SB.length str

fromBase16 :: ByteString -> Maybe HashString
fromBase16 str =
  case base16DecodeLength ptrlen of
    Nothing -> Nothing
    Just !(I# outlen) ->
      unsafePerformIO . unsafeUseAsCString str $ \ptr -> IO $ \st ->
        let !(# st0, a #) = newByteArray# outlen st
            !(# st1, err #) = unIO (c_hexDecode_mba_bs a ptr (fromIntegral ptrlen)) st0
            !(# st2, b #) = unsafeFreezeByteArray# a st1
         in if err /= 0
            then (# st2, Nothing #)
            else (# st2, Just (HashString (SBS b)) #)
  where
    ptrlen = B.length str

fromBase64 :: ByteString -> Maybe HashString
fromBase64 str =
  case base64DecodeLength ptrlen of
    Nothing -> Nothing
    Just !(I# outlen) ->
      unsafePerformIO . unsafeUseAsCString str $ \ptr -> IO $ \st ->
        let !(# st0, a #) = newByteArray# outlen st
            !(# st1, err #) = unIO (c_base64Decode_mba_bs a ptr (fromIntegral ptrlen)) st0
            !(# st2, b #) = unsafeFreezeByteArray# a st1
         in if err /= 0
            then (# st2, Nothing #)
            else (# st2, Just (HashString (SBS b)) #)
  where
    ptrlen = B.length str - base64PadLength_bs str

-- TODO: implement these functions better

toBase16Builder :: HashString -> Builder
toBase16Builder = shortByteString . toShortBase16

toBase64Builder :: HashString -> Builder
toBase64Builder = shortByteString . toShortBase64
