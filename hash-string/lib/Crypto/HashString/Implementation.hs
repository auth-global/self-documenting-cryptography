{-# LANGUAGE MagicHash, UnboxedTuples, CApiFFI, UnliftedFFITypes, BangPatterns, LambdaCase, GeneralizedNewtypeDeriving #-}

module Crypto.HashString.Implementation where

import           Data.Array.Byte
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

-- | Type intended to represent short-ish cryptographic values, say up to 128
--   bytes or so. Supports constant-time comparisons (i.e. run time depends on
--   length of the inputs but is otherwise independent of content), as well as
--   constant-time base16 and base64 conversions.

newtype HashString = HashString { unHashString :: ByteArray } deriving (Semigroup, Monoid)

instance Eq HashString where
  x == y = compare x y == EQ

instance Ord HashString where
  compare (HashString (ByteArray x)) (HashString (ByteArray y)) =
      compare (c_const_memcmp_ba x y minlen) 0
        <> compare xlen ylen
    where
      xlen = SB.length (SBS x)
      ylen = SB.length (SBS y)
      minlen = fromIntegral (min xlen ylen)

instance IsString HashString where
  fromString = \case
      ( 'b' : '1' : '6' : ' ' : xs ) -> doBase16 xs
--      ( 'b' : '6' : '4' : ' ' : xs ) -> doBase64 xs
      xs -> doBase16 xs
    where
      doBase16 = fromMaybe err . fromShortBase16 . SB.pack . map myConv
        where
          err = error "fromString :: String -> HashString  --  base16 syntax error"
          myConv x = if Char.isHexDigit x then c2w x else err
{--
      doBase64 = fromMaybe err . fromShortBase64 . SB.pack . map myConv
        where
          err = error "fromString :: String -> HashString  --  base64 syntax error"
          myConv x = if Char.isAscii x then c2w x else err
--}

instance Show HashString where
  show xs = '"': enc xs ++ ['"']
    where
      enc = map w2c . SB.unpack . toShortBase16

-- | Xor two hashstrings. The length of the result is always the same as the
--   length of the left argument; bytes are either removed from or added to the
--   end of the right argument as needed to match length.

xorLeft :: HashString -> HashString -> HashString
xorLeft (HashString strl@(ByteArray ptrl)) (HashString strr@(ByteArray ptrr))
  | compareInt# 0# (unsafePtrEquality# ptrl ptrr) /= EQ = fromShort (SB.replicate (SB.length (SBS ptrl)) 0)
  | otherwise =
    unsafePerformIO . IO $ \st ->
      let !lenl0@(I# lenl) = SB.length (SBS ptrl)
          !lenr0@(I# lenr) = SB.length (SBS ptrr)
          !(# st0, a #) = newByteArray# lenl st
          !(# st1, () #) = unIO (c_xorleft_ba ptrl (fromIntegral lenl0) ptrr (fromIntegral lenr0) a) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in  (# st2, HashString (ByteArray b) #)

-- | Xor two hashstrings. The length of the result is always the same as the
--   length of the shorter argument, removing bytes from the end of the longer
--   string as needed to match length.

xorMin :: HashString -> HashString -> HashString
xorMin (HashString strl@(ByteArray ptrl)) (HashString strr@(ByteArray ptrr))
  | compareInt# 0# (unsafePtrEquality# ptrl ptrr) /= EQ = fromShort (SB.replicate (SB.length (SBS ptrl)) 0)
  | otherwise =
    unsafePerformIO . IO $ \st ->
      let !minlen0@(I# minlen) = min (SB.length (SBS ptrl)) (SB.length (SBS ptrr))
          !(# st0, a #) = newByteArray# minlen st
          !(# st1, () #) = unIO (c_xormin_ba ptrl ptrr (fromIntegral minlen0) a) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in  (# st2, HashString (ByteArray b) #)

-- | Xor two hashstrings.  The length of the result is always the same as the
--   length of the longer argument, adding null bytes onto the end of the
--   shorter string as needed to match length.

xorMax :: HashString -> HashString -> HashString
xorMax (HashString strl@(ByteArray ptrl)) (HashString strr@(ByteArray ptrr))
  | compareInt# 0# (unsafePtrEquality# ptrl ptrr) /= EQ = fromShort (SB.replicate (SB.length (SBS ptrl)) 0)
  | otherwise =
    unsafePerformIO . IO $ \st ->
      let !lenl = SB.length (SBS ptrl)
          !lenr = SB.length (SBS ptrr)
          !(I# maxlen) = max lenl lenr
          !(# st0, a #) = newByteArray# maxlen st
          !(# st1, () #) = unIO (c_xormax_ba ptrl (fromIntegral lenl) ptrr (fromIntegral lenr) a) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in  (# st2, HashString (ByteArray b) #)

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
            else (# st2, Just (HashString (ByteArray b)) #)
  where
    ptrlen = SB.length str

toShortBase16 :: HashString -> ShortByteString
toShortBase16 (HashString str@(ByteArray ptr)) =
    unsafePerformIO . IO $ \st ->
      let !(I# outlen) = ptrlen * 2
          !(# st0, a #) = newByteArray# outlen st
          !(# st1, () #) = unIO (c_hexEncode_ba a ptr (fromIntegral ptrlen)) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in  (# st2, SBS b #)
  where
    ptrlen = SB.length (SBS ptr)

{--
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
            else (# st2, Just (HashString (ByteArray b)) #)
  where
    ptrlen0 = SB.length str
    ptrlen  = ptrlen0 - fromIntegral (c_base64PadLength_ba ptr (fromIntegral ptrlen0))

toShortBase64 :: HashString -> ShortByteString
toShortBase64 (HashString str@(ByteArray ptr)) =
    unsafePerformIO . IO $ \st ->
      let !(I# outlen) = base64EncodeLength ptrlen
          !(# st0, a #) = newByteArray# outlen st
          !(# st1, () #) = unIO (c_base64Encode_ba a ptr (fromIntegral ptrlen)) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in  (# st2, SBS b #)
  where
    ptrlen = SB.length (SBS ptr)
--}

toShort :: HashString -> ShortByteString
toShort (HashString (ByteArray x)) = SBS x

fromShort :: ShortByteString -> HashString
fromShort (SBS x) = HashString (ByteArray x)

toByteString :: HashString -> ByteString
toByteString = SB.fromShort . toShort

fromByteString :: ByteString -> HashString
fromByteString = fromShort . SB.toShort

toBase16 :: HashString -> ByteString
toBase16 (HashString str@(ByteArray ptr)) =
    unsafeCreate (base16EncodeLength ptrlen) $ \out ->
      c_hexEncode_bs_ba out ptr (fromIntegral ptrlen)
  where
    ptrlen = SB.length (SBS ptr)

{--
toBase64 :: HashString -> ByteString
toBase64 (HashString str@(ByteArray ptr)) =
    unsafeCreate (base64EncodeLength ptrlen) $ \out ->
      c_base64Encode_bs_ba out ptr (fromIntegral ptrlen)
  where
    ptrlen = SB.length (SBS ptr)
--}

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
            else (# st2, Just (HashString (ByteArray b)) #)
  where
    ptrlen = B.length str

{--
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
            else (# st2, Just (HashString (ByteArray b)) #)
  where
    ptrlen = B.length str - base64PadLength_bs str
--}

-- TODO: implement these functions better

toBase16Builder :: HashString -> Builder
toBase16Builder = shortByteString . toShortBase16

{--
toBase64Builder :: HashString -> Builder
toBase64Builder = shortByteString . toShortBase64
--}

base16EncodeLength :: Int -> Int
base16EncodeLength = (*) 2

base16DecodeLength :: Int -> Maybe Int
base16DecodeLength n
    | r == 0 = Just q
    | otherwise = Nothing
  where
    (q,r) = n `divMod` 2

foreign import capi unsafe "hs_hashstring_memcmp.h hs_hashstring_const_memcmp"
  c_const_memcmp_ba
    :: ByteArray#
    -> ByteArray#
    -> CSize
    -> CInt

foreign import capi unsafe "hs_hashstring_base16.h hs_hashstring_hexDecode"
  c_hexDecode_ba
    :: MutableByteArray# RealWorld
    -> ByteArray#
    -> CSize
    -> IO CInt

foreign import capi unsafe "hs_hashstring_base16.h hs_hashstring_hexDecode"
  c_hexDecode_mba_bs
    :: MutableByteArray# RealWorld
    -> CString
    -> CSize
    -> IO CInt

foreign import capi unsafe "hs_hashstring_base16.h hs_hashstring_hexEncode"
  c_hexEncode_ba
    :: MutableByteArray# RealWorld
    -> ByteArray#
    -> CSize
    -> IO ()

foreign import capi unsafe "hs_hashstring_base16.h hs_hashstring_hexEncode"
  c_hexEncode_bs_ba
    :: Ptr Word8
    -> ByteArray#
    -> CSize
    -> IO ()

foreign import capi unsafe "hs_hashstring_xor.h hs_hashstring_xorleft"
  c_xorleft_ba
    :: ByteArray#
    -> CSize
    -> ByteArray#
    -> CSize
    -> MutableByteArray# RealWorld
    -> IO ()

foreign import capi unsafe "hs_hashstring_xor.h hs_hashstring_xormin"
  c_xormin_ba
    :: ByteArray#
    -> ByteArray#
    -> CSize
    -> MutableByteArray# RealWorld
    -> IO ()

foreign import capi unsafe "hs_hashstring_xor.h hs_hashstring_xormax"
  c_xormax_ba
    :: ByteArray#
    -> CSize
    -> ByteArray#
    -> CSize
    -> MutableByteArray# RealWorld
    -> IO ()
