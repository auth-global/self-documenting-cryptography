{-# LANGUAGE MagicHash, CApiFFI, UnliftedFFITypes #-}

module Crypto.HashString.FFI where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.ByteString.Internal (c2w)
import           Data.Word
import           Foreign.C
import           Foreign.Ptr
import           GHC.Exts
import           GHC.IO

-- | Given the length of some binary blob of data, how long will the base64 encoded
--   version be, without padding?

-- There's probably a "cleaner" way to compute this with bit tricks
base64EncodeLength :: Int -> Int
base64EncodeLength n =
    4 * q + if r == 0 then 0 else 1 + r
  where
    (q,r) = n `divMod` 3

-- | Given the length of some base64 encoded data, how long will the binar blob be?
--   The input length must not include any padding, commonly appearing as one or
--   two @=@ characters at the end of a string.

-- There's probably a "cleaner" way to compute this with bit tricks
base64DecodeLength :: Int -> Maybe Int
base64DecodeLength n
    | r == 0 = Just (3 * q)
    | r == 1 = Nothing
    | otherwise = Just ((3 * q) + (r - 1))
  where
    (q,r) = n `divMod` 4

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

foreign import capi unsafe "hs_hashstring_base64.h hs_hashstring_base64Decode"
  c_base64Decode_ba
    :: MutableByteArray# RealWorld
    -> ByteArray#
    -> CSize
    -> IO CInt

foreign import capi unsafe "hs_hashstring_base64.h hs_hashstring_base64Decode"
  c_base64Decode_mba_bs
    :: MutableByteArray# RealWorld
    -> CString
    -> CSize
    -> IO CInt

foreign import capi unsafe "hs_hashstring_base64.h hs_hashstring_base64Encode"
  c_base64Encode_ba
    :: MutableByteArray# RealWorld
    -> ByteArray#
    -> CSize
    -> IO ()

foreign import capi unsafe "hs_hashstring_base64.h hs_hashstring_base64Encode"
  c_base64Encode_bs_ba
    :: Ptr Word8
    -> ByteArray#
    -> CSize
    -> IO ()

foreign import capi unsafe "hs_hashstring_base64.h hs_hashstring_base64PadLength"
  c_base64PadLength_ba
    :: ByteArray#
    -> CSize
    -> CInt

base64PadLength_bs :: ByteString -> Int
base64PadLength_bs xs = min 2 (B.length (B.takeWhileEnd ((==) (c2w '=')) xs))