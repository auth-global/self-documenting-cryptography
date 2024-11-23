{-# LANGUAGE MagicHash, CApiFFI, UnliftedFFITypes #-}

module Crypto.HashString.FFI where

import Data.Word
import Foreign.C
import Foreign.Ptr
import GHC.Exts
import GHC.IO

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

foreign import capi unsafe "hs_hashstring_base16.h hs_hashstring_hexEncode"
  c_hexEncode_ba
    :: MutableByteArray# RealWorld
    -> ByteArray#
    -> CSize
    -> IO ()

foreign import capi unsafe "hs_hashstring_base64.h hs_hashstring_base64Decode"
  c_base64Decode_ba
    :: MutableByteArray# RealWorld
    -> ByteArray#
    -> CSize
    -> IO CInt

foreign import capi unsafe "hs_hashstring_base64.h hs_hashstring_base64Encode"
  c_base64Encode_ba
    :: MutableByteArray# RealWorld
    -> ByteArray#
    -> CSize
    -> IO ()
