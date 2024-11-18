{-# LANGUAGE ForeignFunctionInterface, CApiFFI, MagicHash, UnboxedTuples, UnliftedFFITypes,
             OverloadedStrings, ScopedTypeVariables
#-}

module Crypto.Sha256.Subtle.FFI where

import Data.Bits((.&.), shiftR)
import Data.ByteString(ByteString)
import Data.Word
import qualified Data.ByteString as B
import Data.ByteString.Unsafe(unsafeUseAsCString, unsafeUseAsCStringLen)
import Foreign.C
import GHC.Exts
import GHC.Prim(RealWorld)
import GHC.IO
import System.IO.Unsafe

import Crypto.Sha256.Subtle


-- these calls must be labelled "unsafe", because the datastructures
-- we will be passing in are unpinned... keep that in mind when selecting
-- the size of the updates.  (Also, maybe in some cases a different FFI
-- layer that uses safe calls would be desirable?  Maybe not... It seems like
-- it should be possible to adequately work around the limitations of
-- long-lived unsafe calls by using smaller updates, making more calls to C.)

-- See the documentation for details:
-- https://ghc.gitlab.haskell.org/ghc/doc/users_guide/exts/ffi.html#guaranteed-call-safety

foreign import capi unsafe "hs_sha256.h hs_sha256_init_ctx"
    c_sha256_init_ctx :: Sha256MutCtxPtr# RealWorld -> IO ()

{-
foreign import capi unsafe "hs_sha256.h hs_sha256_update" c_sha256_update
    :: Sha256CtxPtr# -- ^ @state@, a pointer to an constant array of eight Word32
    -> Word64 -- ^ @count@, the number of bytes that a sha256 context has seen
    -> Ptr Word8 -- ^ @buffer@, a pointer to 0-63 constant bytes representing the unprocessed data seen by the context. The length is encoded by the least six significant bits of @count@.
    -> CString -- ^ pointer to the constant data to process
    -> CSize -- ^ length of the data to process
    -> Sha256MutStatePtr# -- ^ output pointer
    -> IO Word64 -- ^ the new @count@

foreign import capi unsafe "hs_sha256.h hs_sha256_update" c_sha256_mutate
    :: Sha256MutStatePtr -- ^ @state@, a pointer to an constant array of eight Word32
    -> Word64 -- ^ @count@, the number of bytes that a sha256 context has seen
    -> Ptr Word8 -- ^ @buffer@, a pointer to 0-63 constant bytes representing the unprocessed data seen by the context. The length is encoded by the least six significant bits of @count@.
    -> CString -- ^ pointer to the constant data to process
    -> CSize -- ^ length of the data to process
    -> Sha256 -- ^ output pointer, may be same as input pointer
    -> IO Word64 -- ^ the new @count@
-}
foreign import capi unsafe "hs_sha256.h hs_sha256_update_ctx"
  c_sha256_update_ctx
    :: Sha256CtxPtr# -- ^ @ctx@, a pointer to a constant sha256 context
    -> CString -- ^ pointer to the constant data to process
    -> CSize -- ^ length of the data to process
    -> Sha256MutCtxPtr# RealWorld -- ^ output pointer
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_update_ctx"
  c_sha256_mutate_ctx
    :: Sha256MutCtxPtr# RealWorld -- ^ @ctx@, a pointer to a constant sha256 context
    -> CString -- ^ pointer to the constant data to process
    -> CSize -- ^ length of the data to process
    -> Sha256MutCtxPtr# RealWorld -- ^ output pointer, can be same as the input context
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_encode_state"
  c_sha256_encode_state
    :: Sha256StatePtr#
    -> MutableByteArray# RealWorld
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_encode_state"
  c_sha256_encode_mutable_state
    :: Sha256MutStatePtr# RealWorld
    -> MutableByteArray# RealWorld
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_decode_state"
  c_sha256_decode_state
    :: ByteArray#
    -> Sha256MutStatePtr# RealWorld
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_get_count"
  c_sha256_get_count
    :: ByteArray#
    -> IO Word64

foreign import capi unsafe "hs_sha256.h hs_sha256_finalize_ctx_bits"
  c_sha256_finalize_ctx_bits
    :: Sha256CtxPtr#
    -> CString
    -> Word64
    -> CString
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_finalize_ctx_bits"
  c_sha256_finalize_mutable_ctx_bits
    :: Sha256MutCtxPtr# RealWorld
    -> CString
    -> Word64
    -> CString
    -> IO ()

sha256_init :: Sha256Ctx
sha256_init =
  unsafePerformIO . IO $ \st ->
    let (# st0, a #) = newByteArray# 40# st -- (#{size sha256_ctx}) st
        (# st1, _ #) = unIO (c_sha256_init_ctx a) st0
        (# st2, b #) = unsafeFreezeByteArray# a st1
     in (# st2, Sha256Ctx# b #)

sha256_byteCount :: Sha256Ctx -> Word64
sha256_byteCount (Sha256Ctx# ctx#) =
   unsafeDupablePerformIO (c_sha256_get_count ctx#)

sha256_blockCount :: Sha256Ctx -> Word64
sha256_blockCount ctx = sha256_byteCount ctx `shiftR` 6

sha256_bufferLength :: Sha256Ctx -> Word8
sha256_bufferLength ctx = fromIntegral (sha256_byteCount ctx .&. 0x3F)

sha256_update :: ByteString -> Sha256Ctx -> Sha256Ctx
sha256_update bs ctx@(Sha256Ctx# ctx#)
  | B.null bs = ctx
  | otherwise = unsafePerformIO $ do
      count <- c_sha256_get_count ctx#
      let (I# bufLen#) = 40 + fromIntegral ((count + fromIntegral (B.length bs)) .&. 0x3F)
      unsafeUseAsCStringLen bs $ \(bp,bl) -> IO $ \st ->
        let (# st'0, a #) = newByteArray# bufLen# st
            -- FIXME: Review this instance of "fromIntegral" more carefully
            (# st'1, _ #) = unIO (c_sha256_update_ctx ctx# bp (fromIntegral bl) a) st'0
            (# st'2, b #) = unsafeFreezeByteArray# a st'1
         in (# st'2, Sha256Ctx# b #)

sha256_finalizeBits :: ByteString -> Word64 -> Sha256Ctx -> ByteString
sha256_finalizeBits bits bitlen0 (Sha256Ctx# ctx) =
    unsafePerformIO $ do
      let result = B.replicate 32 0
      unsafeUseAsCString result $ \rp ->
        unsafeUseAsCString bits $ \bp -> do
          c_sha256_finalize_ctx_bits ctx bp bitlen rp
          return result
  where bitlen = min (fromIntegral (B.length bits) * 8) bitlen0
