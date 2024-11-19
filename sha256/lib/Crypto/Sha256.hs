{-# LANGUAGE MagicHash, UnboxedTuples, OverloadedStrings, ScopedTypeVariables #-}

module Crypto.Sha256
  ( hash
  , Sha256Ctx()
  , sha256_init
  , sha256_update
  , sha256_feed
  , sha256_updates
  , sha256_byteCount
  , sha256_blockCount
  , sha256_bufferLength
  , sha256_finalize
  , sha256_finalizeBits
  ) where

import Data.Bits((.&.), shiftR)
import Data.ByteString(ByteString)
import qualified Data.ByteString as B
import Data.ByteString.Unsafe(unsafeUseAsCString, unsafeUseAsCStringLen)
import Data.Foldable(foldl')
import Data.Function((&))
import Data.Word
import Foreign.C
import GHC.Exts
import GHC.Prim(RealWorld)
import GHC.IO
import System.IO.Unsafe

import Crypto.Sha256.Subtle

hash :: ByteString -> ByteString
hash x = sha256_init & sha256_finalizeBits x maxBound

sha256_init :: Sha256Ctx
sha256_init =
  unsafePerformIO . IO $ \st ->
    let (# st0, a #) = newByteArray# 40# st
        (# st1, _ #) = unIO (c_sha256_init_ctx a) st0
        (# st2, b #) = unsafeFreezeByteArray# a st1
     in (# st2, Sha256Ctx# b #)

sha256_byteCount :: Sha256Ctx -> Word64
sha256_byteCount (Sha256Ctx# ctx) =
   unsafeDupablePerformIO (c_sha256_get_count ctx)

sha256_blockCount :: Sha256Ctx -> Word64
sha256_blockCount ctx = sha256_byteCount ctx `shiftR` 6

sha256_bufferLength :: Sha256Ctx -> Word8
sha256_bufferLength ctx = fromIntegral (sha256_byteCount ctx .&. 0x3F)

sha256_update :: Sha256Ctx -> ByteString -> Sha256Ctx
sha256_update ctx0@(Sha256Ctx# ctx) bs
  | B.null bs = ctx0
  | otherwise = unsafePerformIO $ do
      count <- c_sha256_get_count ctx
      let (I# bufLen#) = 40 + fromIntegral ((count + fromIntegral (B.length bs)) .&. 0x3F)
      unsafeUseAsCStringLen bs $ \(bp,bl) -> IO $ \st ->
        let (# st'0, a #) = newByteArray# bufLen# st
            (# st'1, _ #) = unIO (c_sha256_update_ctx ctx bp (fromIntegral bl) a) st'0
            (# st'2, b #) = unsafeFreezeByteArray# a st'1
         in (# st'2, Sha256Ctx# b #)

sha256_updates :: Foldable f => Sha256Ctx -> f ByteString -> Sha256Ctx
sha256_updates = foldl' sha256_update 

sha256_feed :: ByteString -> Sha256Ctx -> Sha256Ctx
sha256_feed = flip sha256_update

sha256_finalize :: Sha256Ctx -> ByteString
sha256_finalize = sha256_finalizeBits B.empty 0

sha256_finalizeBits :: ByteString -> Word64 -> Sha256Ctx -> ByteString
sha256_finalizeBits bits bitlen0 (Sha256Ctx# ctx) =
    unsafePerformIO $ do
      let result = B.replicate 32 0
      unsafeUseAsCString result $ \rp ->
        unsafeUseAsCString bits $ \bp -> do
          c_sha256_finalize_ctx_bits ctx bp bitlen rp
          return result
  where bitlen = min (fromIntegral (B.length bits) * 8) bitlen0

