{-# LANGUAGE MagicHash, UnboxedTuples, OverloadedStrings, ScopedTypeVariables,
             BangPatterns, LambdaCase #-}

module Crypto.Sha256
  ( hash
  , hash'
  , Sha256Ctx()
  , sha256_init
  , sha256_update,  sha256_feed
  , sha256_updates, sha256_feeds
  , sha256_byteCount
  , sha256_blockCount
  , sha256_bufferLength
  , sha256_state
  , sha256_finalize     , sha256_finalize_toByteString
  , sha256_finalizeBits , sha256_finalizeBits_toByteString
  , sha256_finalizeBytes, sha256_finalizeBytes_toByteString
  ) where

import           Data.Array.Byte
import           Data.Bits((.&.), shiftR)
import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import           Data.ByteString.Internal (unsafeCreate)
import           Data.ByteString.Unsafe(unsafeUseAsCString, unsafeUseAsCStringLen)
import           Data.Foldable(foldl')
import           Data.Function((&))
import           Data.Word
import           GHC.Exts
import           GHC.IO

import           Crypto.HashString
import           Crypto.HashString.Subtle
import           Crypto.Sha256.Subtle

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
     in (# st2, Sha256Ctx (ByteArray b) #)

sha256_byteCount :: Sha256Ctx -> Word64
sha256_byteCount (Sha256Ctx (ByteArray ctx)) = c_sha256_get_count ctx

sha256_blockCount :: Sha256Ctx -> Word64
sha256_blockCount ctx = sha256_byteCount ctx `shiftR` 6

sha256_bufferLength :: Sha256Ctx -> Word8
sha256_bufferLength ctx = fromIntegral (sha256_byteCount ctx .&. 0x3F)

sha256_state :: Sha256Ctx -> HashString
sha256_state = sha256state_encode . sha256state_fromCtxInplace

sha256_update :: Sha256Ctx -> ByteString -> Sha256Ctx
sha256_update ctx0@(Sha256Ctx (ByteArray ctx)) bytes
  | B.null bytes = ctx0
  | otherwise =
    unsafePerformIO $ do
      let count = c_sha256_get_count ctx + fromIntegral (B.length bytes)
      let !(I# bufLen#) = 40 + fromIntegral (count .&. 0x3F)
      unsafeUseAsCStringLen bytes $ \(bp,bl) -> IO $ \st ->
        let !(# st0, a #) = newByteArray# bufLen# st
            !(# st1, _ #) = unIO (c_sha256_update_ctx ctx bp (fromIntegral bl) a) st0
            !(# st2, b #) = unsafeFreezeByteArray# a st1
         in  (# st2, Sha256Ctx (ByteArray b) #)

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
sha256_finalizeBits bits bitlen0 (Sha256Ctx (ByteArray ctx)) =
    unsafePerformIO . unsafeUseAsCString bits $ \bp -> IO $ \st ->
      let !(# st0, a #) = newByteArray# 32# st
          !(# st1, () #) = unIO (c_sha256_finalize_ctx_bits_ba ctx bp bitlen a) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in (# st2, HashString (ByteArray b) #)
  where
    bitlen = min (fromIntegral (B.length bits) * 8) bitlen0

sha256_finalizeBits_toByteString :: ByteString -> Word64 -> Sha256Ctx -> ByteString
sha256_finalizeBits_toByteString bits bitlen0 (Sha256Ctx (ByteArray ctx)) =
    unsafeCreate 32 $ \rp ->
      unsafeUseAsCString bits $ \bp ->
        c_sha256_finalize_ctx_bits ctx bp bitlen rp
  where
    bitlen = min (fromIntegral (B.length bits) * 8) bitlen0

sha256_finalizeBytes :: ByteString -> Sha256Ctx -> HashString
sha256_finalizeBytes = flip sha256_finalizeBits maxBound

sha256_finalizeBytes_toByteString :: ByteString -> Sha256Ctx -> ByteString
sha256_finalizeBytes_toByteString = flip sha256_finalizeBits_toByteString maxBound
