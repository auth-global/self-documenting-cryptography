{-# LANGUAGE MagicHash, UnboxedTuples, OverloadedStrings, ScopedTypeVariables #-}

module Crypto.Sha256
  ( hash
  , HashString(..)
  , hashString_toShort
  , hashString_toShortBase16
  , hashString_toByteString
  , hashString_toBase16
  , Sha256Ctx()
  , sha256_init
  , sha256_update,  sha256_feed
  , sha256_updates, sha256_feeds
  , sha256_byteCount
  , sha256_blockCount
  , sha256_bufferLength
  , sha256_state
  , sha256_finalize
  , sha256_finalizeBits
  , sha256_hashFinalBitString
  ) where

import           Data.Base16.Types
import           Data.Bits((.&.), shiftR)
import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import           Data.ByteString.Internal (w2c)
import qualified Data.ByteString.Base16 as B
import           Data.ByteString.Short.Internal(ShortByteString(..))
import qualified Data.ByteString.Short as SB
import qualified Data.ByteString.Short.Base16 as SB
import           Data.ByteString.Unsafe(unsafeUseAsCString, unsafeUseAsCStringLen)

import Data.Foldable(foldl')
import Data.Function((&))
import Data.Word
import Foreign.C
import GHC.Exts
import GHC.Prim(RealWorld)
import GHC.IO
import System.IO.Unsafe

import Crypto.Sha256.Subtle
import qualified Crypto.Hash.SHA256 as SHA256

newtype HashString = HashString { unHashString :: ShortByteString }

instance Eq HashString where
  x == y = compare x y == EQ

instance Ord HashString where
  compare (HashString xsbs@(SBS x)) (HashString ysbs@(SBS y)) =
      case compare (c_const_memcmp x y minlen) 0 of
        EQ -> compare xlen ylen
        cmp -> cmp
    where
      xlen = SB.length xsbs
      ylen = SB.length ysbs
      minlen = fromIntegral (min xlen ylen)

hashString_toShort :: HashString -> ShortByteString
hashString_toShort = unHashString

hashString_toByteString :: HashString -> ByteString
hashString_toByteString = SB.fromShort . unHashString

-- FIXME! replace this with algorithms that are constant time independent of content
-- Perhaps this would be a reasonable option:

-- https://github.com/Sc00bz/ConstTimeEncoding

-- TODO: add decoding, and support for Base64

-- TODO: add instance IsString HashString

hashString_toShortBase16 :: HashString -> ShortByteString
hashString_toShortBase16 = extractBase16 . SB.encodeBase16' . hashString_toShort

hashString_toBase16 :: HashString -> ByteString
hashString_toBase16 = SB.fromShort . hashString_toShortBase16

-- TODO: there are a number of magic literals scattered throughout that
-- really ought to refer to a symbolic constant of some sort

hash :: ByteString -> ByteString
hash x = sha256_init & sha256_finalizeBits x maxBound

sha256_init :: Sha256Ctx
sha256_init =
  unsafePerformIO . IO $ \st ->
    let (# st0, a #) = newByteArray# 40# st
        (# st1, _ #) = unIO (c_sha256_init_ctx a) st0
        (# st2, b #) = unsafeFreezeByteArray# a st1
     in (# st2, Sha256Ctx b SHA256.init #)

sha256_byteCount :: Sha256Ctx -> Word64
sha256_byteCount (Sha256Ctx ctx _) = c_sha256_get_count ctx

sha256_blockCount :: Sha256Ctx -> Word64
sha256_blockCount ctx = sha256_byteCount ctx `shiftR` 6

sha256_bufferLength :: Sha256Ctx -> Word8
sha256_bufferLength ctx = fromIntegral (sha256_byteCount ctx .&. 0x3F)

encodeB16 = extractBase16 . SB.encodeBase16

sha256_state :: Sha256Ctx -> HashString
sha256_state = HashString . sha256state_encode . sha256state_fromCtxInplace

sha256_update :: Sha256Ctx -> ByteString -> Sha256Ctx
sha256_update ctx0@(Sha256Ctx ctx aux) bytes
  | B.null bytes = ctx0
  | otherwise = unsafePerformIO $ do
      let count = c_sha256_get_count ctx + fromIntegral (B.length bytes)
      let (I# bufLen#) = 40 + fromIntegral (count .&. 0x3F)
      unsafeUseAsCStringLen bytes $ \(bp,bl) -> IO $ \st ->
        let (# st'0, a #) = newByteArray# bufLen# st
            (# st'1, _ #) = unIO (c_sha256_update_ctx ctx bp (fromIntegral bl) a) st'0
            (# st'2, b #) = unsafeFreezeByteArray# a st'1
            aux' = SHA256.update aux bytes
            ctx' = Sha256Ctx b aux'
         in if sha256ctx_cryptohash_ctx_eq ctx' aux'
            then (# st'2, ctx' #)
            else error ("sha256_update output contexts not equal:"
                   ++ "\n ctx' st: " ++ map w2c (SB.unpack (extractBase16 (SB.encodeBase16' (sha256state_encode (sha256state_fromCtx ctx')))))
                   ++ "\n       n: " ++ show (sha256_byteCount ctx')
                   ++ "\n aux' st: " ++ map w2c (SB.unpack (extractBase16 (SB.encodeBase16' (sha256_cryptohash_ctx_encode aux'))))
                   ++ "\n  bytes: " ++ show bytes ++ "\n")
sha256_updates :: Foldable f => Sha256Ctx -> f ByteString -> Sha256Ctx
sha256_updates = foldl' sha256_update

sha256_feed :: ByteString -> Sha256Ctx -> Sha256Ctx
sha256_feed = flip sha256_update

sha256_feeds :: Foldable f => f ByteString -> Sha256Ctx -> Sha256Ctx
sha256_feeds = flip sha256_updates

sha256_finalize :: Sha256Ctx -> ByteString
sha256_finalize = sha256_finalizeBits B.empty 0

sha256_finalizeBits :: ByteString -> Word64 -> Sha256Ctx -> ByteString
sha256_finalizeBits bits bitlen0 ctx0@(Sha256Ctx ctx aux)
    | out == out' = out'
    | otherwise = error (    "sha256_finalizeBits: output hashes not equal"
                        ++ "\n  out  " ++ map w2c (B.unpack (extractBase16 (B.encodeBase16' out)))
                        ++ "\n  out' " ++ map w2c (B.unpack (extractBase16 (B.encodeBase16' out')))
                        ++ "\n")
  where
    bitlen = min (fromIntegral (B.length bits) * 8) bitlen0

    out = unsafePerformIO $ do
      unsafeUseAsCString bits $ \bp -> do
        let result = B.replicate 32 (bp `seq` 0)
        unsafeUseAsCString result $ \rp -> do
          c_sha256_finalize_ctx_bits ctx bp bitlen rp
          return result

    out' = SHA256.finalizeBits aux bits (fromIntegral bitlen0)

sha256_hashFinalBitString :: ByteString -> Word64 -> Sha256Ctx -> HashString
sha256_hashFinalBitString bits bitlen0 (Sha256Ctx ctx _) =
    unsafePerformIO . unsafeUseAsCString bits $ \bp -> IO $ \st ->
      let (# st0, a #) = newByteArray# 32# st
          (# st1, () #) = unIO (c_sha256_finalize_ctx_bits_ba ctx bp bitlen a) st0
          (# st2, b #) = unsafeFreezeByteArray# a st1
       in (# st2, HashString (SBS b) #)
  where
    bitlen = min (fromIntegral (B.length bits) * 8) bitlen0