{-# LANGUAGE OverloadedStrings, BangPatterns, ScopedTypeVariables #-}

module Crypto.PHKDF.Primitives
  ( PhkdfCtx()
  , HmacKey()
  , hmacKey_init
  , phkdfCtx_init
  , phkdfCtx_initFromHmacKey
  , phkdfCtx_hmacKey
  , phkdfCtx_hmacCtx
  , phkdfCtx_reset
  , phkdfCtx_addArg
  , phkdfCtx_addArgs
  , phkdfCtx_finalize
  , phkdfCtx_finalizeHmac
  , phkdfCtx_finalizeHmacCtx
  , phkdfCtx_finalizeStream
  , PhkdfSlowCtx()
  , phkdfSlowCtx_extract
  , phkdfSlowCtx_addArg
  , phkdfSlowCtx_addArgs
  , phkdfSlowCtx_finalize
  , phkdfSlowCtx_finalizeStream
  ) where

import           Data.Bits((.&.))
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Function((&))
import           Data.Foldable(Foldable, foldl')
import           Data.Int
import           Data.Word
import           Data.Stream (Stream(..))
import qualified Data.Stream as Stream
import           Network.ByteOrder (bytestring32)

import           Crypto.PHKDF.HMAC
import           Crypto.PHKDF.HMAC.Subtle
import           Crypto.PHKDF.Primitives.Subtle
import           Crypto.Encoding.PHKDF
import           Crypto.Encoding.SHA3.TupleHash

phkdfCtx_init :: ByteString -> PhkdfCtx
phkdfCtx_init = phkdfCtx_initFromHmacKey . hmacKey_init

phkdfCtx_initFromHmacKey :: HmacKey -> PhkdfCtx
phkdfCtx_initFromHmacKey key =
  PhkdfCtx {
    phkdfCtx_byteLen = 0,
    phkdfCtx_state   = hmacKey_ipad key,
    phkdfCtx_hmacKey = key
  }

phkdfCtx_reset :: PhkdfCtx -> PhkdfCtx
phkdfCtx_reset = phkdfCtx_initFromHmacKey . phkdfCtx_hmacKey

phkdfCtx_hmacCtx :: PhkdfCtx -> HmacCtx
phkdfCtx_hmacCtx = hmacKey_run . phkdfCtx_hmacKey

-- FIXME? what should happen when the SHA256 counters overflow?

phkdfCtx_addArg :: ByteString -> PhkdfCtx -> PhkdfCtx
phkdfCtx_addArg b ctx = phkdfCtx_unsafeFeed [ leftEncodeFromBytes (B.length b), b ] ctx

phkdfCtx_addArgs :: Foldable f => f ByteString -> PhkdfCtx -> PhkdfCtx
phkdfCtx_addArgs params ctx = foldl' (flip phkdfCtx_addArg) ctx params

phkdfCtx_finalize :: Word32 -> ByteString -> PhkdfCtx -> ByteString
phkdfCtx_finalize counter tag ctx = Stream.head (phkdfCtx_finalizeStream counter tag ctx)

phkdfCtx_finalizeHmacCtx :: PhkdfCtx -> HmacCtx
phkdfCtx_finalizeHmacCtx ctx =
  (phkdfCtx_hmacCtx ctx) {
    hmacCtx_ipad = phkdfCtx_state ctx
  }

phkdfCtx_finalizeHmac :: PhkdfCtx -> ByteString
phkdfCtx_finalizeHmac = hmacCtx_finalize . phkdfCtx_finalizeHmacCtx

phkdfCtx_finalizeStream :: Word32 -> ByteString -> PhkdfCtx -> Stream ByteString
phkdfCtx_finalizeStream counter0 tag ctx = go counter0 hmacState0
  where
    -- we want to add 1-64 padding bytes to land on a half-block boundary
    n = phkdfCtx_byteLen ctx
    endPadLen = fromIntegral (64 - ((n - 32) .&. 63))

    endPadding = cycleByteStringToList endPadLen ("\x00" <> tag)

    seguidCtx = phkdfCtx_hmacCtx ctx

    hmacState0 =
        phkdfCtx_finalizeHmacCtx ctx &
        hmacCtx_updates endPadding

    go !counter hmacState = Cons nextBlock (go (counter + 1) hmacState')
      where
        !nextBlock =
            hmacState &
            hmacCtx_updates [bytestring32 counter, tag] &
            hmacCtx_finalize
        hmacState' =
            seguidCtx &
            hmacCtx_update nextBlock

phkdfSlowCtx_extract :: ByteString -> Word32 -> Word32 -> ByteString -> PhkdfCtx -> PhkdfSlowCtx
phkdfSlowCtx_extract fnName rounds counter tag ctx0 = out
  where
    (Cons block0 innerStream) = phkdfCtx_finalizeStream counter tag ctx0

    phkdfLen = ((fromIntegral rounds :: Int64) + 1) * 512
    phkdfLenTag = leftEncode phkdfLen

    extFnNameLen = 30 - B.length phkdfLenTag

    extFnName = cycleByteStringWithNull extFnNameLen fnName

    outerCtx =
        phkdfCtx_reset ctx0 &
        phkdfCtx_addArg extFnName &
        phkdfCtx_unsafeFeed [phkdfLenTag, block0]

    fillerTag = cycleByteStringWithNull 32 tag

    go n !ctx (Cons block stream)
      | n <= 0 = PhkdfSlowCtx {
         phkdfSlowCtx_phkdfCtx = phkdfCtx_unsafeFeed [block] ctx,
         phkdfSlowCtx_counter = counter + rounds + 2,
         phkdfSlowCtx_tag = tag
        }
      | otherwise = go (n-1) (phkdfCtx_unsafeFeed [fillerTag, block] ctx) stream

    out = go rounds outerCtx innerStream


phkdfSlowCtx_addArg :: ByteString -> PhkdfSlowCtx -> PhkdfSlowCtx
phkdfSlowCtx_addArg = phkdfSlowCtx_lift . phkdfCtx_addArg

phkdfSlowCtx_addArgs :: Foldable f => f ByteString -> PhkdfSlowCtx -> PhkdfSlowCtx
phkdfSlowCtx_addArgs = phkdfSlowCtx_lift . phkdfCtx_addArgs

phkdfSlowCtx_finalize :: PhkdfSlowCtx -> ByteString
phkdfSlowCtx_finalize = Stream.head . phkdfSlowCtx_finalizeStream

phkdfSlowCtx_finalizeStream :: PhkdfSlowCtx -> Stream ByteString
phkdfSlowCtx_finalizeStream ctx =
    phkdfCtx_finalizeStream
        (phkdfSlowCtx_counter ctx)
        (phkdfSlowCtx_tag ctx)
        (phkdfSlowCtx_phkdfCtx ctx)
