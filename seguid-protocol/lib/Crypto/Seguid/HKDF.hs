{-# LANGUAGE BangPatterns, OverloadedStrings #-}

-- This belongs in cryptohash-sha512, but we'll put it here for now.  When it's available elsewhere, this can become a shim.  It includes a few minor niceties on top of HKDF proper.

module Crypto.Seguid.HKDF where

import Data.Bits
import Data.ByteString(ByteString)
import qualified Data.ByteString as B
import Data.Foldable(Foldable)
import qualified Data.Foldable as F
import Data.Stream(Stream(..))
import Data.Word
import qualified Data.Stream as Stream
import qualified Crypto.Hash.SHA512 as SHA512
import Crypto.Encoding.SHA3.TupleHash(leftEncode, encodeString)

hkdf :: ByteString -> ByteString -> ByteString -> Int -> ByteString
hkdf salt ikm = let prk = hkdfExtract salt ikm
                 in hkdfExpand prk

hkdfExtract :: ByteString -> ByteString -> ByteString
hkdfExtract = SHA512.hmac

-- FIXME: Optimize this
hkdfExtractTuple :: Foldable list => ByteString -> list ByteString -> ByteString
hkdfExtractTuple key ikms = hkdfExtract key (B.concat . map encodeString $ F.toList ikms) 

hkdfExpand :: ByteString -> ByteString -> Int -> ByteString
hkdfExpand prk info len =
    if len <= 0 then B.empty else B.concat out
  where
    (q,r) = len `divMod` 64
    stream = hkdfExpandUnbounded prk info
    (bs, rest) = Stream.splitAt q stream
    out = if r == 0
          then bs
          else bs <> [B.take r (Stream.head rest)]

hkdfExpandBitLength :: ByteString -> ByteString -> Int -> ByteString
hkdfExpandBitLength prk info len =
    if len <= 0 then B.empty else B.concat out
  where
    (q,r) = len `divMod` 512
    stream = hkdfExpandUnbounded prk info
    (bs, rest) = Stream.splitAt q stream
    out = if r == 0 then bs else
           let (bytes, bits) = r `divMod` 8
               lastBlock = Stream.head rest
               lastBytes = B.take bytes lastBlock
            in if bits == 0 then bs ++ [lastBytes] else
                let lastByte = B.index lastBlock (bytes + 1)
                                .&. shiftL 255 (8 - bits)
                 in bs ++ [lastBytes <> B.singleton lastByte]

hkdfExpandBitLengthStrict :: ByteString -> ByteString -> Int -> ByteString
hkdfExpandBitLengthStrict prk info len =
    hkdfExpandBitLength prk (leftEncode len <> info) len

hkdfExpandMaxList :: ByteString -> ByteString -> [ByteString]
hkdfExpandMaxList = (Stream.take 255 .) . hkdfExpandUnbounded

hkdfExpandUnbounded :: ByteString -> ByteString -> Stream ByteString
hkdfExpandUnbounded prk info = go "" 1
  where
    -- TODO: ensure that cryptohash-sha512 handles precomputed keys
    hmac = SHA512.hmac prk

    go :: ByteString -> Word8 -> Stream ByteString
    go t !ctr = Cons t' $ go t' (ctr + 1)
       where
          t' = hmac (B.concat [t, info, B.singleton ctr])