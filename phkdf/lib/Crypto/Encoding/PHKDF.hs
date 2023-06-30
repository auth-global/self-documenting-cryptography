{-# LANGUAGE OverloadedStrings, ViewPatterns #-}

module Crypto.Encoding.PHKDF where

import Data.Monoid((<>))
import Data.Bits(Bits, (.&.))
import Data.ByteString(ByteString)
import Data.Foldable(Foldable, foldl')
import qualified Data.ByteString as B
import Crypto.Encoding.SHA3.TupleHash

-- FIXME: several functions in here have opportunites for optimization

cycleByteStringToList :: Int -> ByteString -> [ByteString]
cycleByteStringToList outBytes str =
    if outBytes <= 0
    then []
    else if n == 0
         then [ B.replicate outBytes 0 ]
         else replicate q str ++ [B.take r str]
  where
    n = B.length str
    (q,r) = outBytes `quotRem` n

cycleByteStringWithNullToList :: Int -> ByteString -> [ByteString]
cycleByteStringWithNullToList outBytes str = out
  where
    out = cycleByteStringToList outBytes (str <> "\x00")

cycleByteString :: Int -> ByteString -> ByteString
cycleByteString outBytes str = B.concat (cycleByteStringToList outBytes str)

cycleByteStringWithNull :: Int -> ByteString -> ByteString
cycleByteStringWithNull outBytes str =
    B.concat (cycleByteStringWithNullToList outBytes str)

expandDomainTag :: ByteString -> ByteString
expandDomainTag tag = if n <= 19 then tag else tag'
  where
    n = B.length tag
    x = (19 - n) `mod` 64
    tag' = cycleByteStringWithNull (n+x) tag

longPaddingAll :: Foldable f => Int -> Int -> Int -> f ByteString -> ByteString -> ByteString
longPaddingAll minlen minext bytes msgs longTag =
    cycleByteStringWithNull padLen longTag
  where
    extent = add64WhileLt (bytes - encodedByteLength longTag) minext
    padLen = add64WhileLt (extent - encodedVectorByteLength msgs) minlen

longPaddingBytes :: Foldable f => Int -> f ByteString -> ByteString -> ByteString
longPaddingBytes = longPaddingAll 32 3072

longPadding :: Foldable f => f ByteString -> ByteString -> ByteString
longPadding = longPaddingBytes defaultLongPaddingBytes

defaultLongPaddingBytes :: Int
defaultLongPaddingBytes = 8312

{--

FIXME: as written, this only works on signed arithmetic, unless the modulus
is a power of 2, such as 64

-- | @addWhileLt a b c@ is equivalent to  @while (b < c) { b += a }; return b@
addWhileLt :: Integral a => a -> a -> a -> a
addWhileLt a b c
   | b >= c = b
   | otherwise = c + ((b - c) `mod` a)

--}

add64WhileLt :: (Ord a, Num a, Bits a) => a -> a -> a
add64WhileLt b c
   | b >= c = b
   | otherwise = c + ((b - c) .&. 63)

shortPadding :: Foldable f => f ByteString -> ByteString -> ByteString
shortPadding creds = cycleByteStringWithNull n
  where encLen = encodedVectorByteLength creds
        n = 95 - (encLen `mod` 64)

encodedVectorByteLength :: Foldable f => f ByteString -> Int
encodedVectorByteLength = foldl' (\a x -> a + encodedByteLength x) 0
