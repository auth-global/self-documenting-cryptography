{-# LANGUAGE OverloadedStrings, ViewPatterns #-}

module Crypto.Encoding.PHKDF where

import Data.Monoid((<>))
import Data.Bits(Bits, (.&.))
import Data.ByteString(ByteString)
import Data.Foldable(Foldable)
import qualified Data.ByteString as B
import Crypto.Encoding.SHA3.TupleHash

import Debug.Trace

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

{--

FIXME: as written, this only works on signed arithmetic, unless the modulus @a@
is a power of 2, such as 64

-- | @addWhileLt a b c@ is equivalent to  @while (b < c) { b += a }; return b@
addWhileLt :: Integral a => a -> a -> a -> a
addWhileLt a b c
   | b >= c = b
   | otherwise = c + ((b - c) `mod` a)

--}

-- | @add64WhileLt b c@ is equivalent to  @while (b < c) { b += 64 }; return b@

add64WhileLt :: (Ord a, Num a, Bits a) => a -> a -> a
add64WhileLt b c
   | b >= c = b
   | otherwise = c + ((b - c) .&. 63)

add64WhileLt' :: (Ord a, Num a, Bits a, Show a) => a -> a -> a
add64WhileLt' b c
   | b >= c = b
   | otherwise = let d = c + ((b - c) .&. 63)
                  in trace (show b ++ " -> " ++ show d) d

usernamePadding :: Foldable f => f ByteString -> ByteString -> ByteString
usernamePadding headerExtract domainTag
  =  cycleByteStringWithNull (a-32) domainTag
  <> cycleByteStringWithNull    32  domainTag
  where
    al = encodedVectorByteLength headerExtract
    a  = add64WhileLt (157 - al) 32

passwordPaddingBytes :: Foldable f => Int -> f ByteString -> f ByteString -> ByteString -> ByteString -> ByteString -> ByteString
passwordPaddingBytes bytes headerUsername headerLongTag longTag domainTag password
  =  cycleByteStringWithNull (c-32) longTag
  <> cycleByteStringWithNull    32  domainTag
  where
    al = encodedVectorByteLength headerLongTag
    a  = add64WhileLt (bytes - al) 3240
    bl = encodedVectorByteLength headerUsername
    b  = add64WhileLt (a - bl) 136
    cl = encodedByteLength password
    c  = add64WhileLt (b - cl) 32

passwordPadding :: Foldable f => f ByteString -> f ByteString -> ByteString -> ByteString -> ByteString -> ByteString
passwordPadding = passwordPaddingBytes 8413

credentialsPadding :: Foldable f => f ByteString -> ByteString -> ByteString -> ByteString
credentialsPadding credentials longTag domainTag
  =  cycleByteStringWithNull (a-29) longTag
  <> cycleByteStringWithNull    29  domainTag
  where
    al = encodedVectorByteLength credentials
    a  = add64WhileLt (122 - al) 32
