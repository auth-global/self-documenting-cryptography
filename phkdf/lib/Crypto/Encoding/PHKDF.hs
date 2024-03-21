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

cycleByteStringToList :: ByteString -> Int -> [ByteString]
cycleByteStringToList str outBytes =
    if outBytes <= 0
    then []
    else if n == 0
         then [ B.replicate outBytes 0 ]
         else replicate q str ++ [B.take r str]
  where
    n = B.length str
    (q,r) = outBytes `quotRem` n

cycleByteStringWithNullToList :: ByteString -> Int -> [ByteString]
cycleByteStringWithNullToList str outBytes = out
  where
    out = cycleByteStringToList (str <> "\x00") outBytes

cycleByteString :: ByteString -> Int -> ByteString
cycleByteString str outBytes = B.concat (cycleByteStringToList str outBytes)

cycleByteStringWithNull :: ByteString -> Int -> ByteString
cycleByteStringWithNull str outBytes =
    B.concat (cycleByteStringWithNullToList str outBytes)

extendTagToList :: ByteString -> [ByteString]
extendTagToList tag = if n <= 19 then [tag] else tag'
  where
    n = B.length tag
    x = (18 - n) `mod` 64
    tag' = cycleByteStringWithNullToList tag (n+x)
         ++ [B.singleton (fromIntegral x)]

extendTag :: ByteString -> ByteString
extendTag = B.concat <$> extendTagToList

trimExtTag :: ByteString -> Maybe ByteString
trimExtTag extTag
  | n <= 19 = Just extTag
  | extTag /= extendTag tag = Nothing
  | otherwise = Just tag
  where
    n = B.length extTag
    x = B.last extTag
    tag = B.take (n - fromIntegral x - 1) extTag

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

usernamePadding :: Foldable f => f ByteString -> ByteString -> ByteString -> ByteString
usernamePadding headerExtract fillerTag domainTag
  =  cycleByteStringWithNull fillerTag (a-32)
  <> cycleByteStringWithNull domainTag    32
  where
    al = encodedVectorByteLength headerExtract
    a  = add64WhileLt (157 - al) 32

passwordPaddingBytes :: Foldable f => Int -> f ByteString -> f ByteString -> ByteString -> ByteString -> ByteString -> ByteString
passwordPaddingBytes bytes headerUsername headerLongTag fillerTag domainTag password
  =  cycleByteStringWithNull fillerTag (c-32)
  <> cycleByteStringWithNull domainTag    32
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
credentialsPadding credentials fillerTag domainTag
  =  cycleByteStringWithNull fillerTag (a-29)
  <> cycleByteStringWithNull domainTag    29
  where
    al = encodedVectorByteLength credentials
    a  = add64WhileLt (122 - al) 32
