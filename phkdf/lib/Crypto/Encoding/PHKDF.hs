{-# LANGUAGE OverloadedStrings, ViewPatterns #-}

module Crypto.Encoding.PHKDF where

import Data.Monoid((<>))
import Data.Bits(Bits, (.&.))
import Data.ByteString(ByteString)
import Data.Foldable(Foldable)
import Data.Int(Int64)
import Data.List(scanl')
import qualified Data.ByteString as B
import Crypto.Encoding.SHA3.TupleHash

import Debug.Trace

-- FIXME: most of the older parts of this module should be deleted, but
--        need to move to something better first.

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

dropBs :: Int64 -> [ ByteString ] -> [ ByteString ]
dropBs = go
  where
    len = fromIntegral . B.length
    go _ [] = []
    go 0 bs = bs
    go n (b:bs)
      | n >= len b = go (n - len b) bs
      | otherwise = B.drop (fromIntegral n) b : bs

takeBs :: Int64 -> [ ByteString ] -> [ ByteString ]
takeBs = go
  where
    len = fromIntegral . B.length
    go _ [] = []
    go n (b:bs)
      | n <= 0 = []
      | len b < n = b : go (n - len b) bs
      | otherwise = [B.take (fromIntegral n) b]

takeBs' :: Int64 -> [ ByteString ] -> [ ByteString ]
takeBs' n bs = if haveEnough then takeBs n bs else []
  where
    len = fromIntegral . B.length
    haveEnough = any (>= n) (scanl' (+) 0 (map len bs))

takeB' :: Int64 -> ByteString -> Maybe ByteString
takeB' n bs =
  -- this fromIntegral is inherently safe
  if fromIntegral (B.length bs) < n
  then Nothing
  -- this fromIntegral is safe because of the check above
  else Just (B.take (fromIntegral n) bs)

assertTakeB' :: Int64 -> ByteString -> ByteString
assertTakeB' = (maybe (error "not enough bytes") id <$>) . takeB'

nullBuffer :: ByteString
nullBuffer = B.replicate 64 0

chunkify :: Int -> ByteString -> [ ByteString ]
chunkify n = go
  where
    go bs
      | B.null bs = []
      | otherwise = bs0 : go bs1
        where (bs0, bs1) = B.splitAt n bs

chunkifyCycle :: Int64 -> ByteString -> Int64 -> [ ByteString ]
chunkifyCycle len bs = go
  where
    modN pos = pos `mod` (fromIntegral (B.length bs) + 1)
    ext = B.concat (bs:takeBs len (cycle ["\x00", bs]))
    go (modN -> pos) = assertTakeB' len (B.drop (fromIntegral pos) ext) : go (pos + len)
