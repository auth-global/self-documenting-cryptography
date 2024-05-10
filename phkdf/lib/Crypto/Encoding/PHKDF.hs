{-# LANGUAGE OverloadedStrings, ViewPatterns #-}

module Crypto.Encoding.PHKDF where

import Data.Bits(Bits, (.&.), shift)
import Data.ByteString(ByteString)
import Data.Int(Int64)
import Data.List(scanl')
import qualified Data.ByteString as B

import Debug.Trace

extendTagToList :: ByteString -> [ByteString]
extendTagToList tag = if n <= 19 then [tag] else tag'
  where
    n = B.length tag
    x = (19 - n) `mod` 64
    tag' = takeBs (fromIntegral (n+x)) (cycle [tag, "\x00"])
         ++ [B.singleton (fromIntegral x `shift` 2)]

-- | Extends a PHKDF end-of-message tag in order to ensure the last SHA-256
--   block contains something interesting.
--
--   Tags less than 160 bits (20 bytes) long are appended directly, without
--   extension, as the final portion of the message. Thus this function
--   is the identity on short inputs.
--
--   Extended tags that are at least 20 bytes long should be thought of as
--   a bitstring with a single null bit appended at the end to make it a
--   full bytestring.
--
--   Tags 160 bits or longer are first extended, if necessary, to a full
--   bytestring by adding a single "1" bit followed by zero to six "0" bits.
--
--   The bytestring is then extended by 0-63 bytes as needed to make the
--   overall length equivalent to 19 (mod 64). The first byte of the extension
--   is a null byte, then followed by the bytestring, then starting again
--   at the null byte as needed.
--
--   The length of this extension takes up the first 6 bits of the last byte,
--   followed by a "0" or "1" bit denoting whether the tag is a bytestring,
--   or a proper bitstring whose length is an inexact multiple of 8.
--
--   The final bit is reserved for SHA-256's end-of-message padding, which
--   will set it to 1.

extendTag :: ByteString -> ByteString
extendTag = B.concat <$> extendTagToList

-- | This function robustly undoes 'extendTag', thus "proving" that all
--   collisions on PHKDF's tag are cryptographically non-trivial, even after
--   extension.
--
--   This is a "proof" in the sense that if
--   @trimExtendedTag (extendTag x) == Just x@ is true for all bytestrings
--   @x@, then all collisions are non-trivial, but we haven't presented a
--   full deductive proof of this property.  (It will eventually be part of
--   the test suite.)

trimExtendedTag :: ByteString -> Maybe ByteString
trimExtendedTag extTag
  | n <= 19 = Just extTag
  | extTag /= extendTag tag = Nothing
  | otherwise = Just tag
  where
    n = B.length extTag
    x = B.last extTag `shift` (-2)
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

-- | Partition a bytestring into chunks of up to a given size

chunkify :: Int -> ByteString -> [ ByteString ]
chunkify n = go
  where
    go bs
      | B.null bs = []
      | otherwise = bs0 : go bs1
        where (bs0, bs1) = B.splitAt n bs

-- | Partition a cyclically extended bytestring into chunks of
--   a given size, starting at a given offset.
--
--   Note that repetitions of the original string get a single
--   null byte placed between them.

chunkifyCycle
  :: Int64 -- ^ Desired chunk size
  -> ByteString -- ^ String to be cyclically extended.
  -> Int64 -- ^ Starting offset
  -> [ ByteString ] -- ^ Infinite stream of chunks
chunkifyCycle len bs = go
  where
    modN pos = pos `mod` (fromIntegral (B.length bs) + 1)
    ext = B.concat (bs:takeBs len (cycle ["\x00", bs]))
    go (modN -> pos) = assertTakeB' len (B.drop (fromIntegral pos) ext) : go (pos + len)
