{-# LANGUAGE OverloadedStrings, BangPatterns, ScopedTypeVariables, ViewPatterns #-}

module Crypto.Encoding.SHA3.TupleHash
  ( leftEncodeZero
  , leftEncodeInteger
  , leftEncodeIntegerFromBytes
  , leftEncode
  , leftEncodeFromBytes
  , encodeString
  , encodedByteLength
  , encodedVectorByteLength
  , bareEncodeZero
  , bareEncodeInteger
  , bareEncodeIntegerFromBytes
  , bareEncode
  , bareEncodeFromBytes
  , lengthOfBareEncode
  , lengthOfBareEncodeFromBytes
  , lengthOfBareEncodeInteger
  , lengthOfBareEncodeIntegerFromBytes
  , lengthOfLeftEncode
  , lengthOfLeftEncodeFromBytes
  , lengthOfLeftEncodeInteger
  , lengthOfLeftEncodeIntegerFromBytes
  ) where

import Data.Monoid((<>))
import Data.ByteString(ByteString)
import qualified Data.ByteString as B
import Data.Bits
import Data.List(foldl')
import Data.Word
import Math.NumberTheory.Logarithms(integerLog2)

downFrom :: (Num a, Enum a) => a -> [a]
downFrom x = [x-1,x-2..0]

leftEncodeZero :: ByteString
leftEncodeZero = "\x01\x00"

-- I don't like the current interface in that:
--   leftEncodeInteger returns Nothing when provided a negative result, but
--   leftEncode (on FiniteBits) returns leftEncodeZero when provided the same
--   If there were a way in Haskell to constrain the latter bit to unsigned Words, I'd do it
--   Then the more generic version that works on finite signed ints would return (Maybe ByteString)
--   The current interface is a bit of a compromise

leftEncodeInteger :: Integer -> Maybe ByteString
leftEncodeInteger n =
  case compare n 0 of
    LT -> Nothing
    EQ -> Just leftEncodeZero
    -- Note that the bit length is integerLog2 plus one
    -- Round up to the nearest byte by adding 7, then divide by 8
    -- simplifying, we can divide integerLog2 by eight, and then add one
    GT -> case shiftR (integerLog2 n) 3 + 1 of
           nSigBytes
             | nSigBytes > 255 -> Nothing
             | otherwise -> Just (B.pack (go (fromIntegral nSigBytes)))
  where
    go nSigBytes = fromIntegral nSigBytes : map getByte (downFrom nSigBytes)
    -- FIXME: using shiftR here results in a quadratic algorithm
    getByte ix = fromIntegral (shiftR n (8*ix) .&. 0xFF)

leftEncodeIntegerFromBytes :: Integer -> Maybe ByteString
leftEncodeIntegerFromBytes n = leftEncodeInteger (8*n)

leftEncode :: forall b. (Integral b, FiniteBits b) => b -> ByteString
leftEncode n
  | n <= 0 = leftEncodeZero
  | otherwise = B.pack output
  where
    wordLen = finiteBitSize n
    zeros = countLeadingZeros n
    nSigBits = wordLen - zeros
    nSigBytes = max 1 (shiftR (nSigBits + 7) 3)
    getByte :: Int -> Word8
    getByte ix = fromIntegral (shiftR n (8 * ix) .&. 255)
    output = fromIntegral nSigBytes : map getByte (downFrom nSigBytes)

leftEncodeFromBytes :: (Integral b, FiniteBits b) => b -> ByteString
leftEncodeFromBytes n
  | n <= 0 = leftEncodeZero
  | otherwise = B.pack output
  where
    wordLen = finiteBitSize n
    zeros = countLeadingZeros n
    nSigBits = wordLen - zeros + 3
    nSigBytes = max 1 (shiftR (nSigBits + 7) 3)
    getByte ix = fromIntegral (shift n (3 - 8 * ix) .&. 0xFF)
    output = fromIntegral nSigBytes : map getByte (downFrom nSigBytes)

{--
-- FIXME: this doesn't work for x0 > 7
leftEncodeBytesMinusBits :: Word -> Word8 -> ByteString
leftEncodeBytesMinusBits n0 x0 = B.pack (fromIntegral nSigBytes : output)
  where
    n = n0 - fromIntegral (fromEnum (x /= 0))
    wordLen = finiteBitSize n
    zeros = countLeadingZeros n
    nSigBits = wordLen - zeros + 3
    nSigBytes = fromIntegral (max 1 (shiftR (nSigBits + 7) 3)) :: Word8
    getByte ix = fromIntegral byte .|. mx
      where byte = shift n (3 - 8 * ix) .&. 0xFF
            mx   = (-x) * fromIntegral (fromEnum (ix /= 0))
    output = map getByte (nSigBytes `downTo` 0)

-- rightEncode :: Int -> ByteString
--}

encodeString :: ByteString -> ByteString
encodeString bytes
    | byteLen <= 0 = leftEncodeZero
    | otherwise = leftEncodeFromBytes byteLen <> bytes
  where
    byteLen = fromIntegral (B.length bytes) :: Word

encodedByteLength :: ByteString -> Int
encodedByteLength (B.length -> n) = lengthOfLeftEncode n + n

encodedVectorByteLength :: Foldable f => f ByteString -> Int
encodedVectorByteLength = foldl' (\a x -> a + encodedByteLength x) 0

{--
encodeBitString :: Word8 -> ByteString -> [ByteString]
encodeBitString truncBits bytes
   | byteLen <= 0 = [ "\x01\x00" ]
   | otherwise = [ leftEncodeBytesMinusBits byteLen truncBits


     leftEncode bitL, take (byteLength - 1) bytes,
--}

bareEncodeZero :: ByteString
bareEncodeZero = "\x00"

bareEncodeInteger :: Integer -> Maybe ByteString
bareEncodeInteger n =
  case compare n 0 of
    LT -> Nothing
    EQ -> Just leftEncodeZero
    GT -> let nSigBytes = shiftR (integerLog2 n) 3 + 1
           in Just (B.pack (go (fromIntegral nSigBytes)))
  where
    go nSigBytes = fromIntegral nSigBytes : map getByte (downFrom nSigBytes)
    -- FIXME: using shiftR here results in a quadratic algorithm
    getByte ix = fromIntegral (shiftR n (8*ix) .&. 0xFF)

bareEncodeIntegerFromBytes :: Integer -> Maybe ByteString
bareEncodeIntegerFromBytes = fmap (B.drop 1) . leftEncodeIntegerFromBytes

bareEncode :: (Integral b, FiniteBits b) => b -> ByteString
bareEncode = B.drop 1 . leftEncode

bareEncodeFromBytes :: (Integral b, FiniteBits b) => b -> ByteString
bareEncodeFromBytes = B.drop 1 . leftEncodeFromBytes

lengthOfBareEncode :: (Integral b, FiniteBits b) => b -> Int
lengthOfBareEncode n
    | n <= 0 = 1
    | otherwise = nSigBytes
  where
    wordLen = finiteBitSize n
    zeros = countLeadingZeros n
    nSigBits = wordLen - zeros + 3
    nSigBytes = max 1 (shiftR (nSigBits + 7) 3)

lengthOfBareEncodeFromBytes :: (Integral b, FiniteBits b) => b -> Int
lengthOfBareEncodeFromBytes n
    | n <= 0 = 1
    | otherwise = nSigBytes
  where
    wordLen = finiteBitSize n
    zeros = countLeadingZeros n
    nSigBits = wordLen - zeros + 3
    nSigBytes = max 1 (shiftR (nSigBits + 7) 3)

lengthOfBareEncodeInteger :: Integer -> Maybe Int
lengthOfBareEncodeInteger n =
  case compare n 0 of
    LT -> Nothing
    EQ -> Just 1
    GT -> Just (shiftR (integerLog2 n) 3 + 1)

lengthOfBareEncodeIntegerFromBytes :: Integer -> Maybe Int
lengthOfBareEncodeIntegerFromBytes n =
  case compare n 0 of
    LT -> Nothing
    EQ -> Just 1
    GT -> Just (shiftR (integerLog2 n + 3) 3 + 1)

lengthOfLeftEncode :: (Integral b, FiniteBits b) => b -> Int
lengthOfLeftEncode = (+1) . lengthOfBareEncode

lengthOfLeftEncodeFromBytes :: (Integral b, FiniteBits b) => b -> Int
lengthOfLeftEncodeFromBytes = (+1) . lengthOfBareEncodeFromBytes

lengthOfLeftEncodeInteger :: Integer -> Maybe Int
lengthOfLeftEncodeInteger n =
  case lengthOfBareEncodeInteger n of
    Nothing -> Nothing
    Just nSigBytes
       | nSigBytes > 255 -> Nothing
       | otherwise       -> Just (nSigBytes+1)

lengthOfLeftEncodeIntegerFromBytes :: Integer -> Maybe Int
lengthOfLeftEncodeIntegerFromBytes n =
  case lengthOfBareEncodeIntegerFromBytes n of
    Nothing -> Nothing
    Just nSigBytes
       | nSigBytes > 255 -> Nothing
       | otherwise       -> Just (nSigBytes+1)
