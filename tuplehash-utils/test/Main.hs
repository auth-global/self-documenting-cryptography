module Main (main) where

import           Data.Bits(FiniteBits)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Crypto.Encoding.SHA3.TupleHash

import Test.Tasty
import Test.Tasty.QuickCheck

main :: IO ()
main = defaultMain $ testGroup "toplevel"
   [ testProperty "prop_bareEncode" (prop_bareEncode :: NonNegative Int -> Bool)
   , testProperty "prop_leftEncode" (prop_leftEncode :: NonNegative Int -> Bool)
   , testProperty "prop_bareEncodeInteger" prop_bareEncodeInteger
   , testProperty "prop_leftEncodeInteger" prop_leftEncodeInteger
   , testProperty "prop_bareEncodeFromBytes" (prop_bareEncodeFromBytes :: NonNegative Int -> Bool)
   , testProperty "prop_leftEncodeFromBytes" (prop_leftEncodeFromBytes :: NonNegative Int -> Bool)
   , testProperty "prop_bareEncodeIntegerFromBytes" prop_bareEncodeIntegerFromBytes
   , testProperty "prop_leftEncodeIntegerFromBytes" prop_leftEncodeIntegerFromBytes
   ]

readBigEndian :: ByteString -> Integer
readBigEndian = B.foldl delta 0
  where
     delta tot next = 256 * tot + fromIntegral next

prop_bareEncode :: (Integral n, FiniteBits n) => NonNegative n -> Bool
prop_bareEncode (NonNegative n) =
  isValidBareEncode n (bareEncode n)

isValidBareEncode :: (Integral n, FiniteBits n) => n -> ByteString -> Bool
isValidBareEncode n b
    = not (B.null b)
    && ((B.head b /= 0) == (n /= 0))
    && B.length b == lengthOfBareEncode n
    && readBigEndian b == fromIntegral n

prop_leftEncode :: (Integral n, FiniteBits n) => NonNegative n -> Bool
prop_leftEncode (NonNegative n) =
  isValidLeftEncode n (leftEncode n)

isValidLeftEncode :: (Integral n, FiniteBits n) => n -> ByteString -> Bool
isValidLeftEncode n b
    = not (B.null b)
    && fromIntegral (B.head b) == B.length b - 1
    && B.length b == lengthOfLeftEncode n
    && isValidBareEncode n (B.tail b)

prop_bareEncodeInteger :: NonNegative Integer -> Bool
prop_bareEncodeInteger (NonNegative n) =
  case bareEncodeInteger n of
    Nothing -> True
    Just b -> isValidBareEncodeInteger n b

isValidBareEncodeInteger :: Integer -> ByteString -> Bool
isValidBareEncodeInteger n b
    = not (B.null b)
    && ((B.head b /= 0) == (n /= 0))
    && Just (B.length b) == lengthOfBareEncodeInteger n
    && readBigEndian b == n

prop_leftEncodeInteger :: NonNegative Integer -> Bool
prop_leftEncodeInteger (NonNegative n) =
  case leftEncodeInteger n of
    Nothing -> True
    Just b -> isValidLeftEncodeInteger n b

isValidLeftEncodeInteger :: Integer -> ByteString -> Bool
isValidLeftEncodeInteger n b
    = not (B.null b)
    && fromIntegral (B.head b) == B.length b - 1
    && Just (B.length b) == lengthOfLeftEncodeInteger n
    && isValidBareEncodeInteger n (B.tail b)

prop_bareEncodeFromBytes :: (Integral n, FiniteBits n) => NonNegative n -> Bool
prop_bareEncodeFromBytes (NonNegative n) =
  isValidBareEncodeFromBytes n (bareEncodeFromBytes n)

isValidBareEncodeFromBytes :: (Integral n, FiniteBits n) => n -> ByteString -> Bool
isValidBareEncodeFromBytes n b
    = not (B.null b)
    && ((B.head b /= 0) == (n /= 0))
    && B.length b == lengthOfBareEncodeFromBytes n
    && readBigEndian b == 8 * fromIntegral n

prop_leftEncodeFromBytes :: (Integral n, FiniteBits n) => NonNegative n -> Bool
prop_leftEncodeFromBytes (NonNegative n) =
  isValidLeftEncodeFromBytes n (leftEncodeFromBytes n)

isValidLeftEncodeFromBytes :: (Integral n, FiniteBits n) => n -> ByteString -> Bool
isValidLeftEncodeFromBytes n b
    = not (B.null b)
    && fromIntegral (B.head b) == B.length b - 1
    && B.length b == lengthOfLeftEncodeFromBytes n
    && isValidBareEncodeFromBytes n (B.tail b)

prop_bareEncodeIntegerFromBytes :: NonNegative Integer -> Bool
prop_bareEncodeIntegerFromBytes (NonNegative n) =
  case bareEncodeIntegerFromBytes n of
    Nothing -> True
    Just b -> isValidBareEncodeIntegerFromBytes n b

isValidBareEncodeIntegerFromBytes :: Integer -> ByteString -> Bool
isValidBareEncodeIntegerFromBytes n b
    = not (B.null b)
    && ((B.head b /= 0) == (n /= 0))
    && Just (B.length b) == lengthOfBareEncodeIntegerFromBytes n
    && readBigEndian b == 8 * n

prop_leftEncodeIntegerFromBytes :: NonNegative Integer -> Bool
prop_leftEncodeIntegerFromBytes (NonNegative n) =
  case leftEncodeIntegerFromBytes n of
    Nothing -> True
    Just b -> isValidLeftEncodeIntegerFromBytes n b

isValidLeftEncodeIntegerFromBytes :: Integer -> ByteString -> Bool
isValidLeftEncodeIntegerFromBytes n b
    = not (B.null b)
    && fromIntegral (B.head b) == B.length b - 1
    && Just (B.length b) == lengthOfLeftEncodeIntegerFromBytes n
    && isValidBareEncodeIntegerFromBytes n (B.tail b)
