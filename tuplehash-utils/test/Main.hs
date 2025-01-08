module Main (main) where

import           Data.Bits(FiniteBits)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Crypto.Encoding.SHA3.TupleHash

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

f x = 2 ^ x :: Int
f' x = 2 ^ x
g x = 2 ^ x - 1 :: Int
g' x = 2 ^ x - 1

getNonNegativeInt :: NonNegative Int -> Int
getNonNegativeInt = getNonNegative

main :: IO ()
main = defaultMain $ testGroup "toplevel"
   [ testProperty "prop_bareEncode" (prop_bareEncode . getNonNegativeInt)
   , testCase "test_bareEncode" (filter (not . prop_bareEncode . f) [0..62] @?= [])
   , testCase "test_bareEncode'" (filter (not . prop_bareEncode . g) [0..62] @?= [])
   , testProperty "prop_leftEncode" (prop_leftEncode . getNonNegativeInt)
   , testCase "test_leftEncode" (filter (not . prop_leftEncode . f) [0..62] @?= [])
   , testCase "test_leftEncode'" (filter (not . prop_leftEncode . g) [0..62] @?= [])
   , testProperty "prop_bareEncodeInteger" (prop_bareEncodeInteger . getNonNegative)
   , testCase "test_bareEncodeInteger" (filter (not . prop_bareEncodeInteger . f') [0..255] @?= [])
   , testCase "test_bareEncodeInteger'" (filter (not . prop_bareEncodeInteger . g') [0..255] @?= [])
   , testProperty "prop_leftEncodeInteger" (prop_leftEncodeInteger . getNonNegative)
   , testCase "test_leftEncodeInteger" (filter (not . prop_leftEncodeInteger . f') [0..255] @?= [])
   , testCase "test_leftEncodeInteger'" (filter (not . prop_leftEncodeInteger . g') [0..255] @?= [])
   , testProperty "prop_bareEncodeFromBytes" (prop_bareEncodeFromBytes . getNonNegativeInt)
   , testCase "test_bareEncodeFromBytes" (filter (not . prop_bareEncodeFromBytes . f) [0..62] @?= [])
   , testCase "test_bareEncodeFromBytes'" (filter (not . prop_bareEncodeFromBytes . g) [0..63] @?= [])

   , testProperty "prop_leftEncodeFromBytes" (prop_leftEncodeFromBytes . getNonNegativeInt)
   , testCase "test_leftEncodeFromBytes" (filter (not . prop_leftEncodeFromBytes . f) [0..62] @?= [])
   , testCase "test_leftEncodeFromBytes'" (filter (not . prop_leftEncodeFromBytes . g) [0..63] @?= [])
   , testProperty "prop_bareEncodeIntegerFromBytes" prop_bareEncodeIntegerFromBytes
   , testCase "prop_bareEncodeIntegerFromBytes" (filter (not . prop_bareEncodeIntegerFromBytes . f') [0..255] @?= [])
   , testCase "test_bareEncodeIntegerFromBytes'" (filter (not . prop_bareEncodeIntegerFromBytes . g') [0..255] @?= [])
   , testProperty "prop_leftEncodeIntegerFromBytes" prop_leftEncodeIntegerFromBytes
   , testCase "test_leftEncodeIntegerFromBytes" (filter (not . prop_leftEncodeIntegerFromBytes . f') [0..255] @?= [])
   , testCase "test_leftEncodeIntegerFromBytes'" (filter (not . prop_leftEncodeIntegerFromBytes . g') [0..255] @?= [])
   ]

readBigEndian :: ByteString -> Integer
readBigEndian = B.foldl delta 0
  where
     delta tot next = 256 * tot + fromIntegral next

prop_bareEncode :: (Integral n, FiniteBits n) => n -> Bool
prop_bareEncode n =
  isValidBareEncode n (bareEncode n)

isValidBareEncode :: (Integral n, FiniteBits n) => n -> ByteString -> Bool
isValidBareEncode n b
    = not (B.null b)
    && ((B.head b /= 0) == (n /= 0))
    && B.length b == lengthOfBareEncode n
    && readBigEndian b == fromIntegral n

prop_leftEncode :: (Integral n, FiniteBits n) => n -> Bool
prop_leftEncode n =
  isValidLeftEncode n (leftEncode n)

isValidLeftEncode :: (Integral n, FiniteBits n) => n -> ByteString -> Bool
isValidLeftEncode n b
    = not (B.null b)
    && fromIntegral (B.head b) == B.length b - 1
    && B.length b == lengthOfLeftEncode n
    && isValidBareEncode n (B.tail b)

prop_bareEncodeInteger :: Integer -> Bool
prop_bareEncodeInteger n =
  case bareEncodeInteger n of
    Nothing -> True
    Just b -> isValidBareEncodeInteger n b

isValidBareEncodeInteger :: Integer -> ByteString -> Bool
isValidBareEncodeInteger n b
    = not (B.null b)
    && ((B.head b /= 0) == (n /= 0))
    && Just (B.length b) == lengthOfBareEncodeInteger n
    && readBigEndian b == n

prop_leftEncodeInteger :: Integer -> Bool
prop_leftEncodeInteger n =
  case leftEncodeInteger n of
    Nothing -> True
    Just b -> isValidLeftEncodeInteger n b

isValidLeftEncodeInteger :: Integer -> ByteString -> Bool
isValidLeftEncodeInteger n b
    = not (B.null b)
    && fromIntegral (B.head b) == B.length b - 1
    && Just (B.length b) == lengthOfLeftEncodeInteger n
    && isValidBareEncodeInteger n (B.tail b)

prop_bareEncodeFromBytes :: (Integral n, FiniteBits n) => n -> Bool
prop_bareEncodeFromBytes n =
  isValidBareEncodeFromBytes n (bareEncodeFromBytes n)

isValidBareEncodeFromBytes :: (Integral n, FiniteBits n) => n -> ByteString -> Bool
isValidBareEncodeFromBytes n b
    = not (B.null b)
    && ((B.head b /= 0) == (n /= 0))
    && B.length b == lengthOfBareEncodeFromBytes n
    && readBigEndian b == 8 * fromIntegral n

prop_leftEncodeFromBytes :: (Integral n, FiniteBits n) => n -> Bool
prop_leftEncodeFromBytes n =
  isValidLeftEncodeFromBytes n (leftEncodeFromBytes n)

isValidLeftEncodeFromBytes :: (Integral n, FiniteBits n) => n -> ByteString -> Bool
isValidLeftEncodeFromBytes n b
    = not (B.null b)
    && fromIntegral (B.head b) == B.length b - 1
    && B.length b == lengthOfLeftEncodeFromBytes n
    && isValidBareEncodeFromBytes n (B.tail b)

prop_bareEncodeIntegerFromBytes :: Integer -> Bool
prop_bareEncodeIntegerFromBytes n =
  case bareEncodeIntegerFromBytes n of
    Nothing -> True
    Just b -> isValidBareEncodeIntegerFromBytes n b

isValidBareEncodeIntegerFromBytes :: Integer -> ByteString -> Bool
isValidBareEncodeIntegerFromBytes n b
    = not (B.null b)
    && ((B.head b /= 0) == (n /= 0))
    && Just (B.length b) == lengthOfBareEncodeIntegerFromBytes n
    && readBigEndian b == 8 * n

prop_leftEncodeIntegerFromBytes :: Integer -> Bool
prop_leftEncodeIntegerFromBytes n =
  case leftEncodeIntegerFromBytes n of
    Nothing -> True
    Just b -> isValidLeftEncodeIntegerFromBytes n b

isValidLeftEncodeIntegerFromBytes :: Integer -> ByteString -> Bool
isValidLeftEncodeIntegerFromBytes n b
    = not (B.null b)
    && fromIntegral (B.head b) == B.length b - 1
    && Just (B.length b) == lengthOfLeftEncodeIntegerFromBytes n
    && isValidBareEncodeIntegerFromBytes n (B.tail b)
