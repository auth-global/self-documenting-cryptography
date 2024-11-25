{-# LANGUAGE OverloadedStrings, ViewPatterns #-}

module Main (main) where

import           Data.Base16.Types
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as B
import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as SB
import qualified Data.ByteString.Short.Base16 as SB
import           Data.Function(on)
import           Data.Text (Text)
import qualified Data.Text as T
import           Crypto.HashString (HashString(..))
import qualified Crypto.HashString as HS

import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.ByteString()

main :: IO ()
main = defaultMain $ testGroup "toplevel" 
   [ testProperty "prop_compare" prop_compare
   , testProperty "prop_eq_refl" prop_eq_refl
   , testProperty "prop_compare_len" prop_compare_len
   , testProperty "prop_toShortBase16" prop_toShortBase16
   , testProperty "prop_fromShortBase16" prop_fromShortBase16
   , testProperty "prop_toBase16" prop_toBase16
   , testProperty "prop_fromBase16" prop_fromBase16
   ]

-- this should mostly exercise LT/GT, but not likely to exercise EQ or LT/GT determined by length, which we'll write other test cases for

prop_compare :: ShortByteString -> ShortByteString -> Bool
prop_compare as bs = compare as bs == (compare `on` HashString) as bs

prop_eq_refl :: ShortByteString -> Bool
prop_eq_refl (HashString -> bs) = bs == bs

prop_compare_len :: ShortByteString -> ShortByteString -> Bool
prop_compare_len as bs =
    SB.null bs
     || (   (compare `on` HashString) as abs == LT
         && (compare `on` HashString) abs as == GT )
  where
    abs = as <> bs

prop_toShortBase16 :: ShortByteString -> Bool
prop_toShortBase16 as = roundtrip as == Right as
  where
    roundtrip = SB.decodeBase16Untyped . HS.toShortBase16 . HashString

prop_fromShortBase16 :: ShortByteString -> Bool
prop_fromShortBase16 as = roundtrip as == Just as
  where
    roundtrip = fmap unHashString . HS.fromShortBase16 . extractBase16 . SB.encodeBase16'

prop_toBase16 :: ByteString -> Bool
prop_toBase16 as = roundtrip as == Right as
  where
    roundtrip = B.decodeBase16Untyped . HS.toBase16 . HS.fromByteString

prop_fromBase16 :: ByteString -> Bool
prop_fromBase16 as = roundtrip as == Just as
  where
    roundtrip = fmap HS.toByteString . HS.fromBase16 . extractBase16 . B.encodeBase16'
