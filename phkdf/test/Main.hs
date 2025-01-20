import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import           Data.Monoid
import           Test.Tasty
import           Test.Tasty.QuickCheck
import           Test.QuickCheck.Instances.ByteString()

import qualified HMAC
import qualified PHKDF
import           Crypto.Encoding.PHKDF

main = do
  let fileName = PHKDF.testVectorDefaultFileName
  phkdfTvs <- PHKDF.readTestVectorsFromFile fileName
  defaultMain (tests phkdfTvs)

tests :: (String, Either String PHKDF.TestVectors) -> TestTree
tests phkdfTvs = testGroup "Test" [
    testGroup "hmac" HMAC.tests,
    testGroup "phkdf" [PHKDF.testFile phkdfTvs],
    testProperty "prop_extendTag" prop_extendTag
  ]

prop_extendTag :: ByteString -> Bool
prop_extendTag x = trimExtendedTag x' == Just x && validLength
  where
    x' = extendTag x
    validLength = B.length x' <= 19 || B.length x' `mod` 64 == 20
