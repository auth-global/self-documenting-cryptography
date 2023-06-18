import Test.Tasty
import Data.Monoid
import qualified HMAC
import qualified PHKDF

main = do
  let fileName = PHKDF.testVectorDefaultFileName
  phkdfTvs <- PHKDF.readTestVectorsFromFile fileName
  defaultMain (tests phkdfTvs)

tests :: (String, Either String PHKDF.TestVectors) -> TestTree
tests phkdfTvs = testGroup "Test" [
    testGroup "hmac" HMAC.tests,
    testGroup "phkdf" [PHKDF.testFile phkdfTvs]
  ]
