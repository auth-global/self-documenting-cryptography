import Test.Tasty
import Data.Monoid
import qualified G3P

main = do
  let fileName = G3P.testVectorDefaultFileName
  g3pTvs <- G3P.readTestVectorsFromFile fileName
  defaultMain (tests g3pTvs)

tests :: (String, Either String G3P.TestVectors) -> TestTree
tests g3pTvs = testGroup "Test" [
    testGroup "G3Pb1" [G3P.testFile g3pTvs]
  ]
