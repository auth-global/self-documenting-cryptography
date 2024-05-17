import Test.Tasty
import Data.Monoid
import qualified G3P
import qualified G3Pb2
import qualified MyCorpExample

main = do
  let fileName1 = G3P.testVectorDefaultFileName
  g3pb1Tvs <- G3P.readTestVectorsFromFile fileName1
  let fileName2 = G3Pb2.testVectorDefaultFileName
  g3pb2Tvs <- G3Pb2.readTestVectorsFromFile fileName2
  defaultMain (tests g3pb1Tvs g3pb2Tvs)

tests :: (String, Either String G3P.TestVectors) -> (String, Either String G3Pb2.TestVectors) -> TestTree
tests g3pb1Tvs g3pb2Tvs = testGroup "Test" [
    testGroup "G3Pb1" [G3P.testFile g3pb1Tvs],
    testGroup "G3Pb2" [G3Pb2.testFile g3pb2Tvs],
    testGroup "examples" MyCorpExample.tests
  ]
