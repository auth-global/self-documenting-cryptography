import Test.Tasty
import Test.Tasty.HUnit
import qualified HKDF
import PreinitSalt
import Crypto.Seguid.Protocol.Constants

main = defaultMain tests

-- TODO: fuzz testing against one or more implementations

tests :: TestTree
tests = testGroup "seguid-protocol"
  [ testCase "seguid_v0_salt can be recomputed" $
       compute_seguid_v0_salt @?= seguid_v0_salt
  , testCase "seguid_v0_salt can be verified" $
       assertBool "false" (verify_seguid_v0_salt seguid_v0_salt)
  , HKDF.tests
  ] 
