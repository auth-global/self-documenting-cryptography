-- Test Vectors for HMAC-SHA256

{-# LANGUAGE OverloadedStrings #-}

module HMAC where

import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as B
import           Data.Function((&))
import           Test.Tasty
import           Test.Tasty.HUnit

import           Crypto.PHKDF.HMAC

d :: ByteString -> ByteString
d = B.decodeBase16Lenient

tests :: [TestTree]
tests =
  [ testGroup "rfc4231 test vectors"
      [ testCase ("rfc4231-" ++ show n) (run x)
      | (n,x) <- zip [1..] testVectors
      ]
  ]
  where
    hmac :: ByteString -> ByteString -> ByteString
    hmac k m = hmacCtx_init k & hmacCtx_update m & hmacCtx_finalize
    run x = B.encodeBase16 (hmac (key x) (msg x)) @?= B.encodeBase16 (out x)

testVectors :: [TestVector]
testVectors =
  [ rfc4231_testCase1
  , rfc4231_testCase2
  , rfc4231_testCase3
  , rfc4231_testCase4
  , rfc4231_testCase5
  , rfc4231_testCase6
  , rfc4231_testCase7
  ]

data TestVector = TestVector
  { key :: !ByteString
  , msg :: !ByteString
  , out :: !ByteString
  }

rfc4231_testCase1 = TestVector
  { key = B.replicate 20 0x0b
  , msg = "Hi There"
  , out = d "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
  }

rfc4231_testCase2 = TestVector
  { key = "Jefe"
  , msg = "what do ya want for nothing?"
  , out = d "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
  }

rfc4231_testCase3 = TestVector
  { key = B.replicate 20 0xaa
  , msg = B.replicate 50 0xdd
  , out = d "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
  }

rfc4231_testCase4 = TestVector
  { key = d "0102030405060708090a0b0c0d0e0f10111213141516171819"
  , msg = B.replicate 50 0xcd
  , out = d "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
  }

{-

RFC4231 doesn't provide the second half of the output. This seem odd.
Unlike HKDF, truncation is not explicitly part of the HMAC interface.
Is this test vector supposed teach that this is a safe way to use HMAC?

To avoid unnecessary complications here, I just provided the (unofficial)
second half of the output.

-}

rfc4231_testCase5 = TestVector
  { key = B.replicate 20 0x0c
  , msg = "Test With Truncation"
  , out = d "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5"
  }

rfc4231_testCase6 = TestVector
  { key = B.replicate 131 0xaa
  , msg = "Test Using Larger Than Block-Size Key - Hash Key First"
  , out = d "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
  }

rfc4231_testCase7 = TestVector
  { key = B.replicate 131 0xaa
  , msg = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
  , out = d "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
  }
