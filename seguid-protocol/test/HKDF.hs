-- Test Vectors for HKDF-HMAC-SHA512, borrowed from https://github.com/brycx/Test-Vector-Generation/blob/72810c03e22af1b26fe5b254340e9ae5d9e44b06/HKDF/hkdf-hmac-sha2-test-vectors.md

{-# LANGUAGE OverloadedStrings #-}

module HKDF where

import Data.ByteString(ByteString)
import qualified Data.ByteString.Base16 as Base16
import Crypto.Seguid.HKDF
import Test.Tasty
import Test.Tasty.HUnit

d :: ByteString -> ByteString
d = Base16.decodeLenient

data TestVector = TestVector
  { ikm   :: !ByteString
  , salt  :: !ByteString
  , info  :: !ByteString
  , dkLen :: !Int
  , out   :: !ByteString
  }

tests :: TestTree
tests = testGroup "HKDF-HMAC-SHA512 Test Vectors"
    [ testCase (show n) (run x)
    | (n,x) <- zip [1..] testVectors
    ]
  where
    run x = Base16.encode (hkdf (salt x) (ikm x) (info x) (dkLen x)) @?= Base16.encode (out x)

testVectors :: [TestVector]
testVectors =
  [ rfc5869_testCase1
  , rfc5869_testCase2
  , rfc5869_testCase3
  , rfc5869_testCase4
  , rfc5869_testCase7
  , testCase1
  , testCase2
  , testCase3
  , testCase4
  , testCase5
  , testCase6
  ]

rfc5869_testCase1 = TestVector
  { ikm = d "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  , salt = d "000102030405060708090a0b0c"
  , info = d "f0f1f2f3f4f5f6f7f8f9"
  , dkLen = 42
  , out = d "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"
  }

rfc5869_testCase2 = TestVector
  { ikm = d "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
  , salt = d "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
  , info = d "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
  , dkLen = 82
  , out = d "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a93"
  }

rfc5869_testCase3 = TestVector
  { ikm = d "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  , salt = d ""
  , info = d ""
  , dkLen = 42
  , out = d "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac"
  }

rfc5869_testCase4 = TestVector
  { ikm = d "0b0b0b0b0b0b0b0b0b0b0b"
  , salt = d "000102030405060708090a0b0c"
  , info = d "f0f1f2f3f4f5f6f7f8f9"
  , dkLen = 42
  , out = d "7413e8997e020610fbf6823f2ce14bff01875db1ca55f68cfcf3954dc8aff53559bd5e3028b080f7c068"
  }

rfc5869_testCase7 = TestVector
  { ikm = d "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
  , salt = d ""
  , info = d ""
  , dkLen = 42
  , out = d "1407d46013d98bc6decefcfee55f0f90b0c7f63d68eb1a80eaf07e953cfc0a3a5240a155d6e4daa965bb"
  }

testCase1 = TestVector
  { ikm = d "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  , salt = d "000102030405060708090a0b0c"
  , info = d ""
  , dkLen = 32
  , out = d "f81b87481a18b664936daeb222f58cba0ebc55f5c85996b9f1cb396c327b70bb"
  }
  
testCase2 = TestVector
  { ikm = d "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
  , salt = "salt"
  , info = "random InF\x00"
  , dkLen = 128
  , out = d "a246ef99f6a0f783fc004682508e6f288f036469788f004fcbac9414caa889fa175e746ee663914d678c155d510fa536f7d49b1054e85e7751d9745ea02079a78608eec9aacdd82fa9421d6223c158c71b76bcf9008b50e8aac027a73f98643eb3947106b65c0bc9a2983404fd4d0fce0735d639379b1934709c8b2999b5989e"
  }

testCase3 = TestVector
  { ikm = "password"
  , salt = d "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
  , info = d ""
  , dkLen = 256
  , out = d "245d63179146a61ca1a25f92c38391d406bb52da4b773714fb0e43ce9084ce430f43e1980a8817cf0af320fb684776d81f674d2b187449d62200d3e39cb51ab7a444f7964944895ad36b37432fb400fdca0181a9ebda41f9d124d58f8a696dde9bd104a93fbbe3c93b94dd06a2254894b489822ab08daa791f8962a492a6a7379e8710b46fe85c8bf9d64a957641164577d5b5afdaf8fad1fb3879a3c8bc8425b9f265462b59785e7cf7855e6c571353c38907a8d9b0a01c228bb3a1792039e8728ea01c9391601f1626da771f65f2322116ddc4e192d98da81b0402fd664ef89801a4905d9557be5c7f01bf8381fae7d325c3dc7a5795dc760b9668eb63f8ee"
  }

testCase4 = TestVector
  { ikm = d "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  , salt = "s$#$#%$#SBGHWE@#W#lt"
  , info = "random InF\x00"
  , dkLen = 256
  , out = d "e93182a8af74a1e70a6202075759bbbceb1926a18aa9f9ee317965570b507cea7ef11f94d83760bb6f8a2f6031edb581c1ae43f45ead820223d34c6ffadab43d3cfaf9cd782b8aa7bd2ebab8663b51d4e40b9a659a7e262630581fee55ac986770e88f580c8d8b82deba4d1c28bce4dc7a579456ed30a94a1782cab84699a4302ef8d24f23e9122ef2daaba4fd3d84c812c4b3a8d4788397fd38ddccf59d60a8330000cb04e5aa2d3e16e56dbccd8ca68020abcb3bc097788d38dfd2e241ba7772ba188c29d7f4d010b421875c9e7165ed2ebcf338b81071eca62300c9ca9840b6f1fc9403752536b3eca147e9fbf127ff88d33b984582ced74fa029b50f441e"
  }

testCase5 = TestVector
  { ikm = "passwordPASSWORDpassword"
  , salt = "salt"
  , info = d ""
  , dkLen = 32
  , out = d "1ef9dccc02d5786f0d7133da824afe212547f2d8c97e9299345db86814dcb9b8"
  }

testCase6 = TestVector
  { ikm = "pass\x00word"
  , salt = "saltSALTSALTSALTSALTSALTSALTSALTSALTSALTSALTSALTSALT"
  , info = d "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
  , dkLen = 16
  , out = d "8ae15623215eaaa156bad552f411c4ad"
  }
