{-# LANGUAGE OverloadedStrings #-}
import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as B
import           Data.Function((&))
import           Data.Word
import           Test.Tasty
import           Test.Tasty.HUnit

import Crypto.Sha256
import Crypto.Sha256.Hmac
import Crypto.Sha256.Hkdf
import qualified HMAC
import qualified HKDF
import qualified PBKDF2

d :: ByteString -> ByteString
d = B.decodeBase16Lenient

main = do
    defaultMain $ testGroup "toplevel" [
      testGroup "sha256"
        [ testCase ("sha256-" ++ show n) (run x)
        | (n,x) <- zip [1..] testVectors
        ],
      testGroup "hmac" HMAC.tests,
      testGroup "hkdf" HKDF.tests,
      testGroup "pbkdf2" PBKDF2.tests,
      testGroup "bitstrings" testBitstrings
     ]
  where
    run :: SHA256TestVector -> Assertion
    run x = B.encodeBase16 (hash (msg x)) @?= B.encodeBase16 (out x)

data SHA256TestVector = SHA256TestVector
  { msg :: !ByteString
  , out :: !ByteString
  }

testVectors :: [SHA256TestVector]
testVectors =
  [ sha256_testCase1
  , sha256_testCase2
  , sha256_testCase3
  , sha256_testCase4
  , sha256_testCase5
  , sha256_testCase6
  ]

sha256_testCase1 = SHA256TestVector
  { msg = "abc"
  , out = d "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  }

sha256_testCase2 = SHA256TestVector
  { msg = ""
  , out = d "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }

sha256_testCase3 = SHA256TestVector
  { msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  , out = d "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
  }

sha256_testCase4 = SHA256TestVector
  { msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
  , out = d "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
  }

sha256_testCase5 = SHA256TestVector
  { msg = "0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcde"
  , out = d "a518fbe53475606f8cdf66dfeae0c416f774694843647c810c6f89fd7d24ae4c"
  }

sha256_testCase6 = SHA256TestVector
  { msg = "0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef"
  , out = d "37e68bd16eb5be2f6d591cef9c099db166faf048122f736307fb92a1670ef552"
  }

testBitstrings :: [TestTree]
testBitstrings = [testCase "bitstrings-0" (out @?= "731590e201d1e0c020e78c6d8dbacf6e1e7ab8eae42de9e5dc370d96270f1c32")]
 where
  bitstring :: ByteString
  bitstring = hkdf (d "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041") "" "" 128
  myKey = hmacKey (d "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
  sha256bits :: ByteString -> Word64 -> ByteString
  sha256bits x len = sha256_init &
                     sha256_finalizeBits_toByteString x len
  hmacbits :: ByteString -> Word64 -> ByteString
  hmacbits x len = hmacCtx_init myKey &
                   hmacCtx_finalizeBits_toByteString x len
  out = sha256_init &
        sha256_feeds [ sha256bits bitstring n | n <- [0..1024] ] &
        sha256_feeds [ hmacbits bitstring n  | n <- [0..1024] ] &
        sha256_finalize
