{-# LANGUAGE OverloadedStrings #-}
import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as B
import           Data.Function((&))
import           Test.Tasty
import           Test.Tasty.HUnit

import Crypto.Sha256

d :: ByteString -> ByteString
d = B.decodeBase16Lenient

sha256 :: ByteString -> ByteString
sha256 x =
  sha256_init &
  sha256_update x &
  sha256_finalize

main = do
    defaultMain $ testGroup "sha256" 
      [ testCase ("sha256-" ++ show n) (run x)
      | (n,x) <- zip [1..] testVectors
      ]
  where
    run :: SHA256TestVector -> Assertion
    run x = B.encodeBase16 (sha256 (msg x)) @?= B.encodeBase16 (out x)

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
