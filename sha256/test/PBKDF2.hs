-- Test Vectors for PBKDF2-HMAC-SHA256

{-# LANGUAGE OverloadedStrings #-}

module PBKDF2 where

import           Data.Base16.Types
import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as B
import qualified Data.ByteString.Short as SB
import           Data.Function((&))
import           Data.Int
import           Data.Word
import           Test.Tasty
import           Test.Tasty.HUnit

import           Crypto.HashString (HashString(..))
import qualified Crypto.HashString as HS
import           Crypto.Sha256.Pbkdf2
import           Crypto.Sha256.Hmac(hmacKey)

d :: ByteString -> ByteString
d = B.decodeBase16Lenient

tests :: [TestTree]
tests =
  [ testGroup "test vectors"
      [ testCase (show n) (run x)
      | (n,x) <- zip ([1..3]++[5..]) testVectors
      ]
  ]
  where
    run x = HS.toBase16 (pbkdf2 (hmacKey (password x)) (salt x) (rounds x) (B.length (out x))) @?= extractBase16 (B.encodeBase16' (out x))

testVectors :: [TestVector]
testVectors =
  [ testCase1
  , testCase2
  , testCase3
  , testCase5
  , testCase6
  , testCase7
  , testCase8
  , testCase9
  ]

data TestVector = TestVector
  { password :: !ByteString
  , salt :: !ByteString
  , rounds :: !Word64
  , out :: !ByteString
  }

-- Borrowed from:
-- https://github.com/brycx/Test-Vector-Generation/blob/72810c03e22af1b26fe5b254340e9ae5d9e44b06/PBKDF2/pbkdf2-hmac-sha2-test-vectors.md

-- FIXME: the code coverage of these test vectors leaves much to be desired.

testCase1 = TestVector
  { password = "password"
  , salt = "salt"
  , rounds = 1
  , out = d "120fb6cffcf8b32c43e7225256c4f837a86548c9"
  }

testCase2 = TestVector
  { password = "password"
  , salt = "salt"
  , rounds = 2
  , out = d "ae4d0c95af6b46d32d0adff928f06dd02a303f8e"
  }

testCase3 = TestVector
  { password = "password"
  , salt = "salt"
  , rounds = 4096
  , out = d "c5e478d59288c841aa530db6845c4c8d962893a0"
  }

testCase5 = TestVector
  { password = "passwordPASSWORDpassword"
  , salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt"
  , rounds = 4096
  , out = d "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c"
  }

testCase6 = TestVector
  { password = "pass\x00word"
  , salt = "sa\x00lt"
  , rounds = 4096
  , out = d "89b69d0516f829893c696226650a8687"
  }

testCase7 = TestVector
  { password = "passwd"
  , salt = "salt"
  , rounds = 1
  , out = d "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783c294e850150390e1160c34d62e9665d659ae49d314510fc98274cc79681968104b8f89237e69b2d549111868658be62f59bd715cac44a1147ed5317c9bae6b2a"
  }

testCase8 = TestVector
  { password = "Password"
  , salt = "NaCL"
  , rounds = 80000
  , out = d "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d62aae85a11cdde829d89cb6ffd1ab0e63a981f8747d2f2f9fe5874165c83c168d2eed1d2d5ca4052dec2be5715623da019b8c0ec87dc36aa751c38f9893d15c3"
  }

testCase9 = TestVector
  { password = "Password"
  , salt = "sa\x00lt"
  , rounds = 4096
  , out = d "436c82c6af9010bb0fdb274791934ac7dee21745dd11fb57bb90112ab187c495ad82df776ad7cefb606f34fedca59baa5922a57f3e91bc0e11960da7ec87ed0471b456a0808b60dff757b7d313d4068bf8d337a99caede24f3248f87d1bf16892b70b076a07dd163a8a09db788ae34300ff2f2d0a92c9e678186183622a636f4cbce15680dfea46f6d224e51c299d4946aa2471133a649288eef3e4227b609cf203dba65e9fa69e63d35b6ff435ff51664cbd6773d72ebc341d239f0084b004388d6afa504eee6719a7ae1bb9daf6b7628d851fab335f1d13948e8ee6f7ab033a32df447f8d0950809a70066605d6960847ed436fa52cdfbcf261b44d2a87061"
  }
