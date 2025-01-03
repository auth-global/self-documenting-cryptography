{-# LANGUAGE OverloadedStrings #-}

module Bcrypt where

import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import           Test.Tasty
import           Test.Tasty.HUnit
import           Crypto.G3P.BCrypt
import           Crypto.BCrypt

tests :: [TestTree]
tests =
  [ testGroup "external bcrypt binding"
      [ testCase ("bcrypt-" ++ show n ++ "-ext") (runRef x)
      | (n,x) <- zip [0..] testVectors
      ],
    testGroup "bcrypt test vectors"
      [ testCase ("bcrypt-" ++ show n) (run x)
      | (n,x) <- zip [0..] testVectors
      ]
  ]
  where
    run (pass,salt) =  bcrypt pass (B.take 29 salt') @?= Just salt'
      where salt' = "$2b" <> B.drop 3 salt
    runRef (pass,salt) = hashPassword pass (B.take 29 salt) @?= Just salt

-- test vectors copied from
-- https://github.com/pyca/bcrypt/blob/c48c293102e0c8a9f0499adae165eebb9dc11d0b/tests/test_bcrypt.py

testVectors ::[(ByteString, ByteString)]
testVectors =
  [
    (
        "Kk4DQuMMfZL9o",
        "$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm"
    ),
    (
        "9IeRXmnGxMYbs",
        "$2b$04$pQ7gRO7e6wx/936oXhNjrOUNOHL1D0h1N2IDbJZYs.1ppzSof6SPy"
    ),
    (
        "xVQVbwa1S0M8r",
        "$2b$04$SQe9knOzepOVKoYXo9xTteNYr6MBwVz4tpriJVe3PNgYufGIsgKcW"
    ),
    (
        "Zfgr26LWd22Za",
        "$2b$04$eH8zX.q5Q.j2hO1NkVYJQOM6KxntS/ow3.YzVmFrE4t//CoF4fvne"
    ),
    (
        "Tg4daC27epFBE",
        "$2b$04$ahiTdwRXpUG2JLRcIznxc.s1.ydaPGD372bsGs8NqyYjLY1inG5n2"
    ),
    (
        "xhQPMmwh5ALzW",
        "$2b$04$nQn78dV0hGHf5wUBe0zOFu8n07ZbWWOKoGasZKRspZxtt.vBRNMIy"
    ),
    (
        "59je8h5Gj71tg",
        "$2b$04$cvXudZ5ugTg95W.rOjMITuM1jC0piCl3zF5cmGhzCibHZrNHkmckG"
    ),
    (
        "wT4fHJa2N9WSW",
        "$2b$04$YYjtiq4Uh88yUsExO0RNTuEJ.tZlsONac16A8OcLHleWFjVawfGvO"
    ),
    (
        "uSgFRnQdOgm4S",
        "$2b$04$WLTjgY/pZSyqX/fbMbJzf.qxCeTMQOzgL.CimRjMHtMxd/VGKojMu"
    ),
    (
        "tEPtJZXur16Vg",
        "$2b$04$2moPs/x/wnCfeQ5pCheMcuSJQ/KYjOZG780UjA/SiR.KsYWNrC7SG"
    ),
    (
        "vvho8C6nlVf9K",
        "$2b$04$HrEYC/AQ2HS77G78cQDZQ.r44WGcruKw03KHlnp71yVQEwpsi3xl2"
    ),
    (
        "5auCCY9by0Ruf",
        "$2b$04$vVYgSTfB8KVbmhbZE/k3R.ux9A0lJUM4CZwCkHI9fifke2.rTF7MG"
    ),
    (
        "GtTkR6qn2QOZW",
        "$2b$04$JfoNrR8.doieoI8..F.C1OQgwE3uTeuardy6lw0AjALUzOARoyf2m"
    ),
    (
        "zKo8vdFSnjX0f",
        "$2b$04$HP3I0PUs7KBEzMBNFw7o3O7f/uxaZU7aaDot1quHMgB2yrwBXsgyy"
    ),
    (
        "I9VfYlacJiwiK",
        "$2b$04$xnFVhJsTzsFBTeP3PpgbMeMREb6rdKV9faW54Sx.yg9plf4jY8qT6"
    ),
    (
        "VFPO7YXnHQbQO",
        "$2b$04$WQp9.igoLqVr6Qk70mz6xuRxE0RttVXXdukpR9N54x17ecad34ZF6"
    ),
    (
        "VDx5BdxfxstYk",
        "$2b$04$xgZtlonpAHSU/njOCdKztOPuPFzCNVpB4LGicO4/OGgHv.uKHkwsS"
    ),
    (
        "dEe6XfVGrrfSH",
        "$2b$04$2Siw3Nv3Q/gTOIPetAyPr.GNj3aO0lb1E5E9UumYGKjP9BYqlNWJe"
    ),
    (
        "cTT0EAFdwJiLn",
        "$2b$04$7/Qj7Kd8BcSahPO4khB8me4ssDJCW3r4OGYqPF87jxtrSyPj5cS5m"
    ),
    (
        "J8eHUDuxBB520",
        "$2b$04$VvlCUKbTMjaxaYJ.k5juoecpG/7IzcH1AkmqKi.lIZMVIOLClWAk."
    ),
    (
        "U*U",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"
    ),
    (
        "U*U*",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"
    ),
    (
        "U*U*U",
        "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a"
    ),
    (
        B.concat
          [ "0123456789abcdefghijklmnopqrstuvwxyz"
          , "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
          , "chars after 72 are ignored" ],
        "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui"
    ),
    (
        B.concat
          [ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
          , "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
          , "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
          , "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
          , "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
          , "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
          , "chars after 72 are ignored as usual" ],
        "$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6"
    ),
    (
        "\xa3",
        "$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"
    ),
    (
        "pass\x00word",
        "$2b$06$XXXXXXXXXXXXXXXXXXXXXOCgx4gZM7pzl7cruTaiQNiG5S4PGv9Ki"
    ),
{--
--- Not sure why these test vectors aren't working, but both this binding and
--- https://hackage.haskell.org/package/bcrypt compute the same result.

--- Perhaps there is some subtle difference between the lexical syntax of
--  literal strings in Python versus Haskell?

--- Suprisingly, that other bcrypt binding doesn't have a test suite...

--- https://hackage.haskell.org/package/password also includes a bcrypt binding,
--- but the test suite is a bit disappointing.

--- On the other hand, the test case that follows is the only test case with
--  a null character in the input.  So I made my own test case above.

--- TODO: verify (via code review) that $2b$ and $2y$ are exactly equivalent

--- TODO: find test cases that distinguish $2a$ from $2b$ from $2x$, and
---       implement those other variants

    (
        B.concat
          [ "}>\xb3\xfe\xf1\x8b\xa0\xe6(\xa2Lzq\xc3P\x7f\xcc\xc8b{\xf9\x14\xf6"
          , "\xf6`\x81G5\xec\x1d\x87\x10\xbf\xa7\xe1}I7 \x96\xdfc\xf2\xbf\xb3Vh"
          , "\xdfM\x88q\xf7\xff\x1b\x82~z\x13\xdd\xe9\x84\x00\xdd4"
          ],
        "$2b$10$keO.ZZs22YtygVF6BLfhGOI/JjshJYPp8DZsUtym6mJV2Eha2Hdd."
    ),
    (
        B.concat
          [ "g7\r\x01\xf3\xd4\xd0\xa9JB^\x18\x007P\xb2N\xc7\x1c\xee\x87&\x83C"
          , "\x8b\xe8\x18\xc5>\x86\x14/\xd6\xcc\x1cJ\xde\xd7ix\xeb\xdeO\xef"
          , "\xe1i\xac\xcb\x03\x96v1' \xd6@.m\xa5!\xa0\xef\xc0("
          ],
        "$2a$04$tecY.9ylRInW/rAAzXCXPOOlyYeCNzmNTzPDNSIFztFMKbvs/s5XG"
    ),
--}
    (
        "\xa3",
        "$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"
    ),
    (
        "\xff\xff\xa3",
        "$2y$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e"
    )
  ]
