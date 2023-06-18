{-# LANGUAGE OverloadedStrings #-}

module Crypto.Seguid.Protocol.Constants
  ( seguid_v0
  , seguid_v0_salt
  ) where

import Data.ByteString(ByteString)

import Crypto.Seguid.Protocol

{-
seguid-v0-salt = f(1) || ... || f(32)

f(n) = the fractional part of the n^th prime integer to the 3/4 power,
       truncated to 32 bits

See PreinitSalt.hs in test suite for code to generate and verify
this initialization vector:
-}

seguid_v0_salt :: ByteString
seguid_v0_salt =
  "\xAE\x89\xF9\x95\x47\x8D\xC6\x44\x57\xFC\xD2\xB8\x4D\xB3\x4B\x74\
  \\x0A\x44\x58\x32\xD8\xA8\xC2\x09\x5F\x44\xD4\xC0\x19\xBA\x4B\x79\
  \\x80\xA8\xE4\x00\x7F\x2D\xAD\xF5\x23\x44\x22\x18\x00\x87\xE5\xF9\
  \\x33\xE5\x5F\xA8\xCA\xBD\xC3\xF6\xF3\x4B\x6A\xDD\xA4\x98\xEF\xFB\
  \\x49\xC7\xB0\xC5\xD3\xC1\x3B\xA6\x6B\x18\x50\x03\x75\x93\xB7\x7C\
  \\xF9\x67\x47\xDC\x7F\x99\xCF\x1B\x7F\x9B\xE3\xF5\xF9\xEC\xF0\xEE\
  \\xE8\x97\x85\x6E\xDC\x12\x2A\x7E\x54\xE7\x41\xD2\x44\xD3\x93\x80\
  \\xBB\xF1\xC5\xBA\xA8\x8E\x97\x5C\xD4\xD8\xC9\x14\xB8\xBB\xD0\x76"

seguid_v0 :: Foldable f => f ByteString -> Int -> ByteString
seguid_v0 args len = seguidProtocol seguid_v0_salt args "https://docs.auth.global/seguid-v0" len

{--
seguid_v1_args :: [ByteString]
seguid_v1_args = [
   "https://docs.auth.global/seguid-v1",
   "ipns:// TODO: fill this in before any release at all",
   "git:/ TODO: fill this in after it's been generated"
 ]

compute_seguid_v1_salt :: ByteString
compute_seguid_v1_salt = seguid_v0 seguid_v1_args 1024
--}
