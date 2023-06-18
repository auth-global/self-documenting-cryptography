module Crypto.Seguid.Protocol
  ( seguidProtocol
  ) where

import Data.ByteString(ByteString)
import qualified Data.ByteString as B
import Data.Foldable(Foldable)
import Crypto.Seguid.HKDF

seguidProtocol :: Foldable f => ByteString -> f ByteString -> ByteString -> Int -> ByteString
seguidProtocol salt args info bits = out
  where
    prk = hkdfExtractTuple salt args
    out = hkdfExpandBitLengthStrict prk info bits