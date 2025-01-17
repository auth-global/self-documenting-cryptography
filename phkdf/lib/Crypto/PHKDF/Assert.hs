-------------------------------------------------------------------------------
-- |
-- Module:      Crypto.PHKDF.Assert
-- Copyright:   (c) 2024 Auth Global
-- License:     Apache2
--
-------------------------------------------------------------------------------

module Crypto.PHKDF.Assert where

import Data.Bits
import Data.Word
import Crypto.PHKDF.Subtle

phkdfCtx_assertBufferPosition' :: Word64 -> PhkdfCtx -> PhkdfCtx
phkdfCtx_assertBufferPosition' n ctx
  | len .&. 63 /= n .&. 63
  = error ("phkdf buffer position mismatch: " ++ show len ++ " /= " ++ show n ++ " (mod 64)")
  | otherwise = ctx
  where len = phkdfCtx_byteCount ctx

-- TODO: set up a cabal flag and CPP to select between assertions enabled/not

{--}

phkdfCtx_assertBufferPosition :: Word64 -> PhkdfCtx -> PhkdfCtx
phkdfCtx_assertBufferPosition = phkdfCtx_assertBufferPosition'

--}

{--

phkdfCtx_assertBufferPosition :: Word64 -> PhkdfCtx -> PhkdfCtx
phkdfCtx_assertBufferPosition _ = id

--}
