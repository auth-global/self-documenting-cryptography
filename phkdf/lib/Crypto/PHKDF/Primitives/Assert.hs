module Crypto.PHKDF.Primitives.Assert where

import Data.Bits
import Data.Word
import Crypto.PHKDF.Primitives.Subtle

phkdfCtx_assertBufferPosition' :: Word64 -> PhkdfCtx -> PhkdfCtx
phkdfCtx_assertBufferPosition' n ctx
  | len .&. 63 /= n .&. 63
  = error ("phkdf buffer position mismatch: " ++ show len ++ " /= " ++ show n ++ " (mod 64)")
  | otherwise = ctx
  where len = phkdfCtx_byteLen ctx

phkdfSlowCtx_assertBufferPosition' :: Word64 -> PhkdfSlowCtx -> PhkdfSlowCtx
phkdfSlowCtx_assertBufferPosition' n ctx
  | len .&. 63 /= n .&. 63
  = error ("phkdf buffer position mismatch: " ++ show len ++ " /= " ++ show n ++ " (mod 64)")
  | otherwise = ctx
  where len = phkdfCtx_byteLen (phkdfSlowCtx_phkdfCtx ctx)

-- TODO: set up a cabal flag and CPP to select between assertions enabled/not

{--}

phkdfCtx_assertBufferPosition :: Word64 -> PhkdfCtx -> PhkdfCtx
phkdfCtx_assertBufferPosition = phkdfCtx_assertBufferPosition'


phkdfSlowCtx_assertBufferPosition :: Word64 -> PhkdfSlowCtx -> PhkdfSlowCtx
phkdfSlowCtx_assertBufferPosition = phkdfSlowCtx_assertBufferPosition'

--}

{--

phkdfCtx_assertBufferPosition :: Word64 -> PhkdfCtx -> PhkdfCtx
phkdfCtx_assertBufferPosition _ = id

phkdfSlowCtx_assertBufferPosition :: Word64 -> PhkdfSlowCtx -> PhkdfSlowCtx
phkdfSlowCtx_assertBufferPosition _ = id

--}
