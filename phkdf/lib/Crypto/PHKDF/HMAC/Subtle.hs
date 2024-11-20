{-# LANGUAGE ViewPatterns, LambdaCase #-}
{- |

"Internal" data structures representing precomputed HMAC keys and partial HMAC
contexts, supporting incremental computation and backtracking.

-}

module Crypto.PHKDF.HMAC.Subtle
  ( module Crypto.Sha256.Hmac.Subtle
  ) where

import Crypto.Sha256.Hmac.Subtle