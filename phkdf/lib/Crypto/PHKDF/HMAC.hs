{-# LANGUAGE ViewPatterns, LambdaCase, BangPatterns #-}

{- |

An implementation of HMAC-SHA256 that supports precomputed keys, streaming inputs,
backtracking, and bitstring message inputs.

-}

module Crypto.PHKDF.HMAC
  ( module Crypto.Sha256.Hmac
  ) where

import Crypto.Sha256.Hmac            
