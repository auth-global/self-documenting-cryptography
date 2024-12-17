{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Crypto.HashString.ST.Subtle
    ( HashStringRef(..)
    , unsafeFreezeRef
    ) where

import Control.Monad.ST
import Data.Array.Byte

import Crypto.HashString (HashString)

newtype HashStringRef s = HashStringRef { unHashStringRef :: MutableByteArray s } deriving (Eq)

unsafeFreezeRef :: HashStringRef s -> ST s HashString
unsafeFreezeRef = 