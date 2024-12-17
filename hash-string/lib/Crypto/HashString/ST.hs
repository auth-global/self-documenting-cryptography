module Crypto.HashString.ST
    ( HashStringRef
    , 
    ) where

import Crypto.HashString.Subtle

zeroRef :: Int -> ST s (HashStringRef s)

initRef :: HashString -> ST s (HashStringRef s)

mutableXor :: HashStringRef s -> HashString -> ST s ()

mutableXorRef :: HashStringRef s -> HashStringRef s -> ST s ()

freezeRef :: HashStringRef s -> ST s HashString