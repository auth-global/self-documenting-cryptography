module Crypto.HashString
     ( HashString
     , fromShort
     , fromShortBase16
     -- , fromShortBase64
     , toShort
     , toShortBase16
     -- , toShortBase64
     , fromByteString
     , fromBase16
     -- , fromBase64
     , toByteString
     , toBase16
     -- , toBase64
     , toBase16Builder
     -- , toBase64Builder
     , xorLeft
     , xorMin
     , xorMax
     , takeBytes
     ) where

import Crypto.HashString.Implementation