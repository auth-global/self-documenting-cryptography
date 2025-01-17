-------------------------------------------------------------------------------
-- |
-- Module:      Crypto.HashString
-- Copyright:   (c) 2024 Auth Global
-- License:     Apache2
--
-- binary string types supporting constant-time base16 encoding and decoding, as
-- well as constant time lexicographic comparisons. Note that the time required
-- does depend linearly on length, but is otherwise data-independent.
--
-------------------------------------------------------------------------------

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