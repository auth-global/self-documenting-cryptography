-------------------------------------------------------------------------------
-- |
-- Module:      Crypto.HashString.FFI
-- Copyright:   (c) 2024 Auth Global
-- License:     Apache2
--
-------------------------------------------------------------------------------

module Crypto.HashString.FFI
    ( HashString(..)
    , base16EncodeLength
    , base16DecodeLength
    , c_const_memcmp_ba
    , c_hexDecode_ba
    , c_hexDecode_mba_bs
    , c_hexEncode_ba
    , c_hexEncode_bs_ba
    , c_xorleft_ba
    , c_xormin_ba
    , c_xormax_ba
    ) where

import Crypto.HashString.Implementation
