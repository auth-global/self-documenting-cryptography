{-# LANGUAGE MagicHash #-}

module Crypto.Sha256.Subtle where

import GHC.Exts

type Sha256MutStatePtr# = MutableByteArray#

type Sha256StatePtr# = ByteArray#

type Sha256MutCtxPtr# = MutableByteArray#

type Sha256CtxPtr# = ByteArray#

data Sha256State = Sha256State# { unSha256State# :: Sha256StatePtr# }

data Sha256Ctx = Sha256Ctx# { unSha256Ctx# :: Sha256CtxPtr# }
