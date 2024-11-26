module Crypto.Sha256.Pbkdf2.Subtle where

import           Crypto.HashString
import           Crypto.Sha256
import           Crypto.Sha256.Hmac

data Pbkdf2Ctx = Pbkdf2Ctx
  { pbkdf2Ctx_password :: !HmacKeyHashed
  , pbkdf2Ctx_ipadCtx :: !Sha256Ctx
  }

data Pbkdf2Gen = Pbkdf2Gen
  { pbkdf2Gen_password :: !HmacKeyHashed
  , pbkdf2Gen_finalize :: !HashString
  , pbkdf2Gen_state :: !HashString
  }
