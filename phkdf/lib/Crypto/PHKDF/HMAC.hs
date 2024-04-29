{-# LANGUAGE ViewPatterns, LambdaCase, BangPatterns #-}

{- |

An alternate implementation of HMAC in terms of cryptohash-sha256, because
the HMAC implementation provided there doesn't support precomputed keys or
streaming inputs.  TODO: prepare a patch for cryptohash-sha256.

-}


module Crypto.PHKDF.HMAC
  ( hmac
  , HmacKeyPlain
  , HmacKey()
  , hmacKey
  , hmacKey_hashed
  , hmacKey_toHashed
  , hmacKey_peekInput
  , hmacKey_forgetInput
  , hmacKey_run
  , HmacKeyHashed()
  , hmacKeyHashed
  , hmacKeyHashed_toKey
  , HmacKeyPrefixed()
  , hmacKeyPrefixed
  , hmacKeyPrefixed_init
  , hmacKeyPrefixed_initHashed
  , hmacKeyPrefixed_feeds
  , hmacKeyPrefixed_feedsWith
  , hmacKeyPrefixed_run
  , HmacCtx()
  , hmacCtx
  , hmacCtx_init
  , hmacCtx_initWith
  , hmacCtx_update,  hmacCtx_feed
  , hmacCtx_updates, hmacCtx_feeds
  , hmacCtx_finalize
  ) where

import qualified Crypto.Hash.SHA256 as SHA256
import           Data.Bits(xor)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Function((&))
import           Data.Foldable(Foldable, toList)

import           Crypto.PHKDF.HMAC.Subtle
import           Crypto.Encoding.PHKDF(takeBs', dropBs)


hmacKey :: HmacKeyPlain -> HmacKey
hmacKey key = HmacKeyInput key (hmacKeyHashed key)

hmacKey_peekInput :: HmacKey -> Maybe HmacKeyPlain
hmacKey_peekInput = \case
  HmacKeyInput a _ -> Just a
  HmacKeyOutput _  -> Nothing

hmacKey_forgetInput :: HmacKey -> HmacKey
hmacKey_forgetInput = \case
  HmacKeyInput _ b -> HmacKeyOutput b
  x@(HmacKeyOutput _) -> x

-- | A forgetful initialization, equivalent to 'hmacKey_forgetInput . hmacKey'
hmacKey_hashed :: HmacKeyPlain -> HmacKey
hmacKey_hashed = HmacKeyOutput . hmacKeyHashed

hmacKey_run :: HmacKey -> HmacCtx
hmacKey_run = hmacCtx_init

hmacKeyHashed :: HmacKeyPlain -> HmacKeyHashed
hmacKeyHashed key = HmacKeyHashed ipad opad
  where
    ipad = tweak 0x36
    opad = tweak 0x5c
    k1 = if B.length key > 64 then SHA256.hash key else key
    k2 = B.append k1 (B.replicate (64 - B.length k1) 0)
    hash x = SHA256.update SHA256.init x & hmacKeyPadding_unsafeFromCtx
    tweak c = hash (B.map (xor c) k2)

hmacKeyHashed_toKey :: HmacKeyHashed -> HmacKey
hmacKeyHashed_toKey = HmacKeyOutput

hmacKeyHashed_run :: HmacKeyHashed -> HmacCtx
hmacKeyHashed_run key = HmacCtx
    { hmacCtx_ipadCtx = hmacKeyHashed_ipadCtx key
    , hmacCtx_opad = hmacKeyHashed_opad key
    }

hmacKeyHashed_runWith :: HmacKeyHashed -> ByteString -> HmacCtx
hmacKeyHashed_runWith key str = HmacCtx
    { hmacCtx_ipadCtx = SHA256.update (hmacKeyHashed_ipadCtx key) str
    , hmacCtx_opad = hmacKeyHashed_opad key
    }

hmacKeyPrefixed :: HmacKeyPlain -> HmacKeyPrefixed
hmacKeyPrefixed = hmacKeyPrefixed_initHashed . hmacKeyHashed

hmacKeyPrefixed_init :: HmacKey -> HmacKeyPrefixed
hmacKeyPrefixed_init = hmacKeyPrefixed_initHashed . hmacKey_toHashed

hmacKeyPrefixed_initHashed :: HmacKeyHashed -> HmacKeyPrefixed
hmacKeyPrefixed_initHashed (HmacKeyHashed ipad opad) = HmacKeyPrefixed 1 ipad opad

hmacKeyPrefixed_feeds :: Foldable f => f ByteString -> HmacKeyPrefixed -> (ByteString, HmacKeyPrefixed)
hmacKeyPrefixed_feeds = hmacKeyPrefixed_feedsWith id

hmacKeyPrefixed_feedsWith :: Foldable f => (a -> ByteString) -> f a -> HmacKeyPrefixed -> (ByteString, HmacKeyPrefixed)
hmacKeyPrefixed_feedsWith f = go . map f . toList
  where
    go bss !st =
      case takeBs' 64 bss of
        [] -> (B.concat bss, st)
        x  -> go (dropBs 64 bss) st'
                where
                  st' = HmacKeyPrefixed
                    { hmacKeyPrefixed_blockCount = blockCount + 1
                    , hmacKeyPrefixed_ipad = ipad'
                    , hmacKeyPrefixed_opad = opad
                    }
                  blockCount = hmacKeyPrefixed_blockCount st
                  ipad' =
                    hmacKeyPrefixed_ipad st &
                    hmacKeyPadding_runWith blockCount &
                    flip SHA256.updates x &
                    hmacKeyPadding_unsafeFromCtx
                  opad = hmacKeyPrefixed_opad st

hmacKeyPrefixed_run :: HmacKeyPrefixed -> HmacCtx
hmacKeyPrefixed_run key = HmacCtx
    { hmacCtx_ipadCtx = ipadCtx
    , hmacCtx_opad    = opad    }
  where
    blockCount = hmacKeyPrefixed_blockCount key
    ipad = hmacKeyPrefixed_ipad key
    opad = hmacKeyPrefixed_opad key
    ipadCtx = hmacKeyPadding_runWith blockCount ipad

-- | A simple interface to HMAC-SHA-256. Note that this function was written
--   to make partial application an efficient way to compute the hmac of
--   multiple messages with exactly the same key:
--
--   @
--     let hash = hmac "my-key"
--      in (hash "message 1", hash "message 2")
--   @

-- Written in the point-free style to help ensure the above claim is true

hmac :: HmacKeyPlain -> ByteString -> ByteString
hmac = fmap hmacCtx_finalize . hmacCtx_initWith . hmacKey_hashed

hmacCtx :: HmacKeyPlain -> HmacCtx
hmacCtx = hmacCtx_init . hmacKey_hashed

-- | Initialize a new empty HMAC context from a precomputed HMAC key.

hmacCtx_init :: HmacKey -> HmacCtx
hmacCtx_init = hmacKeyHashed_run . hmacKey_toHashed

hmacCtx_initWith :: HmacKey -> ByteString -> HmacCtx
hmacCtx_initWith = hmacKeyHashed_runWith . hmacKey_toHashed

-- | Append a bytestring onto the end of the message argument to HMAC.

hmacCtx_update ::  HmacCtx -> ByteString -> HmacCtx
hmacCtx_update = flip hmacCtx_feed

hmacCtx_feed :: ByteString -> HmacCtx -> HmacCtx
hmacCtx_feed b (HmacCtx ic oc) = HmacCtx (SHA256.update ic b) oc

-- | Append zero or more bytestrings onto the end of the message argument to
--   HMAC.

hmacCtx_updates :: Foldable f => HmacCtx -> f ByteString -> HmacCtx
hmacCtx_updates = flip hmacCtx_feeds

hmacCtx_feeds :: Foldable f => f ByteString -> HmacCtx -> HmacCtx
hmacCtx_feeds bs (HmacCtx ic oc) = HmacCtx (SHA256.updates ic (toList bs)) oc

-- | Finish computing the final 32-byte hash for an HMAC context.

hmacCtx_finalize :: HmacCtx -> ByteString
hmacCtx_finalize (HmacCtx ic oc) = outer
  where
    inner = SHA256.finalize ic
    outer = SHA256.finalize (SHA256.update (hmacKeyPadding_runWith 1 oc) inner)
