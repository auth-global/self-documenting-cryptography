{-# LANGUAGE BangPatterns #-}

-- | An implementation of PBKDF2-HMAC-SHA256

module Crypto.Sha256.Pbkdf2
     ( pbkdf2
     , pbkdf2_index
     , Pbkdf2Ctx()
     , pbkdf2Ctx_init
     , pbkdf2Ctx_feed, pbkdf2Ctx_feeds
     , pbkdf2Ctx_update, pbkdf2Ctx_updates
     , pbkdf2Ctx_finalize
     , Pbkdf2Gen()
     , pbkdf2Gen_iterate
     , pbkdf2Gen_finalize
     )
     where

import           Data.ByteString(ByteString)
import qualified Data.ByteString.Short as SB
import           Data.Function((&))
import           Data.Word
import           Crypto.HashString ( HashString )
import qualified Crypto.HashString as HS
import           Crypto.Sha256
import           Crypto.Sha256.Hmac
import           Crypto.Sha256.Hmac.Subtle
import           Crypto.Sha256.Pbkdf2.Subtle
import qualified Network.ByteOrder as NB

takeHS :: Int -> [ HashString ] -> [ HashString ]
takeHS = go
  where
    len = SB.length . HS.toShort
    go _ [] = []
    go n (b:bs)
      | n <= 0 = []
      | len b < n = b : go (n - len b) bs
      | otherwise = [HS.fromShort (SB.take n (HS.toShort b))]

-- TODO: write pbkdf2 and pbkdf2_index functions in a point-free style

pbkdf2
  :: HmacKey -- ^ nominally the "password"
  -> ByteString -- ^ nominally the "salt"
  -> Word64 -- ^ number of rounds
  -> Int -- ^ desired length of output
  -> HashString
pbkdf2 password0 salt rounds len = out
  where
     password = hmacKey_toHashed password0
     saltCtx =
       pbkdf2Ctx_init password &
       pbkdf2Ctx_feed salt
     gen index =
       pbkdf2Ctx_finalize index saltCtx &
       pbkdf2Gen_iterate ((max rounds 1) - 1) &
       pbkdf2Gen_finalize
     out = mconcat (takeHS len (map gen [1..maxBound]))

pbkdf2_index
  :: HmacKey -- ^ nominally the "password"
  -> ByteString -- ^ nominally the "salt"
  -> Word32 -- ^ the "index", returns the i-th block of output. The first index is 1, thus the result consists of bytes starting at 32*(i-1) and ending before 32*i.  This is appended as 4 more bytes after the salt.
  -> Word64 -- ^ number of rounds
  -> HashString -- ^ 32-byte output"
pbkdf2_index password0 salt index rounds = out
  where
     password = hmacKey_toHashed password0
     saltCtx =
       pbkdf2Ctx_init password &
       pbkdf2Ctx_feed salt
     out =
       pbkdf2Ctx_finalize index saltCtx &
       pbkdf2Gen_iterate ((max rounds 1) - 1) &
       pbkdf2Gen_finalize

pbkdf2Ctx_init :: HmacKeyHashed -> Pbkdf2Ctx
pbkdf2Ctx_init password = Pbkdf2Ctx
    { pbkdf2Ctx_password = password
    , pbkdf2Ctx_ipadCtx = hmacKeyHashed_ipadCtx password
    }

-- | Append some bytes to the end of the salt. Flipped version of 'pbkdf2Ctx_feed'.

pbkdf2Ctx_update :: Pbkdf2Ctx -> ByteString -> Pbkdf2Ctx
pbkdf2Ctx_update ctx bs = ctx { pbkdf2Ctx_ipadCtx = sha256_update (pbkdf2Ctx_ipadCtx ctx) bs }

-- | Append zero or more bytestrings to the end of the salt. Flipped version of 'pbkdf2Ctx_feeds'

pbkdf2Ctx_updates :: Foldable f => Pbkdf2Ctx -> f ByteString -> Pbkdf2Ctx
pbkdf2Ctx_updates ctx bs = ctx { pbkdf2Ctx_ipadCtx = sha256_updates (pbkdf2Ctx_ipadCtx ctx) bs }

-- | Append some bytes to the end of the salt. Flipped version of 'pbkdf2Ctx_update'.

pbkdf2Ctx_feed :: ByteString -> Pbkdf2Ctx -> Pbkdf2Ctx
pbkdf2Ctx_feed = flip pbkdf2Ctx_update

-- | Append zero or more bytestrings to the end of the salt. Flipped version of 'pbkdf2Ctx_updates'.

pbkdf2Ctx_feeds :: Foldable f => f ByteString -> Pbkdf2Ctx ->  Pbkdf2Ctx
pbkdf2Ctx_feeds = flip pbkdf2Ctx_updates

-- | Append the index to the end of the salt, and then initialize a 'Pbkdf2Gen' with
--   one round applied.

pbkdf2Ctx_finalize :: Word32 -> Pbkdf2Ctx -> Pbkdf2Gen
pbkdf2Ctx_finalize index ctx = Pbkdf2Gen
  { pbkdf2Gen_password = password
  , pbkdf2Gen_finalize = state
  , pbkdf2Gen_state = state
  }
  where
    password = pbkdf2Ctx_password ctx
    ipad = pbkdf2Ctx_ipadCtx ctx &
           sha256_finalizeBytes_toByteString (NB.bytestring32 index)
    state = hmacKeyHashed_opadCtx password &
            sha256_finalizeBytes ipad

-- | Apply zero or more rounds to a pbkdf2 computation.

pbkdf2Gen_iterate :: Word64 -> Pbkdf2Gen -> Pbkdf2Gen
pbkdf2Gen_iterate n0 ctx = go n0 xorSum0 state0
  where
    password = pbkdf2Gen_password ctx
    xorSum0 = pbkdf2Gen_finalize ctx
    state0 = pbkdf2Gen_state ctx
    go n xorSum state
      | n <= 0 =
        Pbkdf2Gen
          { pbkdf2Gen_password = password
          , pbkdf2Gen_finalize = xorSum
          , pbkdf2Gen_state = state
          }
      | otherwise =
        let !state' = hmacKeyHashed_run password &
                      hmacCtx_finalizeBytes (HS.toByteString state)
            !xorSum' = HS.xorLeft state' xorSum
         in go (n-1) xorSum' state'
