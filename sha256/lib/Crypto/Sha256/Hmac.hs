{-# LANGUAGE ViewPatterns, LambdaCase, BangPatterns #-}

{- |

An implementation of HMAC-SHA256 that supports precomputed keys, streaming,
backtracking, and bitstring inputs.

-}

module Crypto.Sha256.Hmac
  ( hmac
  , HmacKeyPlain
  -- , hmacKeyPlain_eq
  , HmacKey()
  , hmacKey
  , hmacKey_hashed
  , hmacKey_toPlain
  , hmacKey_toHashed
  , hmacKey_forgetPlain
  , hmacKey_run
  , HmacKeyLike()
  , hmacKeyLike
  , hmacKeyLike_init
  , hmacKeyLike_initHashed
  , hmacKeyLike_initPrefixed
  , hmacKeyLike_toKey
  , hmacKeyLike_toPlain
  , hmacKeyLike_toHashed
  , hmacKeyLike_toPrefixed
  , hmacKeyLike_run
  , hmacKeyLike_byteCount
  , hmacKeyLike_blockCount
  , hmacKeyLike_bufferLength
  -- , hmacKeyLike_feeds
  -- , hmacKeyLike_feedsWith
  , HmacKeyHashed()
  , hmacKeyHashed
  , hmacKeyHashed_toKey
  , HmacKeyPrefixed()
  , hmacKeyPrefixed
  , hmacKeyPrefixed_init
  , hmacKeyPrefixed_initHashed
  , hmacKeyPrefixed_initLike
  , hmacKeyPrefixed_toHashed
  -- , hmacKeyPrefixed_eqHashed
  , hmacKeyPrefixed_feed
  , hmacKeyPrefixed_feeds
  , hmacKeyPrefixed_feedsWith
  , hmacKeyPrefixed_run
  , hmacKeyPrefixed_byteCount
  , hmacKeyPrefixed_blockCount
  , hmacKeyPrefixed_bufferLength
  , HmacCtx()
  , hmacCtx
  , hmacCtx_init
  , hmacCtx_initWith
  , hmacCtx_update,  hmacCtx_feed
  , hmacCtx_updates, hmacCtx_feeds
  , hmacCtx_finalize
  , hmacCtx_finalizeBits
  , hmacCtx_byteCount
  , hmacCtx_blockCount
  , hmacCtx_bufferLength
--  , hmacCtx_toHmacKeyPrefixed
  ) where

import           Data.Bits(xor)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.List(scanl')
import           Data.Function((&))
import           Data.Foldable(Foldable, toList)
import           Data.Int
import           Data.Word

import           Crypto.Sha256 as Sha256
import           Crypto.Sha256.Subtle
import           Crypto.Sha256.Hmac.Implementation

-- Should these be made publicly available?  Are these available anywhere else?
dropBs :: Int64 -> [ ByteString ] -> [ ByteString ]
dropBs = go
  where
    len = fromIntegral . B.length
    go _ [] = []
    go 0 bs = bs
    go n (b:bs)
      | n >= len b = go (n - len b) bs
      | otherwise = B.drop (fromIntegral n) b : bs

takeBs :: Int64 -> [ ByteString ] -> [ ByteString ]
takeBs = go
  where
    len = fromIntegral . B.length
    go _ [] = []
    go n (b:bs)
      | n <= 0 = []
      | len b < n = b : go (n - len b) bs
      | otherwise = [B.take (fromIntegral n) b]

takeBs' :: Int64 -> [ ByteString ] -> [ ByteString ]
takeBs' n bs = if haveEnough then takeBs n bs else []
  where
    len = fromIntegral . B.length
    haveEnough = any (>= n) (scanl' (+) 0 (map len bs))


-- Initialize a precomputed hmac key from a plaintext bytestring, which
-- can then be turned into an hmac context using 'hmacKey_run'
--
-- Note this structure retains the plaintext key, which isn't strictly necessary
-- for actually computing the resulting hmac function.  The plaintext key can
-- be forgotten using '
hmacKey :: HmacKeyPlain -> HmacKey
hmacKey key = HmacKey_Plain key (hmacKeyHashed key)

-- | If the plaintext hmac key has been remembered by the precomputed key, return it.
--   Otherwise return 'Nothing'.  Keys precomputed by 'hmacKey' retain the plaintext,
--   which can subsequently be forgotten by 'hmacKey_forgetPlain'.  Alternatively,
--   keys precomputed by 'hmacKey_hashed' never retains the plaintext key in the
--   first place.
hmacKey_toPlain :: HmacKey -> Maybe HmacKeyPlain
hmacKey_toPlain = \case
  HmacKey_Plain a _ -> Just a
  HmacKey_Hashed _  -> Nothing

-- | Forget any plaintext hmac keys being retained by a given precomputed key, meaning
--   that for all x, @hmacKey_toPlain (hmacKey_forgetPlain x) == Nothing@.
--
--   This is potentially useful when implementing PBKDF2, as the plaintext password can
--   immediately be replaced with a precomputed hmac key, even before key-stretching
--   is complete. Note that the precomputed hmac key does provide a fast brute-force
--   attack on the plaintext key, typically as little as 1 SHA256 block, so this cannot be
--   relied upon for secrecy if the hmac key is potentially guessable, such as a weak
--   password or a non-secret salt.

hmacKey_forgetPlain :: HmacKey -> HmacKey
hmacKey_forgetPlain = \case
  HmacKey_Plain _ b -> HmacKey_Hashed b
  x@(HmacKey_Hashed _) -> x

hmacKeyLike :: HmacKeyPlain -> HmacKeyLike
hmacKeyLike key = HmacKeyLike_Plain key (hmacKeyHashed key)

hmacKeyLike_init :: HmacKey -> HmacKeyLike
hmacKeyLike_init = \case
  HmacKey_Plain a b -> HmacKeyLike_Plain a b
  HmacKey_Hashed b -> HmacKeyLike_Hashed b

hmacKeyLike_initHashed :: HmacKeyHashed -> HmacKeyLike
hmacKeyLike_initHashed = HmacKeyLike_Hashed

hmacKeyLike_initPrefixed :: HmacKeyPrefixed -> HmacKeyLike
hmacKeyLike_initPrefixed = HmacKeyLike_Prefixed

hmacKeyLike_toPlain :: HmacKeyLike -> Maybe HmacKeyPlain
hmacKeyLike_toPlain = \case
  HmacKeyLike_Plain a _ -> Just a
  HmacKeyLike_Hashed _ -> Nothing
  HmacKeyLike_Prefixed _ -> Nothing

hmacKeyLike_toHashed :: HmacKeyLike -> Maybe HmacKeyHashed
hmacKeyLike_toHashed = \case
  HmacKeyLike_Plain _ a -> Just a
  HmacKeyLike_Hashed a -> Just a
  HmacKeyLike_Prefixed a -> hmacKeyPrefixed_toHashed a

hmacKeyLike_toKey :: HmacKeyLike -> Maybe HmacKey
hmacKeyLike_toKey = \case
  HmacKeyLike_Plain a b -> Just $ HmacKey_Plain a b
  HmacKeyLike_Hashed b -> Just $ HmacKey_Hashed b
  HmacKeyLike_Prefixed c -> HmacKey_Hashed <$> hmacKeyPrefixed_toHashed c

hmacKeyLike_toPrefixed :: HmacKeyLike -> HmacKeyPrefixed
hmacKeyLike_toPrefixed = \case
  HmacKeyLike_Plain _ b -> hmacKeyPrefixed_initHashed b
  HmacKeyLike_Hashed b -> hmacKeyPrefixed_initHashed b
  HmacKeyLike_Prefixed b -> b

hmacKeyLike_run :: HmacKeyLike -> HmacCtx
hmacKeyLike_run = \case
  HmacKeyLike_Plain _ a -> hmacKeyHashed_run a
  HmacKeyLike_Hashed a -> hmacKeyHashed_run a
  HmacKeyLike_Prefixed a -> hmacKeyPrefixed_run a

-- | how many bytes have been fed into the SHA256 state machine?  This is always 64
--   more bytes than hmac's "message" input.
--   If @hmacKeyLike_toKey x == Just ...@, then @hmacKeyLike_byteCount x == 64@.
--   If @hmacKeyLike_toKey x == Nothing@, then this returns a multiple of 64 that is
--   greater or equal to 128.
--   

hmacKeyLike_byteCount :: HmacKeyLike -> Word64
hmacKeyLike_byteCount = \case
  HmacKeyLike_Plain _ _ -> 64
  HmacKeyLike_Hashed _ -> 64
  HmacKeyLike_Prefixed b -> hmacKeyPrefixed_byteCount b

hmacKeyLike_blockCount :: HmacKeyLike -> Word64
hmacKeyLike_blockCount = \case
  HmacKeyLike_Plain _ _ -> 1
  HmacKeyLike_Hashed _ -> 1
  HmacKeyLike_Prefixed b -> hmacKeyPrefixed_blockCount b

hmacKeyLike_bufferLength :: HmacKeyLike -> Word8
hmacKeyLike_bufferLength = const 0

-- | Precompute an HmacKey without retaining the plaintext input, equivalent to
--   'hmacKey_forgetInput . hmacKey'
hmacKey_hashed :: HmacKeyPlain -> HmacKey
hmacKey_hashed = HmacKey_Hashed . hmacKeyHashed

hmacKey_run :: HmacKey -> HmacCtx
hmacKey_run = hmacCtx_init

hmacKeyHashed :: HmacKeyPlain -> HmacKeyHashed
hmacKeyHashed key = HmacKeyHashed ipad opad
  where
    ipad = tweak 0x36
    opad = tweak 0x5c
    k1 = if B.length key > 64 then Sha256.hash key else key
    k2 = B.append k1 (B.replicate (64 - B.length k1) 0)
    tweak c = sha256state_init & sha256state_feed (B.map (xor c) k2)

hmacKeyHashed_toKey :: HmacKeyHashed -> HmacKey
hmacKeyHashed_toKey = HmacKey_Hashed

hmacKeyHashed_run :: HmacKeyHashed -> HmacCtx
hmacKeyHashed_run key = HmacCtx
    { hmacCtx_ipadCtx = hmacKeyHashed_ipadCtx key
    , hmacCtx_opad = hmacKeyHashed_opad key
    }

hmacKeyHashed_runWith :: HmacKeyHashed -> ByteString -> HmacCtx
hmacKeyHashed_runWith key str = HmacCtx
    { hmacCtx_ipadCtx = hmacKeyHashed_runIpadCtx key str
    , hmacCtx_opad = hmacKeyHashed_opad key
    }

hmacKeyPrefixed :: HmacKeyPlain -> HmacKeyPrefixed
hmacKeyPrefixed = hmacKeyPrefixed_initHashed . hmacKeyHashed

hmacKeyPrefixed_init :: HmacKey -> HmacKeyPrefixed
hmacKeyPrefixed_init = hmacKeyPrefixed_initHashed . hmacKey_toHashed

hmacKeyPrefixed_initHashed :: HmacKeyHashed -> HmacKeyPrefixed
hmacKeyPrefixed_initHashed k = HmacKeyPrefixed (hmacKeyHashed_ipadCtx k) (hmacKeyHashed_opad k)
hmacKeyPrefixed_initLike :: HmacKeyLike -> HmacKeyPrefixed
hmacKeyPrefixed_initLike = hmacKeyLike_toPrefixed

hmacKeyPrefixed_toHashed :: HmacKeyPrefixed -> Maybe HmacKeyHashed
hmacKeyPrefixed_toHashed x =
  if hmacKeyPrefixed_blockCount x == 1
  then Just $ HmacKeyHashed
    { hmacKeyHashed_ipad = sha256state_fromCtxInplace (hmacKeyPrefixed_ipadCtx x)
    , hmacKeyHashed_opad = hmacKeyPrefixed_opad x
    }
  else Nothing

hmacKeyPrefixed_feed :: ByteString -> HmacKeyPrefixed -> (ByteString, HmacKeyPrefixed)
hmacKeyPrefixed_feed x = hmacKeyPrefixed_feeds [x]

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
                    { hmacKeyPrefixed_ipadCtx = sha256_updates (hmacKeyPrefixed_ipadCtx st) x
                    , hmacKeyPrefixed_opad = hmacKeyPrefixed_opad st
                    }

hmacKeyPrefixed_run :: HmacKeyPrefixed -> HmacCtx
hmacKeyPrefixed_run key = HmacCtx
    { hmacCtx_ipadCtx = hmacKeyPrefixed_ipadCtx key
    , hmacCtx_opad    = hmacKeyPrefixed_opad key
    }

hmacKeyPrefixed_byteCount :: HmacKeyPrefixed -> Word64
hmacKeyPrefixed_byteCount = sha256_byteCount . hmacKeyPrefixed_ipadCtx

hmacKeyPrefixed_blockCount :: HmacKeyPrefixed -> Word64
hmacKeyPrefixed_blockCount = sha256_blockCount . hmacKeyPrefixed_ipadCtx

hmacKeyPrefixed_bufferLength :: HmacKeyPrefixed -> Word8
hmacKeyPrefixed_bufferLength = const 0

-- | A simple interface to HMAC-SHA256. Note that this function was written
--   to make partial application an efficient way to compute the hmac of
--   multiple messages with exactly the same key:
--
--   @
--     let myHash = hmac "my-key"
--      in (myHash "message 1", myHash "message 2", myHash "message 3")
--   @
--
--   This typically saves two SHA-256 blocks per reused function application.
--   Thus this example saves four block computations from the two reused
--   calls to @myHash@ in this example.
--
--   Initializing the @myHash@ closure requires computing two SHA-256 blocks.
--   Applying the closure requires two further SHA-256 blocks per message,
--   as every message is less than 56 bytes long. Thus the total computation
--   requires 8 SHA-256 blocks with reuse, or 12 SHA-256 blocks without reuse.
--
--   Key reuse can save four or more block computations per application if
--   the reused key is longer than 64 bytes. I don't recommend using HMAC
--   keys that are longer than 64 bytes, as all such keys can be trivially
--   replaced with the SHA256 hash of the key, which is only 32 bytes long.
--
--   This high-level interface is implemented using 'hmacCtx_finalize',
--   'hmacKeyHashed_run', and 'hmacKeyHashed' composed in a point-free style
--   in order to help ensure key reuse works as expected.

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
hmacCtx_feed b (HmacCtx ic oc) = HmacCtx (sha256_update ic b) oc

-- | Append zero or more bytestrings onto the end of the message argument to
--   HMAC.

hmacCtx_updates :: Foldable f => HmacCtx -> f ByteString -> HmacCtx
hmacCtx_updates = flip hmacCtx_feeds

hmacCtx_feeds :: Foldable f => f ByteString -> HmacCtx -> HmacCtx
hmacCtx_feeds bs (HmacCtx ic oc) = HmacCtx (sha256_updates ic (toList bs)) oc

-- | Finish computing the final 32-byte hash for an HMAC context.

hmacCtx_finalize :: HmacCtx -> ByteString
hmacCtx_finalize (HmacCtx ic oc) = outer
  where
    inner = sha256_finalize ic
    outer = sha256_finalize (sha256state_runWith 1 inner oc)

-- | Append any arbitrary bitstring onto the end of an HMAC context, and
--   finish computing the final 32-byte hash.

hmacCtx_finalizeBits :: ByteString -> Word64 -> HmacCtx -> ByteString
hmacCtx_finalizeBits bits bitlen (HmacCtx ic oc) = outer
  where
    inner = sha256_finalizeBits bits bitlen ic
    outer = sha256_finalize (sha256state_runWith 1 inner oc)

hmacCtx_byteCount :: HmacCtx -> Word64
hmacCtx_byteCount = sha256_byteCount . hmacCtx_ipadCtx

hmacCtx_blockCount :: HmacCtx -> Word64
hmacCtx_blockCount = sha256_blockCount . hmacCtx_ipadCtx

hmacCtx_bufferLength :: HmacCtx -> Word8
hmacCtx_bufferLength = sha256_bufferLength . hmacCtx_ipadCtx

-- Ugh, I don't have convenient access to cryptohash's internal counter. I
-- should fix that. I also need to fix the fact that cryptohash-sha256 exposes
-- endianess issues in a publicly-facing bytestrings, thus potentially creating
-- less-than-immediately-obvious problems when serializing/deserializing SHA256
-- states. Thus part of the reason why I started on newer SHA256 bindings for
-- GHC 9.4.

-- hmacCtx_toHmacKeyPrefixed :: HmacCtx -> (ByteString, HmacKeyPrefixed)
