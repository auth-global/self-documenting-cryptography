{-# LANGUAGE LambdaCase #-}
{- |

"Internal" data structures representing precomputed HMAC keys and partial HMAC
contexts, supporting incremental computation and backtracking.

-}

module Crypto.PHKDF.HMAC.Subtle
  ( HmacKeyPlain
  , HmacKey(..)
  , hmacKey_ipad
  , hmacKey_ipadCtx
  , hmacKey_opad
  , hmacKey_opadCtx
  , hmacKey_toHashed
  , HmacKeyHashed(..)
  , hmacKeyHashed_ipadCtx
  , hmacKeyHashed_opadCtx
  , HmacKeyPrefixed(..)
  , HmacCtx(..)
  , HmacKeyPadding(..)
  , hmacKeyPadding_unsafeFromCtx
  , hmacKeyPadding_runWith
  ) where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL

import           Data.ByteString.Builder (byteString, shortByteString)
import qualified Data.ByteString.Builder as BB
import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as SB
import           Data.ByteString.Builder.Extra (word64Host)

import           Data.Word(Word64)

import qualified Crypto.Hash.SHA256 as SHA256

type HmacKeyPlain = ByteString

data HmacKey
   = HmacKeyInput  {-# UNPACK #-} !HmacKeyPlain HmacKeyHashed
   | HmacKeyOutput {-# UNPACK #-} !HmacKeyHashed

instance Eq HmacKey where
  (HmacKeyInput a _) == (HmacKeyInput b _)  =  a == b
  a == b  =  hmacKey_toHashed a == hmacKey_toHashed b

hmacKey_ipad :: HmacKey -> HmacKeyPadding
hmacKey_ipad = hmacKeyHashed_ipad . hmacKey_toHashed

hmacKey_ipadCtx :: HmacKey -> SHA256.Ctx
hmacKey_ipadCtx = hmacKeyPadding_runWith 1 . hmacKey_ipad

hmacKey_opad :: HmacKey -> HmacKeyPadding
hmacKey_opad = hmacKeyHashed_opad . hmacKey_toHashed

hmacKey_opadCtx :: HmacKey -> SHA256.Ctx
hmacKey_opadCtx = hmacKeyPadding_runWith 1 . hmacKey_opad

hmacKey_toHashed  :: HmacKey -> HmacKeyHashed
hmacKey_toHashed = \case
  HmacKeyInput _ x -> x
  HmacKeyOutput x -> x

-- | Fixed-size context representing the state of a partial HMAC computation
--   with a complete HMAC key and a partial message parameter.

data HmacCtx = HmacCtx
  { hmacCtx_ipadCtx :: {-# UNPACK #-} !SHA256.Ctx
  , hmacCtx_opad    :: {-# UNPACK #-} !HmacKeyPadding
  } deriving (Eq)

nullBuffer :: ByteString
nullBuffer = BS.replicate 64 0


{--
data Cached a b
  = CachedInput !a b
  | CachedOutput !b
    deriving (Eq, Ord, Show)

cached_initWith :: (a -> b) -> a -> Cached a b
cached_initWith f a = CachedInput a (f a)

cached_readOutput :: Cached a b -> b
cached_readOutput = \case
  CachedInput _ b -> b
  CachedOutput b -> b

cached_peekInput :: Cached a b -> Maybe a
cached_peekInput = \case
  CachedInput a _ -> Just a
  CachedOutput _  -> Nothing

cached_forgetInput :: Cached a b -> Cached c b
cached_forgetInput = \case
  CachedInput _ b -> CachedOutput b
  CachedOutput b -> CachedOutput b
--}

-- | A precomputed HMAC key. This structure must always be exactly
--   64 bytes long, and consists of two SHA256 hashes.
--
--   Computing an HMAC key typically costs two SHA256 blocks. No additional
--   blocks are incurred for keys that are 64 bytes or less in
--   length.  Keys that are longer than 64 bytes long must be first hashed
--   with SHA256 before the key can be derived, incurring extra block
--   comptuations.
--
--   It is not uncommon that implementations of PBKDF2, HKDF, etc unnecessarily
--   redo this computation even though a single HMAC key is used repeatedly.
--
--   Technically these "hashes" are unfinished SHA-256 states,
--   as the standard end-of-message padding has yet to be applied.
--   Thus you can't compute these hashes using the most common
--   command-line tools like sha256sum
--
--   The first 32 bytes represents the SHA-256 state of the inner padding.
--   This is followed by the 32 byte state of the outer padding.  No
--   counter or buffer for leftover bytes are needed, because the
--   counter is known and there are never any leftover bytes.
data HmacKeyHashed = HmacKeyHashed
  { hmacKeyHashed_ipad :: {-# UNPACK #-} !HmacKeyPadding
  , hmacKeyHashed_opad :: {-# UNPACK #-} !HmacKeyPadding
  } deriving (Eq, Ord, Show)

hmacKeyHashed_ipadCtx :: HmacKeyHashed -> SHA256.Ctx
hmacKeyHashed_ipadCtx = hmacKeyPadding_runWith 1 . hmacKeyHashed_ipad

hmacKeyHashed_opadCtx :: HmacKeyHashed -> SHA256.Ctx
hmacKeyHashed_opadCtx = hmacKeyPadding_runWith 1 . hmacKeyHashed_opad

newtype HmacKeyPadding = HmacKeyPadding ShortByteString deriving (Eq, Ord, Show)

hmacKeyPadding_runWith :: Word64 -> HmacKeyPadding -> SHA256.Ctx
hmacKeyPadding_runWith blockCount (HmacKeyPadding pad) = SHA256.Ctx (run out)
  where
    run = BL.toStrict . BB.toLazyByteString
    out = word64Host (64 * blockCount)
       <> byteString nullBuffer
       <> shortByteString pad

hmacKeyPadding_unsafeFromCtx :: SHA256.Ctx -> HmacKeyPadding
hmacKeyPadding_unsafeFromCtx (SHA256.Ctx bs) = HmacKeyPadding out
  where out = SB.toShort (BS.drop 72 bs)

-- | Halfway between an HmacKeyHashed and an HmacCtx.
--   It's both an HmacKeyHashed that's gained a counter,
--   and a HmacCtx that's guaranteed to contain no unprocessed
--   input data.

data HmacKeyPrefixed = HmacKeyPrefixed
  { hmacKeyPrefixed_blockCount :: {-# UNPACK #-} !Word64
  , hmacKeyPrefixed_ipad :: {-# UNPACK #-} !HmacKeyPadding
  , hmacKeyPrefixed_opad :: {-# UNPACK #-} !HmacKeyPadding
  }
