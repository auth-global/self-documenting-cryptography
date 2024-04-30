{-# LANGUAGE ViewPatterns, LambdaCase #-}
{- |

"Internal" data structures representing precomputed HMAC keys and partial HMAC
contexts, supporting incremental computation and backtracking.

-}

module Crypto.PHKDF.HMAC.Subtle
  ( HmacKeyPlain
  , hmacKeyPlain_eq
  , HmacKey(..)
  , hmacKey_ipad
  , hmacKey_ipadCtx
  , hmacKey_opad
  , hmacKey_opadCtx
  , hmacKey_toHashed
  , HmacKeyLike(..)
  , hmacKeyLike_ipadCtx
  , hmacKeyLike_opad
  , hmacKeyLike_opadCtx
  , HmacKeyHashed(..)
  , hmacKeyHashed_ipadCtx
  , hmacKeyHashed_opadCtx
  , HmacKeyPrefixed(..)
  , hmacKeyPrefixed_ipadCtx
  , hmacKeyPrefixed_opadCtx
  , hmacKeyPrefixed_eqHashed
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

import           Data.Function(on)
import           Data.Word(Word64)

import           Crypto.Encoding.PHKDF(nullBuffer)
import qualified Crypto.Hash.SHA256 as SHA256

type HmacKeyPlain = ByteString

data HmacKey
   = HmacKey_Plain  {-# UNPACK #-} !HmacKeyPlain HmacKeyHashed
   | HmacKey_Hashed {-# UNPACK #-} !HmacKeyHashed

instance Eq HmacKey where
  (HmacKey_Plain a _) == (HmacKey_Plain b _)  =  hmacKeyPlain_eq a b
  a == b  =  hmacKey_toHashed a == hmacKey_toHashed b

-- | This function can in theory return False, when converting both strings
--   to a 'HmacKeyHashed' first and then comparing returns True. However,
--   probabilistically speaking, the recall of this function is
--   cryptographically close to 1, and a lot faster.

hmacKeyPlain_eq :: HmacKeyPlain -> HmacKeyPlain -> Bool
hmacKeyPlain_eq a b =
  case (BS.length a > 64, BS.length b > 64) of
    (False, False) -> ((==) `on` normalize) a b
    (True, False) -> checkEq a b
    (False, True) -> checkEq b a
    (True, True) -> a == b
  where
    normalize = BS.dropWhileEnd (==0)
    checkEq x (normalize -> y)
       | BS.length y > 32 || BS.length y <= 16 = False
       | otherwise = normalize (SHA256.hash x) == y

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
  HmacKey_Plain _ x -> x
  HmacKey_Hashed x -> x

data HmacKeyLike
   = HmacKeyLike_Plain {-# UNPACK #-} !HmacKeyPlain HmacKeyHashed
   | HmacKeyLike_Hashed {-# UNPACK #-} !HmacKeyHashed
   | HmacKeyLike_Prefixed {-# UNPACK #-} !HmacKeyPrefixed

hmacKeyPrefixed_eqHashed :: HmacKeyPrefixed -> HmacKeyHashed -> Bool
hmacKeyPrefixed_eqHashed a
  | hmacKeyPrefixed_blockCount a /= 1 = const False
  | otherwise = \b -> hmacKeyPrefixed_ipad a == hmacKeyHashed_ipad b
                   && hmacKeyPrefixed_opad a == hmacKeyHashed_opad b

hmacKeyPrefixed_ipadCtx :: HmacKeyPrefixed -> SHA256.Ctx
hmacKeyPrefixed_ipadCtx x =
  hmacKeyPadding_runWith (hmacKeyPrefixed_blockCount x) (hmacKeyPrefixed_ipad x)

hmacKeyPrefixed_opadCtx :: HmacKeyPrefixed -> SHA256.Ctx
hmacKeyPrefixed_opadCtx x =
  hmacKeyPadding_runWith 1 (hmacKeyPrefixed_opad x)

instance Eq HmacKeyLike where
  (HmacKeyLike_Plain a _) == (HmacKeyLike_Plain b _) = hmacKeyPlain_eq a b
  (HmacKeyLike_Plain _ a) == (HmacKeyLike_Hashed b) = a == b
  (HmacKeyLike_Plain _ a) == (HmacKeyLike_Prefixed b) = hmacKeyPrefixed_eqHashed b a
  (HmacKeyLike_Hashed a) == (HmacKeyLike_Plain _ b) = a == b
  (HmacKeyLike_Hashed a) == (HmacKeyLike_Hashed b) = a == b
  (HmacKeyLike_Hashed a) == (HmacKeyLike_Prefixed b) = hmacKeyPrefixed_eqHashed b a
  (HmacKeyLike_Prefixed a) == (HmacKeyLike_Plain _ b) = hmacKeyPrefixed_eqHashed a b
  (HmacKeyLike_Prefixed a) == (HmacKeyLike_Hashed b) = hmacKeyPrefixed_eqHashed a b
  (HmacKeyLike_Prefixed a) == (HmacKeyLike_Prefixed b) = a == b

hmacKeyLike_ipadCtx :: HmacKeyLike -> SHA256.Ctx
hmacKeyLike_ipadCtx = \case
  HmacKeyLike_Plain _ x -> hmacKeyHashed_ipadCtx x
  HmacKeyLike_Hashed x -> hmacKeyHashed_ipadCtx x
  HmacKeyLike_Prefixed x -> hmacKeyPadding_runWith (hmacKeyPrefixed_blockCount x) (hmacKeyPrefixed_ipad x)

hmacKeyLike_opad :: HmacKeyLike -> HmacKeyPadding
hmacKeyLike_opad = \case
  HmacKeyLike_Plain _ x -> hmacKeyHashed_opad x
  HmacKeyLike_Hashed x -> hmacKeyHashed_opad x
  HmacKeyLike_Prefixed x -> hmacKeyPrefixed_opad x

hmacKeyLike_opadCtx :: HmacKeyLike -> SHA256.Ctx
hmacKeyLike_opadCtx = hmacKeyPadding_runWith 1 . hmacKeyLike_opad

-- | Fixed-size context representing the state of a partial HMAC computation
--   with a complete HMAC key and a partial message parameter.

data HmacCtx = HmacCtx
  { hmacCtx_ipadCtx :: {-# UNPACK #-} !SHA256.Ctx
  , hmacCtx_opad    :: {-# UNPACK #-} !HmacKeyPadding
  } deriving (Eq)

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
  } deriving (Eq)
