{-# LANGUAGE ViewPatterns, LambdaCase #-}

module Crypto.Sha256.Hmac.Implementation where

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

import           Crypto.Sha256 as Sha256
import           Crypto.Sha256.Subtle

type HmacKeyPlain = ByteString

nullBuffer :: ByteString
nullBuffer = BS.replicate 64 0

-- | A cached, precomputed hmac key. It comes in two flavors, one that remembers the
--   plaintext key, and one that doesn't, remembering only the precomputed hmac key.
--
--   Computing an hmac key typically requires two SHA256 blocks, unless the key itself
--   is more than 64 bytes, in which case precomputing the key will require at least
--   four SHA256 blocks.

data HmacKey
   = HmacKey_Plain  {-# UNPACK #-} !HmacKeyPlain HmacKeyHashed
   | HmacKey_Hashed {-# UNPACK #-} !HmacKeyHashed

{--
instance Eq HmacKey where
  (HmacKey_Plain a _) == (HmacKey_Plain b _)  =  hmacKeyPlain_eq a b
  a == b  =  hmacKey_toHashed a == hmacKey_toHashed b

-- | This function can in theory return False, when converting both strings
--   to a 'HmacKeyHashed' first and then comparing returns True. However,
--   probabilistically speaking, the recall of this function is
--   cryptographically close to 1, and significantly faster than a full
--   HMAC key derivation.
--
--   There are three ways that a failure of recall, i.e. a false negative, can
--   happen:
--
--   If one key is 32 bytes or shorter, and the other is longer than 64 bytes,
--   recall failures can happen if the SHA-256 hash of the longer key ends in
--   at least 16 null bytes, corresponding to a partial preimage.
--
--   If both keys are longer than 64 bytes, recall failures can happen when
--   those keys collide SHA-256.
--
--   Alternatively, recall failures can happen when HMAC-SHA256's key schedule
--   collides. This should be considerably more difficult than a regular SHA-256
--   collision, because it involves xor'ing each key with two different pads,
--   and then hashing both. Thus, effectively, this requires two SHA-256
--   collisions of a very specific form.

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
       | otherwise = normalize (Sha256.hash x) == y
--}
hmacKey_ipad :: HmacKey -> Sha256State
hmacKey_ipad = hmacKeyHashed_ipad . hmacKey_toHashed

hmacKey_runIpadCtx :: HmacKey -> ByteString -> Sha256Ctx
hmacKey_runIpadCtx k b = sha256state_runWith 1 b (hmacKey_ipad k)

hmacKey_ipadCtx :: HmacKey -> Sha256Ctx
hmacKey_ipadCtx = flip hmacKey_runIpadCtx BS.empty

hmacKey_opad :: HmacKey -> Sha256State
hmacKey_opad = hmacKeyHashed_opad . hmacKey_toHashed

hmacKey_runOpadCtx :: HmacKey -> ByteString -> Sha256Ctx
hmacKey_runOpadCtx k b = sha256state_runWith 1 b (hmacKey_opad k)

hmacKey_opadCtx :: HmacKey -> Sha256Ctx
hmacKey_opadCtx = flip hmacKey_runOpadCtx BS.empty 

hmacKey_toHashed :: HmacKey -> HmacKeyHashed
hmacKey_toHashed = \case
   HmacKey_Plain _ x -> x
   HmacKey_Hashed  x -> x 

-- | An @HmacKeyLike@ context can either be an 'HmacKey', or a
--   'HmacKeyPrefixed'.

data HmacKeyLike
   = HmacKeyLike_Plain {-# UNPACK #-} !HmacKeyPlain HmacKeyHashed
   | HmacKeyLike_Hashed {-# UNPACK #-} !HmacKeyHashed
   | HmacKeyLike_Prefixed {-# UNPACK #-} !HmacKeyPrefixed

{--
hmacKeyPrefixed_eqHashed :: HmacKeyPrefixed -> HmacKeyHashed -> Bool
hmacKeyPrefixed_eqHashed a
  | hmacKeyPrefixed_blockCount a /= 1 = const False
  | otherwise = \b -> hmacKeyPrefixed_ipad a == hmacKeyHashed_ipad b
                   && hmacKeyPrefixed_opad a == hmacKeyHashed_opad b

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
--}
hmacKeyLike_ipadCtx :: HmacKeyLike -> Sha256Ctx
hmacKeyLike_ipadCtx = \case
  HmacKeyLike_Plain _ x -> hmacKeyHashed_ipadCtx x
  HmacKeyLike_Hashed x -> hmacKeyHashed_ipadCtx x
  HmacKeyLike_Prefixed x -> hmacKeyPrefixed_ipadCtx x

hmacKeyLike_opad :: HmacKeyLike -> Sha256State
hmacKeyLike_opad = \case
  HmacKeyLike_Plain _ x -> hmacKeyHashed_opad x
  HmacKeyLike_Hashed x -> hmacKeyHashed_opad x
  HmacKeyLike_Prefixed x -> hmacKeyPrefixed_opad x

hmacKeyLike_opadCtx :: HmacKeyLike -> Sha256Ctx
hmacKeyLike_opadCtx = \case
  HmacKeyLike_Plain _ x -> hmacKeyHashed_opadCtx x
  HmacKeyLike_Hashed x -> hmacKeyHashed_opadCtx x
  HmacKeyLike_Prefixed x -> hmacKeyPrefixed_opadCtx x

hmacKeyLike_runIpadCtx :: HmacKeyLike -> ByteString -> Sha256Ctx
hmacKeyLike_runIpadCtx = \case
  HmacKeyLike_Plain _ x -> hmacKeyHashed_runIpadCtx x
  HmacKeyLike_Hashed x -> hmacKeyHashed_runIpadCtx x
  HmacKeyLike_Prefixed x -> hmacKeyPrefixed_runIpadCtx x

hmacKeyLike_runOpadCtx :: HmacKeyLike -> ByteString -> Sha256Ctx
hmacKeyLike_runOpadCtx = \case
  HmacKeyLike_Plain _ x -> hmacKeyHashed_runOpadCtx x
  HmacKeyLike_Hashed x -> hmacKeyHashed_runOpadCtx x
  HmacKeyLike_Prefixed x -> hmacKeyPrefixed_runOpadCtx x

-- | Fixed-size context representing the state of a partial HMAC computation
--   with a complete HMAC key and a partial message parameter.  This maintains
--   a buffer of up to 63 unprocessed bytes, so that you may feed it arbitrary
--   bytestring without dealing with buffer boundaries.

data HmacCtx = HmacCtx
  { hmacCtx_ipadCtx :: {-# UNPACK #-} !Sha256Ctx
  , hmacCtx_opad    :: {-# UNPACK #-} !Sha256State
  }

-- | A precomputed HMAC key. This structure is 64 bytes long, and consists of two
--   SHA256 hashes.
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
--   command-line tools like sha256sum.
-- 
--   The lack of end-of-message padding is also why precomputing
--   HMAC keys on keys up to 64 bytes only requires one SHA-256 block
--   computation for each of the two pads, whereas more typically
--   the boundary for extra block computations happens between the 55th
--   and 56th byte due to end-of-message padding.

-- TODO: Might it be a good idea to pack both states into one ByteArray?

data HmacKeyHashed = HmacKeyHashed
  { hmacKeyHashed_ipad :: {-# UNPACK #-} !Sha256State
  , hmacKeyHashed_opad :: {-# UNPACK #-} !Sha256State
  }

hmacKeyHashed_ipadCtx :: HmacKeyHashed -> Sha256Ctx
hmacKeyHashed_ipadCtx = flip hmacKeyHashed_runIpadCtx BS.empty

hmacKeyHashed_runIpadCtx :: HmacKeyHashed -> ByteString -> Sha256Ctx
hmacKeyHashed_runIpadCtx k b = sha256state_runWith 1 b (hmacKeyHashed_ipad k)

hmacKeyHashed_opadCtx :: HmacKeyHashed -> Sha256Ctx
hmacKeyHashed_opadCtx = flip hmacKeyHashed_runOpadCtx BS.empty

hmacKeyHashed_runOpadCtx :: HmacKeyHashed -> ByteString -> Sha256Ctx
hmacKeyHashed_runOpadCtx k b = sha256state_runWith 1 b (hmacKeyHashed_opad k)

-- | Halfway between an HmacKeyHashed and an HmacCtx.
--   It's both an HmacKeyHashed that's gained a counter,
--   and a HmacCtx that's guaranteed to contain no unprocessed
--   input data.

data HmacKeyPrefixed = HmacKeyPrefixed
  { hmacKeyPrefixed_ipadCtx :: {-# UNPACK #-} !Sha256Ctx
  , hmacKeyPrefixed_opad    :: {-# UNPACK #-} !Sha256State
  }

hmacKeyPrefixed_runIpadCtx :: HmacKeyPrefixed -> ByteString -> Sha256Ctx
hmacKeyPrefixed_runIpadCtx k b = sha256_feed b (hmacKeyPrefixed_ipadCtx k)

hmacKeyPrefixed_runOpadCtx :: HmacKeyPrefixed -> ByteString -> Sha256Ctx
hmacKeyPrefixed_runOpadCtx k b = sha256state_runWith 1 b (hmacKeyPrefixed_opad k)

hmacKeyPrefixed_opadCtx :: HmacKeyPrefixed -> Sha256Ctx
hmacKeyPrefixed_opadCtx = flip hmacKeyPrefixed_runOpadCtx BS.empty