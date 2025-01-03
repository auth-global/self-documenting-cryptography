{-# LANGUAGE CApiFFI, OverloadedStrings, ViewPatterns #-}

{- |

Bcrypt with an excessive amount of freedom and salt, appropriate for
our excessively salty era. This module exports bindings that are
potentially cryptographically unsafe to lower-level functions written in C.

Bcrypt's state machine exhibits a beautiful grouplike structure known as a
/quasigroup/, see [wikipedia](https://en.wikipedia.org/wiki/Quasigroup) or the
[ncat wiki](https://ncatlab.org/nlab/show/quasigroup). Blowfish's state machine
is exactly 4168 bytes, and bcrypt's modification to blowfish's key expansion
represents a /transition code/ that is also exactly 4168 bytes long.

Basically, each call to /Blowfish_expandstate/ encrypts the transition code
with the Blowfish block cipher in Cipher Block Chaining (CBC) mode of operation.
Well, not quite, as this key setup process actually uses each output block
to overwrite part of the key, so it's more like CBC with key feedback.

/Blowfish_expandstate/ is part of a relation between input states, transition
codes, and output states. Given any two components of any one of these
3-tuples, one can efficiently compute the third component.

/Blowfish_expandstate/ is what computes output states from input states
and transition codes.  One can also implement /Blowfish_reverseExpandstate/
that computes input states from output states and transition codes, and
/Blowfish_transitionCode/ that computes transition codes from input states
and output states. Together they form the triple of functions needed to satisfy
the universal-algebra-flavored definition of a quasigroup.

This quasigroup implies that no state or transition code is particularly
special, and that choosing a different transition code does not change the
dynamical properties of the blowfish state machine /on average/.

Of course, the molecules in a cup full of room-temperature water /on average/
are moving much too slowly to ever become a gas, yet a cup full of water that
is exposed to the open air will reliably evaporate over time. Similarly,
this quasigroup structure also implies that allowing unrestricted use of
transition codes, as the 'bcryptXs' binding allows you to do, is horribly
broken from a security perspective.

Yet this also implies that choosing transition codes in an open and honest
way is a perfectly safe modification to the bcrypt algorithm. Thus the goal
of bcrypt-xs-ctr is to add enough restrictions to how these transition codes
are chosen and used to tame excessively long tags and keep everything secure.

The first and safest recommendation is to include the excess salt in the
derivation of other inputs to bcrypt, thus enforcing the requirement
that the tags be chosen before the inputs are examined.

As a fallback, the bcryptXsCtrSuperRound has a couple of design features that
somewhat naively attempt to address this issue:

1.  The initial call to @expand@ is designed to rapidly and completely
    encode both @key0@ and @key1@ into the bcrypt state, relative to
    the starting round state. This ensures a complete transfer of entropy
    after a small number of Blowfish block encryptions.

    (This argument assumes @length key0 + length key1 <= 72@ bytes long)

2.  The first N bytes of the p-box are protected by the function name, which
    exists primarily to prohibit nearly all possible transition codes, to
    ensure the firt N bytes of the transition code aren't under any possible
    control of external input.

    (This argument assumes @length name == N@)

3.  Every bcrypt round (a miniround within the superround) repeats the same
    4168 - N external bytes in four different places, each in the same relative
    position with respect to a 4168-byte state or transition code.

    Two of these repetitions occur by xor-ing the external bytes with the
    last bytes of the state vector. The first N bytes of the state-xor are
    reserved, once for key0 and once for key1.

    Two of these repeititons occur as the last bytes of the transition code.
    The first 4 bytes of the transition code is reserved for a counter, which
    is complemented between repetitions for a guaranteed non-linear effect.
    The remaining (N - 4) bytes are taken up by the function name.

    This breaks all the obvious attacks, and may well break many or all of
    the less obvious attacks too. I wouldn't want to rely too much on this
    particular combinatorial block design structure without further study,
    which is likely to suggest further design improvements.

    However, this was a no-risk move that didn't cost the intended use cases
    anything, but looked plausibly strong against issues that lay well beyond
    the intended scope of the design.

    (This argument assumes @4 < length key0 == length key1 == length name@)

4.  The transition code includes a counter to ensure that the transitions
    are different on every call to @expand@.  The counter takes up the
    first four bytes of the transition code to ensure it affects the first
    output block.

    This implies that in the highly unlikely case that bcrypt's machine
    ever loops back around to the same state within a single key-stretching
    computation, this counter /ensures/ that the next state transitioned
    to /will/ be different than before, and will be different within the
    first blowfish block, thus breaking any cycles.

-}

module Crypto.G3P.BCrypt.Subtle
  ( orpheanBeholderScryDoubt
  , bcrypt_outputSalt
  , bcryptRaw_outputSalt
  , bcryptRaw_genInputs
  , BCryptXs(..)
  , bcryptXs
  , BCryptXsCtr(..)
  , bcryptXsCtrSuperRound
  , bcryptXs_maxKeyLength
  , bcryptXs_maxSaltLength
  , bcryptXsCtr_outputLength
  , BCryptState(..)
  , base64Encode
  , base64Decode
  ) where

#include "g3p_bcrypt.h"

import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import           Data.ByteString.Internal (c2w, w2c)
import qualified Data.ByteString.Internal as B
import qualified Data.Char as Char
import           Data.Word
import           Data.Int

import           Foreign.C.String
import           Foreign.C.Types
import           Foreign.ForeignPtr
import           Foreign.Ptr
import           System.IO.Unsafe


orpheanBeholderScryDoubt :: ByteString
orpheanBeholderScryDoubt = "OrpheanBeholderScryDoubt"

bcrypt_outputSalt :: ByteString
bcrypt_outputSalt = orpheanBeholderScryDoubt

bcryptRaw_outputSalt :: ByteString
bcryptRaw_outputSalt = orpheanBeholderScryDoubt

-- uhh, whut? Am I looking at the wrong version of some documentation? Figuring
-- out why this is at least sometimes necessary is a good puzzle for later:

myUseAsCString :: ByteString -> (CString -> IO a) -> IO a
myUseAsCString x f = if B.null x then f nullPtr else B.unsafeUseAsCString x f

data BCryptXs = BCryptXs
  { bcryptXs_key0 :: !ByteString
  , bcryptXs_salt0 :: !ByteString
  , bcryptXs_keyL :: !ByteString
  , bcryptXs_saltL :: !ByteString
  , bcryptXs_keyR :: !ByteString
  , bcryptXs_saltR :: !ByteString
  , bcryptXs_saltZ :: !ByteString -- ^ not subject to maxSaltLength, but that doesn't seem overly relevant
  , bcryptXs_rounds :: !Word32
  }

data BCryptXsCtr = BCryptXsCtr
  { bcryptXsCtr_key0 :: !ByteString
  , bcryptXsCtr_key1 :: !ByteString
  , bcryptXsCtr_tag  :: !ByteString
  , bcryptXsCtr_name :: !ByteString
  }

foreign import capi "g3p_bcrypt.h G3P_bcrypt_xs"
  c_bcrypt_xs
    :: CString -> Word16 -> CString -> Word16
    -> CString -> Word16 -> CString -> Word16
    -> CString -> Word16 -> CString -> Word16
    -> CString -> Word32 -> Word32 -> Ptr Word8 -> IO ()

foreign import capi "g3p_bcrypt.h G3P_bcrypt_xs_ctr_superround"
  c_bcrypt_xs_ctr_superround
    :: CString
    -> CString -> Word32 -> CString -> Word32
    -> CString -> Word32 -> CString -> Word32
    -> Word32 -> Word32 -> Word32 -> CString -> IO Word32

foreign import capi "g3p_bcrypt_base64.h G3P_bcrypt_base64Encode"
  c_bcrypt_base64Encode
    :: Ptr Word8
    -> CString
    -> Word32
    -> IO ()

foreign import capi "g3p_bcrypt_base64.h G3P_bcrypt_base64Decode"
  c_bcrypt_base64Decode
    :: Ptr Word8
    -> CString
    -> Word32
    -> IO CInt

-- | Any key longer than 72 bytes will be truncated.

bcryptXs_maxKeyLength :: Int
bcryptXs_maxKeyLength = (#const BCRYPT_XS_MAX_KEY_LENGTH)

-- | Any salt longer than 4168 bytes will be truncated.

bcryptXs_maxSaltLength :: Int
bcryptXs_maxSaltLength = (#const BCRYPT_XS_MAX_SALT_LENGTH)

-- | returns 4168 bytes
bcryptXsCtr_outputLength :: Int
bcryptXsCtr_outputLength = (#const G3P_BLF_CTX_LENGTH)

-- | bcrypt with an excessive amount of freedom. As such, this function
--   is trivially insecure, but it can still be used to implement secure
--   password hashing functions, including standard bcrypt and the very
--   lightly generalized bcryptRaw.
--
--   This was the starting point for 'bcryptXsCtrSuperRound' and 'bcryptXsFree'

bcryptXs :: BCryptXs -> ByteString
bcryptXs x = if B.null sZ then "" else unsafePerformIO $ do
  myUseAsCString k0 $ \k0' -> do
    myUseAsCString s0 $ \s0' -> do
      myUseAsCString kL $ \kL' -> do
        myUseAsCString sL $ \sL' -> do
          myUseAsCString kR $ \kR' -> do
            myUseAsCString sR $ \sR' -> do
              myUseAsCString sZ $ \sZ' -> do
                B.create (B.length sZ) $ \out' -> do
                    (c_bcrypt_xs
                        k0' (len16 k0) s0' (len16 s0)
                        kL' (len16 kL) sL' (len16 sL)
                        kR' (len16 kR) sR' (len16 sR)
                        sZ' (len32 sZ) rounds out')
  where
    k0 = bcryptXs_key0 x
    s0 = bcryptXs_salt0 x
    kL = bcryptXs_keyL x
    sL = bcryptXs_saltL x
    kR = bcryptXs_keyR x
    sR = bcryptXs_saltR x
    sZ = bcryptXs_saltZ x
    rounds = bcryptXs_rounds x

-- | Likely at least somewhat less subtle than the one above, thanks to the addition of a counter.

bcryptXsCtrSuperRound :: BCryptXsCtr -> Word32 -> Word32 -> Word32 -> Maybe BCryptState -> (Word32, BCryptState)
bcryptXsCtrSuperRound x tagPos rounds ctr mst = unsafePerformIO $ do
  myUseAsCString k0 $ \k0' -> do
    myUseAsCString k1 $ \k1' -> do
      myUseAsCString tt $ \tt' -> do
        myUseAsCString nn $ \nn' -> do
          myUseAsCString st $ \st' -> do
            outPtr <- B.mallocByteString bcryptXsCtr_outputLength
            let out = B.BS outPtr bcryptXsCtr_outputLength
            myUseAsCString out $ \out' -> do
                tagPos' <- c_bcrypt_xs_ctr_superround
                              st'
                              k0' (len32 k0) k1' (len32 k1)
                              nn' (len32 nn) tt' (len32 tt)
                              tagPos rounds ctr out'
                return (tagPos',BCryptState out)
  where
    k0 = bcryptXsCtr_key0 x
    k1 = bcryptXsCtr_key1 x
    tt = bcryptXsCtr_tag x
    nn = bcryptXsCtr_name x
    st = maybe "" bcryptState_toByteString mst

maxLen16 :: Int
maxLen16 = fromIntegral (maxBound :: Word16)

len16 :: ByteString -> Word16
len16 x = fromIntegral (min maxLen16 (B.length x))


maxWord32 :: Int64
maxWord32 = fromIntegral (maxBound :: Word32)

maxInt :: Int64
maxInt = fromIntegral (maxBound :: Int)

maxLen32 :: Int
maxLen32 = fromIntegral (min maxWord32 maxInt)

len32 :: ByteString -> Word32
len32 x = fromIntegral (min maxLen32 (B.length x))

newtype BCryptState = BCryptState { bcryptState_toByteString :: ByteString } deriving (Eq, Ord, Show)

-- | Given the length of some binary blob of data, how long will the base64 encoded
--   version be, without padding?

-- There's probably a "cleaner" way to compute this with bit tricks
base64EncodeLength :: Int -> Int
base64EncodeLength n =
    4 * q + if r == 0 then 0 else 1 + r
  where
    (q,r) = n `divMod` 3

-- | Given the length of some base64 encoded data, how long will the binar blob be?
--   The input length must not include any padding, commonly appearing as one or
--   two @=@ characters at the end of a string.

-- There's probably a "cleaner" way to compute this with bit tricks
base64DecodeLength :: Int -> Maybe Int
base64DecodeLength n
    | r == 0 = Just (3 * q)
    | r == 1 = Nothing
    | otherwise = Just ((3 * q) + (r - 1))
  where
    (q,r) = n `divMod` 4

base64Decode :: ByteString -> Maybe ByteString
base64Decode input =
  case base64DecodeLength inLen of
    Nothing -> Nothing
    Just outLen ->
      unsafePerformIO $ do
        myUseAsCString input $ \inPtr -> do
          out <- B.mallocByteString outLen
          err <- withForeignPtr out $ \outPtr -> do
            c_bcrypt_base64Decode outPtr inPtr (fromIntegral inLen)
          if err == 0
          then return $! Just $! B.BS out outLen
          else return Nothing
  where
    inLen = B.length input

base64Encode :: ByteString -> ByteString
base64Encode input =
  B.unsafeCreate outLen $ \outPtr -> do
    myUseAsCString input $ \inPtr -> do
      c_bcrypt_base64Encode outPtr inPtr (fromIntegral inLen)
  where
    inLen = B.length input
    outLen = base64EncodeLength inLen

bcryptRaw_genInputs :: ByteString -> ByteString -> Word32 -> BCryptXs
bcryptRaw_genInputs (truncateKey -> key) (truncateKey -> salt) rounds =
    BCryptXs
    { bcryptXs_key0 = key
    , bcryptXs_salt0 = salt
    , bcryptXs_keyL = key
    , bcryptXs_saltL = B.empty
    , bcryptXs_keyR = salt
    , bcryptXs_saltR = B.empty
    , bcryptXs_saltZ = bcryptRaw_outputSalt
    , bcryptXs_rounds = rounds
    }

truncateKey :: ByteString -> ByteString
truncateKey = B.take bcryptXs_maxKeyLength

