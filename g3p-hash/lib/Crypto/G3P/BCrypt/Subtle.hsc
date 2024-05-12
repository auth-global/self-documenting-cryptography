{-# LANGUAGE CApiFFI, OverloadedStrings #-}

{- |

Bcrypt with an excessive amount of freedom and salt, appropriate for
our excessively salty era. This module exports bindings that are
potentially cryptographically unsafe to lower-level functions written in C.

Bcrypt's state machine exhibits a beautiful grouplike structure. Blowfish's
state machine is exactly 4168 bytes, and bcrypt's modification to blowfish's
key expansion represents a /transition code/ that is also exactly 4168 bytes
long.

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
and output states.

This structure implies that no state or transition code is particularly
special, and that choosing a different transition code does not change the
dynamical properties of the blowfish state machine /on average/.

Of course, the molecules in a cup full of room-temperature water /on average/
are moving much too slowly to ever become a gas, yet a cup full of water that
is exposed to the open air will reliably evaporate over time. Similarly,
this grouplike structure also implies that allowing unrestricted use of
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
    external bytes in the same places in the transition code, but complements
    the first 4 bytes for a guaranteed non-linear difference.

    This breaks all the obvious attacks, and may well break many or all of
    the less obvious attacks too. I wouldn't want to rely too much on this
    particular combinatorial block design structure without further study,
    which is likely to suggest further design improvements.

    However, this was a no-risk move that didn't cost the intended use cases
    anything, but looked plausibly strong against issues that lay well beyond
    the intended scope of the design.

    (This argument assumes @length key0 == length key1 == length name@)

4.  The transition code includes a counter to ensure that the transitions
    are different on every call to @expand@.  The counter takes up the
    first four bytes of the transition code to ensure it affects the first
    output block.

    This implies that in the highly unlikely case that bcrypt's machine
    ever loops back around to the same state within a single key-stretching
    computation, this counter /ensures/ that the next state transitioned
    to /will/ be different than before, and will be different within the
    first blowfish block, thus breaking any cycles.

If I were going all-out to build a really top-notch new mode of operation
for bcrypt centered around transition codes, I would certainly investigate
protecting much more of the initial sequence of the transition code and
let potentially untrusted tags have most or all of the P-box xor before
the transition code comes into play.

However, given that I'm /only/ going all out to build a really top-notch
mode of operation for bcrypt as a password hash function with extended
salts, I felt it best to mimic the existing mode of operation as much as
possible: thus two derived keys get alternated in the p-box xor, simulating
the existing structure of alternating the password and salt. This should
allow existing analyses for bcrypt to be carried over to the G3P with much
greater ease.

-}

module Crypto.G3P.BCrypt.Subtle
  ( BCryptXs(..)
  , bcryptXs
  , BCryptXsCtr(..)
  , bcryptXsCtrSuperRound
  , bcryptXs_maxKeyLength
  , bcryptXs_maxSaltLength
  , bcryptXsCtr_outputLength
  , BCryptState(..)
  ) where

#include "g3p_bcrypt.h"

import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import qualified Data.ByteString.Internal as B
import           Data.Word
import           Data.Int

import           Foreign.Ptr
import           Foreign.C.String
import           System.IO.Unsafe


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

foreign import capi "g3p_bcrypt.h bcrypt_xs" c_bcrypt_xs
    :: CString -> Word16 -> CString -> Word16
    -> CString -> Word16 -> CString -> Word16
    -> CString -> Word16 -> CString -> Word16
    -> CString -> Word32 -> Word32 -> Ptr Word8 -> IO ()

foreign import capi "g3p_bcrypt.h bcrypt_xs_ctr_superround" c_bcrypt_xs_ctr_superround
    :: CString
    -> CString -> Word32 -> CString -> Word32
    -> CString -> Word32 -> CString -> Word32
    -> Word32 -> Word32 -> Word32 -> CString -> IO Word32

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
