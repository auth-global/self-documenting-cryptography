{-# LANGUAGE CApiFFI, OverloadedStrings, BangPatterns, ViewPatterns #-}

-------------------------------------------------------------------------------
-- |
-- Module:      Crypto.G3P.BCrypt.Subtle
-- Copyright:   (c) 2024 Auth Global
-- License:     Apache2
--
-------------------------------------------------------------------------------
{-|
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
derivation of other inputs to bcrypt, thus enforcing the requirement that the
tags be chosen before the inputs are examined. For example, the G3P integration
performs local commitments to parts of the long tag, and the entire long tag is
intended to be committed to before the beginning of the PHKDF key-stretching
phase.

As a fallback, the bcryptXsCtrSuperRound has a couple of design features that
somewhat naively attempt to address this issue:

1.  The initial call to @expand@ is designed to rapidly and completely
    encode both @key0@ and @key1@ into the bcrypt state, relative to
    the starting round state. This ensures a complete transfer of entropy
    after a small number of Blowfish block encryptions.

    (This argument assumes @length key0 + length key1 <= 72@ bytes long)

2.  Except for the very first bcrypt-state XOR operation of a superround in
    the initial call to @expand@, the first N bytes of the P-box are protected
    by key0, key1, the function name, and the counter, and thus outside the
    direct control of the long tag. This also serves to restrict the space of
    possible bcrypt-state transitions by prohibiting almost all of them within
    the context of a single computation.

    (This argument assumes @length key0 == length key1 == length name == N@)

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
  , BlowfishContextRef(..)
  , blowfishInit
  , blowfishEncodeRef
  , blowfishDecodeRef
  , blowfishExpandRef
  , blowfishRevexpandRef
  , blowfishEncryptECB64Ref
  , blowfishEncryptECB64
  ) where

#include "g3p_bcrypt.h"

import           Control.Monad.ST
import           Control.Monad.ST.Unsafe
import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import qualified Data.ByteString.Internal as B
import           Data.Word
import           Data.Int

import           Foreign.C.String
import           Foreign.C.Types
import           Foreign.ForeignPtr
import           Foreign.Marshal.Utils
import           Foreign.Ptr
import           Foreign.Storable
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
    :: CString -> Word32 -> CString -> Word32
    -> CString -> Word32 -> CString -> Word32
    -> CString -> Word32 -> CString -> Word32
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

data BlfCtx

instance Storable BlfCtx where
  alignment _ = 8
  sizeOf _  = #{size G3P_blf_ctx}

newtype BlowfishContext = BlowfishContext { unBlowfishContext :: ForeignPtr BlfCtx }

newtype BlowfishContextRef st = BlowfishContextRef { unBlowfishContextRef :: ForeignPtr BlfCtx }

blowfishInitRef :: ST s (BlowfishContextRef s)
blowfishInitRef =
  unsafeIOToST $ do
    fp <- mallocForeignPtr
    withForeignPtr fp $ \p -> do
      copyBytes p c_blowfish_init (sizeOf (undefined :: BlfCtx))
    return (BlowfishContextRef fp)

-- | Deserialize a blowfish context from a binary blob, which must be 4168
--   bytes long. The format consists of 1042 big-endian unsigned 'Word32's
--   in network byte order, the first 18 words comprising the P-box and the
--   remaining 1024 comprising the S-box. Inverse of 'blowfishEncode'

blowfishDecode :: ByteString -> ST s (Maybe (BlowfishContextRef s))
blowfishDecode st
  | B.length st /= bcryptXsCtr_outputLength = return Nothing
  | otherwise =
    unsafeIOToST $ do
      fp <- mallocForeignPtr
      myUseAsCString st $ \stp -> do
        withForeignPtr fp $ \p -> do
          c_blowfish_decodestate stp p
      return (Just (BlowfishContextRef fp))

foreign import capi "g3p_bcrypt.h G3P_Blowfish_decodestate"
  c_blowfish_decodestate
    :: CString
    -> Ptr BlfCtx
    -> IO ()

-- | Serialize a blowfish context as a binary blob, which will be 4168 bytes
--   long. The format consists of 1042 big-endian unsigned 'Word32's
--   in network byte order, the first 18 words comprising the P-box and the
--   remaining 1024 comprising the S-box. Inverse of 'blowfishDecode'

blowfishEncode :: BlowfishContextRef s -> ST s ByteString
blowfishEncode (BlowfishContextRef ctx) =
  unsafeIOToST $ do
    withForeignPtr ctx $ \p -> do
      B.create bcryptXsCtr_outputLength $ \st ->
        c_blowfish_encodestate p (castPtr st)

foreign import capi "g3p_bcrypt.h G3P_Blowfish_encodestate"
  c_blowfish_encodestate
    :: Ptr BlfCtx
    -> CString
    -> IO ()

-- | XOR plus blowfish-expand.  The XOR operation is classic bcrypt,
--   which modifies the P-box by truncating or cyclically extending
--   the first string parameter to 72 bytes.  Note that you can bypass
--   this XOR operation by simply passing in the empty string.
--
--   The second argument is a transition code, which is truncated or cyclically
--   extended to 4168 bytes long. Arbitrary unrestricted use of a transition
--   code trivially allows full control over the resulting state, as
--   illustrated by 'blowfishTranscode'.

blowfishExpandRef
  :: BlowfishContextRef s
  -> Bool  -- ^ does the key have an implicit null byte?
  -> ByteString -- ^ key to be xor'ed into the P-box
  -> ByteString -- ^ salt to be encrypted via blowfish
  -> ST s ()
blowfishExpandRef (BlowfishContextRef ctx) !implicitNull
                  (B.take 72 -> key) (B.take 4168 -> salt) =
  unsafeIOToST $ do
    withForeignPtr ctx $ \xp ->
      myUseAsCString key $ \kp ->
        myUseAsCString salt $ \sp ->
          let kl = fromIntegral (B.length key)
              sl = fromIntegral (B.length salt)
           in c_blowfish_expand xp kp kl sp sl implicitNull

foreign import capi "g3p_bcrypt.h G3P_Blowfish_expand"
  c_blowfish_expand
    :: Ptr BlfCtx
    -> CString -> Word32
    -> CString -> Word32
    -> Bool -> IO ()

-- | a reverse blowfish-expand, then XOR.  Undoes the action of
--   'blowfishExpand'
--
--   The existence of this function is mostly interesting from
--   a theoretical perspective, as it is one of the trio of functions
--   that establishes the quasigroup structure surrounding bcryptExpand,
--   and illustrates the downside of transferring a bcryptXsCtr computation
--   in the middle of a super round.

blowfishRevexpandRef
  :: BlowfishContextRef s
  -> Bool  -- ^ does the key have an implicit null byte?
  -> ByteString -- ^ key to be xor'ed into the P-box
  -> ByteString -- ^ salt to be encrypted via blowfish
  -> ST s ()
blowfishRevexpandRef (BlowfishContextRef ctx) !implicitNull
                     (B.take 72 -> key) (B.take 4168 -> salt) =
  unsafeIOToST $ do
    withForeignPtr ctx $ \xp ->
      myUseAsCString key $ \kp ->
        myUseAsCString salt $ \sp ->
          let kl = fromIntegral (B.length key)
              sl = fromIntegral (B.length salt)
           in c_blowfish_revexpand xp kp kl sp sl implicitNull

foreign import capi "g3p_bcrypt.h G3P_Blowfish_revexpand"
  c_blowfish_revexpand
    :: Ptr BlfCtx
    -> CString -> Word32
    -> CString -> Word32
    -> Bool -> IO ()

-- | given a desired starting state and ending state, this function produces
--   the salt that can be used with 'blowfishExpand' or 'blowfishRevexpand'
--   that corresponds to that transition.
--
--   Note that this function does not account for the XOR operation, so you'll
--   need to do that to use this function. See the test suite for some examples.
--
--   The existence of this function is rather interesting. It provides a means
--   of abusing the salt parameter, as demonstrated by the sample attack on
--   'bcryptXs', and illustrates the relative cryptoacoustic durability of
--   plaintext messages encoded into this salt.
--
--   Namely, it demonstrates that anybody who can see a snapshot of bcrypt's
--   cryptographic state before and after a blowfish expansion (without xor)
--   can efficiently deduce the salt that was used to make the transition.
--
--   The same property is also more obviously true of the XOR operation,
--   which has a much simpler algebraic structure.  One can deduce the
--   key that was xor-ed into the cryptographic state by simply xor-ing the
--   before and after state.

foreign import capi "g3p_bcrypt.h G3P_Blowfish_transcode"
  c_blowfish_transcode
    :: CString
    -> CString
    -> CString
    -> IO ()

-- | Encrypt a short-ish string using a blowfish context as the key
--   in Electronic Codebook (ECB) mode iterated 64 times. This does
--   not mutate the blowfish state.

blowfishEncryptECB64Ref :: BlowfishContextRef s -> ByteString -> ST s ByteString
blowfishEncryptECB64Ref (BlowfishContextRef ctx) str =
  unsafeIOToST $ do
    withForeignPtr ctx $ \p -> do
      myUseAsCString str $ \inp -> do
        B.create len $ \outp -> do
          c_bcrypt_xs_output p inp (fromIntegral len) (castPtr outp)
  where
    len = B.length str

foreign import capi "g3p_bcrypt.h G3P_bcrypt_xs_output"
  c_bcrypt_xs_output
    :: Ptr BlfCtx
    -> CString
    -> Word32
    -> CString
    -> IO ()

-- | Unsafely creates a mutable reference of a pure value without copying it.
--   This is entirely safe to use if you never mutate the reference, or if you
--   are guaranteed to never refer to the pure value again. Otherwise you'll
--   break Haskell's referential transparency, thus inhibiting your ability to
--   algebraically reason about the behavior of a Haskell program.
blowfishUnsafeThaw :: BlowfishContext -> BlowfishContextRef s
blowfishUnsafeThaw (BlowfishContext x) = BlowfishContextRef x

blowfishEncryptECB64 :: BlowfishContext -> ByteString -> ByteString
blowfishEncryptECB64 ctx str =
  runST $ blowfishEncryptECB64Ref (blowfishUnsafeThaw ctx) str

blowfishEncryptECB64Ref :: BlowfishContextRef s -> ByteString -> ST s ByteString
blowfishEncryptECB64Ref (BlowfishContextRef ctx) str =
  unsafeIOToST $ do
    withForeignPtr ctx $ \p -> do
      myUseAsCString str $ \inp -> do
        B.create len $ \outp -> do
          c_bcrypt_xs_output p inp (fromIntegral len) (castPtr outp)
  where
    len = B.length str

foreign import capi "g3p_bcrypt.h G3P_bcrypt_xs_output"
  c_bcrypt_xs_output
    :: Ptr BlfCtx
    -> CString
    -> Word32
    -> CString
    -> IO ()

-- | Decrypt a short-ish string using a blowfish context as the key in
--   Electronic Codebook (ECB) mode iterated 64 times. This string must be an
--   exact multiple of 8. This routine does not mutate the blowfish state.

blowfishDecryptECB64Ref :: BlowfishContextRef s -> ByteString -> ST s (Maybe ByteString)
blowfishDecryptECB64Ref (BlowfishContextRef ctx) str =
  | len `mod` 8 /= 0 =
    return Nothing
  | otherwise =
    unsafeIOToST $ do
      withForeignPtr ctx $ \p -> do
        myUseAsCString str $ \inp -> do
          Just <$> B.create len $ \outp -> do
            _ <- c_bcrypt_xs_revoutput p inp (fromIntegral len) (castPtr outp)
	    return ()
  where
    len = B.length str

foreign import capi "g3p_bcrypt.h G3P_bcrypt_xs_revoutput"
  c_bcrypt_xs_revoutput
    :: Ptr BlfCtx
    -> CString
    -> Word32
    -> CString
    -> IO ()

blowfishDecryptECB64 :: BlowfishContext -> ByteString -> Maybe ByteString
blowfishDecryptECB64 ctx str =
  runST $ blowfishDecryptECB64Ref (blowfishUnsafeThaw ctx) str

blowfishEncryptECB64Ref :: BlowfishContextRef s -> ByteString -> ST s ByteString
blowfishEncryptECB64Ref (BlowfishContextRef ctx) str =
  unsafeIOToST $ do
    withForeignPtr ctx $ \p -> do
      myUseAsCString str $ \inp -> do
        B.create len $ \outp -> do
          c_bcrypt_xs_output p inp (fromIntegral len) (castPtr outp)
  where
    len = B.length str

foreign import capi "g3p_bcrypt.h G3P_bcrypt_xs_output"
  c_bcrypt_xs_output
    :: Ptr BlfCtx
    -> CString
    -> Word32
    -> CString
    -> IO ()

foreign import capi "g3p_bcrypt.h &g3p_blf_init"
  c_blowfish_init :: Ptr BlfCtx

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
                        k0' (len k0) s0' (len s0)
                        kL' (len kL) sL' (len sL)
                        kR' (len kR) sR' (len sR)
                        sZ' (len sZ) rounds out')
  where
    len = fromIntegral . B.length
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