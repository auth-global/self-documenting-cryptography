{-# LANGUAGE CApiFFI, ViewPatterns #-}

-- |  A very minimal binding to the core of the bcrypt algorithm, adapted from
--    OpenBSD's implementation. The Global Password Prehash Protocol version
--    G3Pb1 cannot be implemented in terms of standard bcrypt interfaces for
--    several reasons:
--
--    1.  Standard bcrypt hashes are truncated to 23 bytes.  The G3P depends
--        on all 24 output bytes.
--
--    2.  Standard bcrypt must specify a number of rounds that is a power of
--        two. The G3P allows any number of rounds between 1 and 2^32 inclusive.
--
--    3.  the G3P needs unimpeded access to the full 72 byte password input.
--        This is not doable with all bcrypt variants.
--
--    4.  Standard bcrypt limits salt length to 16 bytes.  The G3P depends on
--        72 byte salt parameters.
--
--    For this reason, this binding completely removes the code for handling
--    unix-style bcrypt hashes, whic has repeatedly proven problematic. One
--    of the major design motifs of the G3P is to replace this cruft with PHKDF,
--    which is intended to be bulletproof.
--
--    Similarly, this binding cannot be directly used to process unix-style
--    bcrypt hashes, which does make testing a bit of a challenge.  However,
--    the core algorithm is unmodified, so implementing unix-style hash
--    handling in terms of this binding is very much possible.
--
--    This will be done in the test suite for this library.  Hopefully that
--    implementation will eventually migrate here, once it's production-ready,
--    so that this binding might also be used to handle standard bcrypt hashes
--    directly.

module Crypto.G3P.BCrypt
  ( bcryptRaw
  , bcryptRaw_maxInputLength
  , bcryptRaw_outputLength
  ) where

#include "bcrypt_raw.h"

import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import           Data.Word

import           Foreign.C.String
import           Foreign.C
import           System.IO.Unsafe

foreign import capi "bcrypt_raw.h bcrypt_raw" c_bcrypt_raw :: CString -> Word32 -> CString -> Word32 -> CString -> Word32 -> IO ()

-- | Any input longer than 72 bytes will be truncated.

bcryptRaw_maxInputLength :: Int
bcryptRaw_maxInputLength = (#const BCRYPT_RAW_MAX_INPUT_LENGTH)

-- | Any output hash from 'bcryptRaw' will be exactly 24 bytes long.

bcryptRaw_outputLength :: Int
bcryptRaw_outputLength = (#const BCRYPT_RAW_OUTPUT_LENGTH)

-- | @bcryptRaw key salt rounds@ Be aware that key and salts that are longer than
--   72 bytes long do get truncated must be exactly 72 bytes long. This binding
--   will return a hash that is exactly 24 bytes long.
--
--   Note the rounds parameter is one less than the number of rounds to be
--   computed. Thus if you want something equivalent to the traditional bcrypt
--   cost parameter of 12, you need to specify 4095 rounds.  This is because
--   @2^12 - 1 = 4095@.

bcryptRaw :: ByteString -> ByteString -> Word32 -> ByteString
bcryptRaw (f -> key) (f -> salt) rounds
  = unsafePerformIO $ do
      B.unsafeUseAsCString key $ \keyPtr -> do
        B.unsafeUseAsCString salt $ \saltPtr -> do
          -- using a superfluous `seq` to try to ensure that this allocates a new
          -- unique bytestring.   FIXME: there's almost certainly a better, more
          -- proper, more idiomatic solution here
          let output = B.replicate bcryptRaw_outputLength (saltPtr `seq` 0)
          B.unsafeUseAsCString output $ \outPtr -> do
            c_bcrypt_raw keyPtr (len key) saltPtr (len salt) outPtr rounds
            return output
  where
    len key = fromIntegral (min 72 (B.length key))

f :: ByteString -> ByteString
f key = if B.null key then B.replicate 72 0 else key
