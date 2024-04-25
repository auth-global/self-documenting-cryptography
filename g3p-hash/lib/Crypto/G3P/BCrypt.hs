{-# LANGUAGE ViewPatterns, OverloadedStrings #-}

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
--    4.  Standard bcrypt limits salt length to 16 bytes. Version 1 of the G3P
--        depends on 72 byte salt parameters, and Version 2 depends on 4168 byte
--        salts.
--
--    5.  In addition to the standard salt parameter, Version 2 of the G3P
--        depends on two additional 4168 byte salt parameters which are
--        assumed to be filled with null bytes by standard bcrypt.
--
--    6.  G3Pb2 also implements a counter at the start of the excess salt
--
--    For this reason, this binding completely removes the code for handling
--    unix-style bcrypt hashes, which has repeatedly proven problematic. One
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
  , bcryptRaw_outputSalt
  , orpheanBeholderScryDoubt
  , BCryptXs()
  , bcryptRaw_genInputs
  ) where

import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import           Data.Word

import           Crypto.G3P.BCrypt.Subtle

-- | Any input longer than 72 bytes will be truncated.

bcryptRaw_maxInputLength :: Int
bcryptRaw_maxInputLength = bcryptXs_maxKeyLength

-- | Any output hash from 'bcryptRaw' will be exactly 24 bytes long.

bcryptRaw_outputLength :: Int
bcryptRaw_outputLength = B.length bcryptRaw_outputSalt

bcryptRaw_outputSalt :: ByteString
bcryptRaw_outputSalt = orpheanBeholderScryDoubt

orpheanBeholderScryDoubt :: ByteString
orpheanBeholderScryDoubt = "OrpheanBeholderScryDoubt"

-- | @bcryptRaw key salt rounds@ Be aware that keys and salts that are longer
--   than 72 bytes do get truncated to exactly 72 bytes. This binding will
--   return a hash that is exactly 24 bytes long.
--
--   Note the rounds parameter is one less than the number of rounds to be
--   computed. Thus if you want something equivalent to the traditional bcrypt
--   cost parameter of 12, you need to specify 4095 rounds.  This is because
--   @2^12 - 1 = 4095@.

bcryptRaw :: ByteString -> ByteString -> Word32 -> ByteString
bcryptRaw key salt rounds = bcryptXs (bcryptRaw_genInputs key salt rounds)

-- | Generate an equivalent input block for 'bcryptXs'

bcryptRaw_genInputs :: ByteString -> ByteString -> Word32 -> BCryptXs
bcryptRaw_genInputs (f -> key) (f -> salt) rounds =
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

f :: ByteString -> ByteString
f = B.take bcryptRaw_maxInputLength
