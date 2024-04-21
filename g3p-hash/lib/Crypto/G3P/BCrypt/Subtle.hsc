{-# LANGUAGE CApiFFI, OverloadedStrings #-}

-- |  Bcrypt with an excessive amount of freedom and salt, appropriate for
--    our excessively salty era.

module Crypto.G3P.BCrypt.Subtle
  ( BCryptInputs(..)
  , bcryptXS
  , bcryptXSCtrDump
  , bcryptXS_maxKeyLength
  , bcryptXS_maxSaltLength
  , bcryptXSCtrDump_outputLength
  ) where

#include "bcrypt_xs.h"

import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import           Data.Word
import           Data.Int

import           Foreign.C.String
import           System.IO.Unsafe

data BCryptInputs = BCryptInputs
  { bcryptInputs_key0 :: !ByteString
  , bcryptInputs_salt0 :: !ByteString
  , bcryptInputs_keyL :: !ByteString
  , bcryptInputs_saltL :: !ByteString
  , bcryptInputs_keyR :: !ByteString
  , bcryptInputs_saltR :: !ByteString
  , bcryptInputs_saltZ :: !ByteString -- ^ not subject to maxSaltLength, but that doesn't seem overly relevant
  , bcryptInputs_rounds :: !Word32
  }

foreign import capi "bcrypt_xs.h bcrypt_xs" c_bcrypt_xs
    :: CString -> Word16 -> CString -> Word16
    -> CString -> Word16 -> CString -> Word16
    -> CString -> Word16 -> CString -> Word16
    -> CString -> Word32 -> Word32 -> CString -> IO ()

foreign import capi "bcrypt_xs.h bcrypt_xs_ctr_dump" c_bcrypt_xs_ctr_dump
    :: CString -> Word16 -> CString -> Word16
    -> CString -> Word16 -> CString -> Word16
    -> CString -> Word16 -> CString -> Word16
    -> Word32 -> CString -> IO ()

-- | Any key longer than 72 bytes will be truncated.

bcryptXS_maxKeyLength :: Int
bcryptXS_maxKeyLength = (#const BCRYPT_XS_MAX_KEY_LENGTH)

-- | Any salt longer than 4168 bytes will be truncated.

bcryptXS_maxSaltLength :: Int
bcryptXS_maxSaltLength = (#const BCRYPT_XS_MAX_SALT_LENGTH)

-- | returns 4168 bytes
bcryptXSCtrDump_outputLength :: Int
bcryptXSCtrDump_outputLength = (#const G3P_BLF_CTX_LENGTH)

-- | A bcrypt version with excessive freedom and extended, extra large salts.

bcryptXS :: BCryptInputs -> ByteString
bcryptXS x = if B.null sZ then "" else unsafePerformIO $ do
  B.unsafeUseAsCString k0 $ \k0' -> do
    B.unsafeUseAsCString s0 $ \s0' -> do
      B.unsafeUseAsCString kL $ \kL' -> do
        B.unsafeUseAsCString sL $ \sL' -> do
          B.unsafeUseAsCString kR $ \kR' -> do
            B.unsafeUseAsCString sR $ \sR' -> do
              B.unsafeUseAsCString sZ $ \sZ' -> do
                -- using a superfluous `seq` to try to ensure that this
                -- allocates a new unique bytestring. FIXME: there's almost
                -- certainly a better, more proper, more idiomatic solution
                let out = B.replicate (sZ' `seq` B.length sZ) 0
                B.unsafeUseAsCString out $ \out' -> do
                    (c_bcrypt_xs
                        k0' (len k0) s0' (len s0)
                        kL' (len kL) sL' (len sL)
                        kR' (len kR) sR' (len sR)
                        sZ' (len' sZ) rounds out')
                    return out
  where
    k0 = f (bcryptInputs_key0 x)
    s0 = f (bcryptInputs_salt0 x)
    kL = f (bcryptInputs_keyL x)
    sL = f (bcryptInputs_saltL x)
    kR = f (bcryptInputs_keyR x)
    sR = f (bcryptInputs_saltR x)
    sZ = bcryptInputs_saltZ x
    rounds = bcryptInputs_rounds x

-- | Likely at least somewhat less subtle than the one above, thanks to the addition of a counter.

bcryptXSCtrDump :: BCryptInputs -> ByteString
bcryptXSCtrDump x = if B.null sZ then "" else unsafePerformIO $ do
  B.unsafeUseAsCString k0 $ \k0' -> do
    B.unsafeUseAsCString s0 $ \s0' -> do
      B.unsafeUseAsCString kL $ \kL' -> do
        B.unsafeUseAsCString sL $ \sL' -> do
          B.unsafeUseAsCString kR $ \kR' -> do
            B.unsafeUseAsCString sR $ \sR' -> do
              -- using a superfluous `seq` to try to ensure that this
              -- allocates a new unique bytestring. FIXME: there's almost
              -- certainly a better, more proper, more idiomatic solution
              let out = B.replicate (sR' `seq` bcryptXSCtrDump_outputLength) 0
              B.unsafeUseAsCString out $ \out' -> do
                  (c_bcrypt_xs_ctr_dump
                        k0' (len k0) s0' (len s0)
                        kL' (len kL) sL' (len sL)
                        kR' (len kR) sR' (len sR)
                        rounds out')
                  return out
  where
    k0 = f (bcryptInputs_key0 x)
    s0 = f (bcryptInputs_salt0 x)
    kL = f (bcryptInputs_keyL x)
    sL = f (bcryptInputs_saltL x)
    kR = f (bcryptInputs_keyR x)
    sR = f (bcryptInputs_saltR x)
    sZ = bcryptInputs_saltZ x
    rounds = bcryptInputs_rounds x

f :: ByteString -> ByteString
f key = if B.null key then "\x00" else key

maxLen16 :: Int
maxLen16 = fromIntegral (maxBound :: Word16)

len :: ByteString -> Word16
len x = fromIntegral (min maxLen16 (B.length x))

maxWord32 :: Int64
maxWord32 = fromIntegral (maxBound :: Word32)

maxInt :: Int64
maxInt = fromIntegral (maxBound :: Int)

maxLen32 :: Int
maxLen32 = fromIntegral (min maxWord32 maxInt)

len' :: ByteString -> Word32
len' x = fromIntegral (min maxLen32 (B.length x))
