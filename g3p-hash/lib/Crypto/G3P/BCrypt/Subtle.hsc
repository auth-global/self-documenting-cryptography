{-# LANGUAGE CApiFFI, OverloadedStrings #-}

-- |  Bcrypt with an excessive amount of freedom and salt, appropriate for
--    our excessively salty era.

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

#include "bcrypt_xs.h"

import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import           Data.Word
import           Data.Int

import           Foreign.C.String
import           System.IO.Unsafe

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
  { bcryptXsCtr_keyL :: !ByteString
  , bcryptXsCtr_keyR :: !ByteString
  , bcryptXsCtr_tag  :: !ByteString
  , bcryptXsCtr_name :: !ByteString
  }

foreign import capi "bcrypt_xs.h bcrypt_xs" c_bcrypt_xs
    :: CString -> Word16 -> CString -> Word16
    -> CString -> Word16 -> CString -> Word16
    -> CString -> Word16 -> CString -> Word16
    -> CString -> Word32 -> Word32 -> CString -> IO ()

foreign import capi "bcrypt_xs.h bcrypt_xs_ctr_superround" c_bcrypt_xs_ctr_superround
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

-- | A bcrypt version with excessive freedom and extended, extra large salts.

bcryptXs :: BCryptXs -> ByteString
bcryptXs x = if B.null sZ then "" else unsafePerformIO $ do
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
                        k0' (len16 k0) s0' (len16 s0)
                        kL' (len16 kL) sL' (len16 sL)
                        kR' (len16 kR) sR' (len16 sR)
                        sZ' (len32 sZ) rounds out')
                    return out
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
  B.unsafeUseAsCString kL $ \kL' -> do
    B.unsafeUseAsCString kR $ \kR' -> do
      B.unsafeUseAsCString tt $ \tt' -> do
        B.unsafeUseAsCString nn $ \nn' -> do
          B.unsafeUseAsCString st $ \st' -> do
            -- using a superfluous `seq` to try to ensure that this
            -- allocates a new unique bytestring. FIXME: there's almost
            -- certainly a better, more proper, more idiomatic solution
            let out = B.replicate bcryptXsCtr_outputLength (nn' `seq` 0)
            B.unsafeUseAsCString out $ \out' -> do
                tagPos' <- c_bcrypt_xs_ctr_superround
                              st'
                              kL' (len32 kL) kR' (len32 kR)
                              nn' (len32 nn) tt' (len32 tt)
                              tagPos rounds ctr out'
                return (tagPos',BCryptState out)
  where
    kL = bcryptXsCtr_keyL x
    kR = bcryptXsCtr_keyR x
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
