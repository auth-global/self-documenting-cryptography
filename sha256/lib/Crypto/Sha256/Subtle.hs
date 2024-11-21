{-# LANGUAGE MagicHash, UnboxedTuples, CApiFFI, UnliftedFFITypes, BangPatterns #-}

module Crypto.Sha256.Subtle where

import           Data.ByteString (ByteString)
import           Data.ByteString.Unsafe(unsafeUseAsCStringLen)
import           Data.ByteString.Short.Internal (ShortByteString(..))

-- import Data.Array.Byte
import Data.Bits((.&.))
import Data.Word
import qualified Data.ByteString as B
import Foreign.C
import Foreign.Ptr
import GHC.Exts
import GHC.IO

nullBuffer :: ByteString
nullBuffer = B.replicate 64 0

type Sha256MutableState# = MutableByteArray#

type Sha256State# = ByteArray#

type Sha256MutableCtx# = MutableByteArray#

type Sha256Ctx# = ByteArray#

data Sha256State = Sha256State { unSha256State :: !Sha256State# }

instance Eq Sha256State where
  x == y = compare x y == EQ

instance Ord Sha256State where
  compare (Sha256State x) (Sha256State y) =
    compare (c_const_memcmp_uint32be x y 8) 0

data Sha256Ctx = Sha256Ctx { unSha256Ctx :: !Sha256Ctx# }

instance Eq Sha256Ctx where
  x == y = compare x y == EQ

instance Ord Sha256Ctx where
  compare (Sha256Ctx x) (Sha256Ctx y) =
    compare (c_const_memcmp_ctx x y) 0

data Sha256MutableCtx a = Sha256MutableCtx { unSha256MutableCtx :: !(Sha256MutableCtx# a) }

sha256state_init :: Sha256State
sha256state_init =
  unsafePerformIO . IO $ \st ->
    let !(Ptr addr) = c_sha256_init
        !(# st0, a #) = newByteArray# 32# st
        st1 = copyAddrToByteArray# addr a 0# 32# st0
        -- FIXME?  Review this to ensure that 32# is the correct input above
        -- Problem is the documentation is ambiguous, and the source is magic.
        -- I'm assuming copyAddrToByteArray# works similarly as copyByteArray#.
        !(# st2, b #) = unsafeFreezeByteArray# a st1
     in (# st2, (Sha256State b) #)

-- | Note that this function only processes as many 64-byte blocks as possible,
--   then discards the remainder of the input.  Also note that this function does
--   nothing to track the number of bytes that have been fed into the state, which
--   will have to be done externally.

sha256state_feed :: ByteString -> Sha256State -> Sha256State
sha256state_feed bytes (Sha256State p) =
  unsafePerformIO . unsafeUseAsCStringLen bytes $ \(bp, bl) -> IO $ \st ->
    let !(# st0, a #) = newByteArray# 32# st
        !(# st1, _ #) = unIO (c_sha256_update p bp (fromIntegral bl) a) st0
        !(# st2, b #) = unsafeFreezeByteArray# a st1
     in (# st2, Sha256State b #)

-- | Cast a Sha256Ctx to a Sha256State, without (much, if any) copying.
--   This has the disadvantage that the result will retain at least 8, and up to
--   71 unnecessary bytes, depending on the length of the buffer.  72 extra bytes
--   will likely be possible once this binding supports mutable contexts and
--   supports freezing mutable contexts into immutable contexts without copying.

sha256state_fromCtxInplace :: Sha256Ctx -> Sha256State
sha256state_fromCtxInplace (Sha256Ctx a) = Sha256State a

-- | Cast a Sha256Ctx to a Sha256State. This copies the first 32 bytes of the
--   Sha256Ctx structure, so the result is always as small as possible.

sha256state_fromCtx :: Sha256Ctx -> Sha256State
sha256state_fromCtx (Sha256Ctx ctx) =
  unsafePerformIO . IO $ \st ->
    let !(# st0, a #) = newByteArray# 32# st
        st1 = copyByteArray# ctx 0# a 0# 32# st0
        !(# st2, b #) = unsafeFreezeByteArray# a st1
     in (# st2, Sha256State b #)

sha256state_runWith :: Word64 -> ByteString -> Sha256State -> Sha256Ctx
sha256state_runWith blocks bytes (Sha256State p) =
    unsafePerformIO . unsafeUseAsCStringLen bytes $ \(bp, bl) -> IO $ \st ->
      let !(# st0, a #) = newByteArray# ctxLen# st
          !(# st1, () #) = unIO (c_sha256_promote_to_ctx p blocks bp (fromIntegral bl) a) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in (# st2, Sha256Ctx b #)
  where
    !(I# ctxLen#) = 40 + B.length bytes .&. 0x3F

sha256state_encode :: Sha256State -> ShortByteString
sha256state_encode (Sha256State x) =
    unsafePerformIO . IO $ \st ->
      let !(# st0, a #) = newByteArray# 32# st
          !(# st1, () #) = unIO (c_sha256_encode_state x a) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in (# st2, SBS b #)

sha256state_decode :: ShortByteString -> Sha256State
sha256state_decode (SBS x) =
    unsafePerformIO . IO $ \st ->
      let !(# st0, a #) = newByteArray# 32# st
          !(# st1, () #) = unIO (c_sha256_decode_state x a) st0
          !(# st2, b #) = unsafeFreezeByteArray# a st1
       in (# st2, Sha256State b #)

-- these calls must be labelled "unsafe", because the datastructures
-- we will be passing in are unpinned... keep that in mind when selecting
-- the size of the updates.  (Also, maybe in some cases a different FFI
-- layer that uses safe calls would be desirable?  Maybe not... It seems like
-- it should be possible to adequately work around the limitations of
-- long-lived unsafe calls by using smaller updates, making more calls to C.)

-- See the documentation for details:
-- https://ghc.gitlab.haskell.org/ghc/doc/users_guide/exts/ffi.html#guaranteed-call-safety

-- TODO: some functions have more than one binding, mostly for type reasons, and there
-- are several more variants of some of these bindings this module should support.

foreign import ccall unsafe "hs_sha256.h &hs_sha256_init"
    c_sha256_init :: Ptr Word32

foreign import capi unsafe "hs_sha256.h hs_sha256_init_ctx"
    c_sha256_init_ctx :: Sha256MutableCtx# RealWorld -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_promote_to_ctx"
  c_sha256_promote_to_ctx
    :: Sha256State# -- ^ @state@, a pointer to an constant array of eight Word32
    -> Word64 -- ^ @blockCount@, the number of blocks that a sha256 context has processed
    -> CString -- ^ pointer to the constant data to process
    -> CSize -- ^ length of the data to process
    -> Sha256MutableCtx# RealWorld -- ^ output pointer
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_update"
  c_sha256_update
    :: Sha256State# -- ^ @state@, a pointer to an constant array of eight Word32
    -> CString -- ^ pointer to the constant data to process
    -> CSize -- ^ length of the data to process
    -> Sha256MutableState# RealWorld -- ^ output pointer
    -> IO Word64 -- ^ the new @count@

foreign import capi unsafe "hs_sha256.h hs_sha256_update_ctx"
  c_sha256_update_ctx
    :: Sha256Ctx# -- ^ @ctx@, a pointer to a constant sha256 context
    -> CString -- ^ pointer to the constant data to process
    -> CSize -- ^ length of the data to process
    -> Sha256MutableCtx# RealWorld -- ^ output pointer
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_update_ctx"
  c_sha256_mutate_ctx
    :: Sha256MutableCtx# RealWorld -- ^ @ctx@, a pointer to a constant sha256 context
    -> CString -- ^ pointer to the constant data to process
    -> CSize -- ^ length of the data to process
    -> Sha256MutableCtx# RealWorld -- ^ output pointer, can be same as the input context
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_get_count"
  c_sha256_get_count
    :: Sha256State#
    -> Word64

foreign import capi unsafe "hs_sha256.h hs_sha256_finalize_ctx_bits"
  c_sha256_finalize_ctx_bits
    :: Sha256Ctx#
    -> CString
    -> Word64
    -> Ptr Word8
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_finalize_ctx_bits"
  c_sha256_finalize_ctx_bits_ba
    :: Sha256Ctx#
    -> CString
    -> Word64
    -> MutableByteArray# RealWorld
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_finalize_ctx_bits"
  c_sha256_finalize_mutable_ctx_bits
    :: Sha256MutableCtx# RealWorld
    -> CString
    -> Word64
    -> CString
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_encode_state"
  c_sha256_encode_state
    :: Sha256State#
    -> MutableByteArray# RealWorld
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_decode_state"
  c_sha256_decode_state
    :: ByteArray#
    -> Sha256MutableState# RealWorld
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_const_memcmp"
  c_const_memcmp
    :: ByteArray#
    -> ByteArray#
    -> CSize
    -> CInt

foreign import capi unsafe "hs_sha256.h hs_sha256_const_memcmp_uint32be"
  c_const_memcmp_uint32be
    :: ByteArray#
    -> ByteArray#
    -> Word32
    -> CInt

foreign import capi unsafe "hs_sha256.h hs_sha256_const_memcmp_ctx"
  c_const_memcmp_ctx
    :: ByteArray#
    -> ByteArray#
    -> CInt
