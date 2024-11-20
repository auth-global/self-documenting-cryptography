{-# LANGUAGE MagicHash, UnboxedTuples, CApiFFI, UnliftedFFITypes #-}

module Crypto.Sha256.Subtle where

import Data.Bits((.&.), shiftR)
import Data.ByteString(ByteString)
import Data.Word
import qualified Data.ByteString as B
import Data.ByteString.Unsafe(unsafeUseAsCString, unsafeUseAsCStringLen)
import Foreign.C
import Foreign.Ptr
import GHC.Exts
import GHC.Prim(RealWorld)
import GHC.IO
import System.IO.Unsafe

type Sha256MutStatePtr# = MutableByteArray#

type Sha256StatePtr# = ByteArray#

type Sha256MutCtxPtr# = MutableByteArray#

type Sha256CtxPtr# = ByteArray#

data Sha256State = Sha256State# { unSha256State# :: Sha256StatePtr# }

instance Eq Sha256State where
  x == y = compare x y == EQ

instance Ord Sha256State where
  compare (Sha256State# x) (Sha256State# y) =
    compare (c_const_memcmp_uint32be x y 8) 0

data Sha256Ctx = Sha256Ctx# { unSha256Ctx# :: Sha256CtxPtr# }

instance Eq Sha256Ctx where
  x == y = compare x y == EQ

instance Ord Sha256Ctx where
  compare (Sha256Ctx# x) (Sha256Ctx# y) =
    compare (c_const_memcmp_ctx x y) 0

data Sha256MutCtx a = Sha256MutCtx# { unSha256MutCtx# :: Sha256MutCtxPtr# a }

sha256state_init :: Sha256State
sha256state_init =
  unsafePerformIO . IO $ \st ->
    let (Ptr addr) = c_sha256_init
        (# st0, a #) = newByteArray# 32# st
        st1 = copyAddrToByteArray# addr a 0# 32# st0
        -- FIXME?  Review this to ensure that 32# is the correct input above
        -- Problem is the documentation is ambiguous, and the source is magic.
        -- I'm assuming copyAddrToByteArray# works similarly as copyByteArray#.
        (# st2, b #) = unsafeFreezeByteArray# a st1
     in (# st2, Sha256State# b #)

-- | Note that this function only processes as many 64-byte blocks as possible,
--   then discards the remainder of the input.  Also note that this function does
--   nothing to track the number of bytes that have been fed into the state, which
--   will have to be done externally.

sha256state_feed :: ByteString -> Sha256State -> Sha256State
sha256state_feed b (Sha256State# p) =
  unsafePerformIO . unsafeUseAsCStringLen b $ \(bp, bl) -> IO $ \st ->
    let (# st0, a #) = newByteArray# 32# st
        (# st1, _ #) = unIO (c_sha256_update p 0 nullPtr bp (fromIntegral bl) a) st0
        (# st2, b #) = unsafeFreezeByteArray# a st1
     in (# st2, Sha256State# b #)

-- | Cast a Sha256Ctx to a Sha256State, without (much, if any) copying.
--   This has the disadvantage that the result will retain at least 8, and up to
--   71 unnecessary bytes, depending on the length of the buffer.  72 extra bytes
--   will likely be possible once this binding supports mutable contexts and
--   supports freezing mutable contexts into immutable contexts without copying.

sha256state_fromCtxInplace :: Sha256Ctx -> Sha256State
sha256state_fromCtxInplace (Sha256Ctx# a) = Sha256State# a

-- | Cast a Sha256Ctx to a Sha256State, without (much, if any) copying.
--   This copies the first 32 bytes of the Sha256Ctx structure, so the result is always
--   as small as possible.

sha256state_fromCtx :: Sha256Ctx -> Sha256State
sha256state_fromCtx (Sha256Ctx# ctx#) =
  unsafePerformIO . IO $ \st ->
    let (# st0, a #) = newByteArray# 32# st
        st1 = copyByteArray# ctx# 0# a 0# 32# st0
        (# st2, b #) = unsafeFreezeByteArray# a st1
     in (# st2, Sha256State# b #)

sha256state_runWith :: Word64 -> ByteString -> Sha256State -> Sha256Ctx
sha256state_runWith blocks bytes (Sha256State# p) =
    unsafePerformIO . unsafeUseAsCStringLen bytes $ \(bp, bl) -> IO $ \st ->
      let (# st0, a #) = newByteArray# ctxLen# st
          (# st1, () #) = unIO (c_sha256_promote_to_ctx p blocks bp (fromIntegral bl) a) st0
          (# st2, b #) = unsafeFreezeByteArray# a st1
       in (# st2, Sha256Ctx# b #)
  where
    (I# ctxLen#) = 40 + B.length bytes .&. 0x3F

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
    c_sha256_init_ctx :: Sha256MutCtxPtr# RealWorld -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_promote_to_ctx"
  c_sha256_promote_to_ctx
    :: Sha256StatePtr# -- ^ @state@, a pointer to an constant array of eight Word32
    -> Word64 -- ^ @blockCount@, the number of blocks that a sha256 context has processed
    -> CString -- ^ pointer to the constant data to process
    -> CSize -- ^ length of the data to process
    -> Sha256MutCtxPtr# RealWorld -- ^ output pointer
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_update"
  c_sha256_update
    :: Sha256StatePtr# -- ^ @state@, a pointer to an constant array of eight Word32
    -> Word64 -- ^ @count@, the number of bytes that a sha256 context has seen
    -> Ptr Word8 -- ^ @buffer@, a pointer to 0-63 constant bytes representing the unprocessed data seen by the context. The length is encoded by the least six significant bits of @count@.
    -> CString -- ^ pointer to the constant data to process
    -> CSize -- ^ length of the data to process
    -> Sha256MutStatePtr# RealWorld -- ^ output pointer, may be same as input pointer
    -> IO Word64 -- ^ the new @count@

foreign import capi unsafe "hs_sha256.h hs_sha256_update_ctx"
  c_sha256_update_ctx
    :: Sha256CtxPtr# -- ^ @ctx@, a pointer to a constant sha256 context
    -> CString -- ^ pointer to the constant data to process
    -> CSize -- ^ length of the data to process
    -> Sha256MutCtxPtr# RealWorld -- ^ output pointer
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_update_ctx"
  c_sha256_mutate_ctx
    :: Sha256MutCtxPtr# RealWorld -- ^ @ctx@, a pointer to a constant sha256 context
    -> CString -- ^ pointer to the constant data to process
    -> CSize -- ^ length of the data to process
    -> Sha256MutCtxPtr# RealWorld -- ^ output pointer, can be same as the input context
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_encode_state"
  c_sha256_encode_state
    :: Sha256StatePtr#
    -> MutableByteArray# RealWorld
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_encode_state"
  c_sha256_encode_mutable_state
    :: Sha256MutStatePtr# RealWorld
    -> MutableByteArray# RealWorld
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_decode_state"
  c_sha256_decode_state
    :: ByteArray#
    -> Sha256MutStatePtr# RealWorld
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_get_count"
  c_sha256_get_count
    :: Sha256StatePtr#
    -> IO Word64

foreign import capi unsafe "hs_sha256.h hs_sha256_finalize_ctx_bits"
  c_sha256_finalize_ctx_bits
    :: Sha256CtxPtr#
    -> CString
    -> Word64
    -> CString
    -> IO ()

foreign import capi unsafe "hs_sha256.h hs_sha256_finalize_ctx_bits"
  c_sha256_finalize_mutable_ctx_bits
    :: Sha256MutCtxPtr# RealWorld
    -> CString
    -> Word64
    -> CString
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
