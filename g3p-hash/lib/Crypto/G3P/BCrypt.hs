{-# LANGUAGE ViewPatterns, OverloadedStrings, BangPatterns, ScopedTypeVariables #-}

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
  , bcryptXsFree
  ) where

import           Control.Exception(assert)

import           Data.Bits((.&.), complement)
import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import           Data.Function((&))
import           Data.Int
import           Data.Word

import           Network.ByteOrder(word32, bytestring32)

import           Crypto.PHKDF.HMAC (HmacKeyPrefixed, hmacKeyPrefixed_feeds)
import           Crypto.PHKDF.Primitives(phkdfCtx_initPrefixed, phkdfCtx_addArgsBy, phkdfCtx_finalize)

import           Crypto.Encoding.PHKDF (chunkify, chunkifyCycle, takeBs, nullBuffer)
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

formatFnName :: ByteString -> ByteString
formatFnName (B.take 28 -> name) = B.concat [bytestring32 0, name, nameExt]
  where
    nameExt = B.take (28 - B.length name) nullBuffer

bcryptXsFree_tagBytesPerRound :: Int
bcryptXsFree_tagBytesPerRound = 4176

concatTakeBs :: Int -> [ByteString] -> ByteString
concatTakeBs n bs = B.concat (takeBs (fromIntegral n) bs)

bcryptXsFree :: Foldable f => (a -> ByteString) -> ByteString
             -> ByteString -> f a -> ByteString -> Word32
             -> HmacKeyPrefixed -> (Int, HmacKeyPrefixed)
bcryptXsFree toString fnName longTag contextTags domainTag rounds_ = initRound
  where
    rounds :: Int64 = fromIntegral rounds_ + 1
    -- Do 1-128 minirounds in the first superround, so that we end on an
    -- exact multiple of 128
    miniRoundBytes :: Int64 = fromIntegral bcryptXsFree_tagBytesPerRound
    miniRounds0 = 128 - (- rounds) .&. (complement 127)
    -- The number of superrounds after the first
    superRounds0 = (rounds - miniRounds0) `div` 128
    tagBytesFrom = chunkifyCycle 32 longTag

    -- minimum number of half blocks to complete a local commitment to the
    -- entirety of an excessively long extended salt for a single bcrypt round.

    -- The first and last rounds of the superround have their extended salts
    -- committed to as part of deriving the keys in use for that superround.

    -- This turns into cryptoacoustic repetition if the longTag is not
    -- excessively long.

    halfBlocks :: Int = ceiling ((fromIntegral miniRoundBytes :: Float) / 32)

    initRound :: HmacKeyPrefixed -> (Int, HmacKeyPrefixed)
    initRound !sha0 =
      let
        -- Locally ensure that the extended salt for the first and last
        -- rounds have been committed to before deriving the keys.

        -- (This turns into cryptoacoustic repetition if the extended salt
        -- isn't excessively long.)

        lastOffset = (miniRounds0 - 1) * miniRoundBytes

        ltA = take halfBlocks $ tagBytesFrom 0
        ltZ = take halfBlocks $ tagBytesFrom lastOffset

        -- Now actually perform the commitment:
        ("", sha1) = hmacKeyPrefixed_feeds (ltA ++ ltZ) sha0

      in superRound 0 sha1 Nothing rounds_ (fromIntegral miniRounds0) (fromIntegral superRounds0)

    superRound :: Word32 -> HmacKeyPrefixed -> Maybe BCryptState -> Word32 -> Word32 -> Word32 -> (Int, HmacKeyPrefixed)
    superRound tagPos !sha0 mBcrypt0 ctr miniRounds superRounds =
          -- do 1-128 rounds in the first superround, so that we
          -- land on an exact multiple of 128 rounds left to do.
      let
        -- The derivation of the keys for the superround will locally commit
        -- to the first 64 - 190 bytes of the extended salt of the
        -- penultimate miniround.  (The first 40 bytes are P-Box salt)
        penOffset = fromIntegral tagPos + 40 + (fromIntegral miniRounds - 2) * miniRoundBytes
        endPad0 n = concatTakeBs n (tagBytesFrom (penOffset + 64))
        endPad1 n = concatTakeBs n (tagBytesFrom (penOffset + 64 + fromIntegral n))
        key0 = phkdfCtx_initPrefixed (tagBytesFrom penOffset !! 0) sha0 &
               phkdfCtx_addArgsBy toString contextTags &
               phkdfCtx_finalize endPad0 (word32 "KEY0") domainTag
        key1 = phkdfCtx_initPrefixed (tagBytesFrom penOffset !! 1) sha0 &
               phkdfCtx_addArgsBy toString contextTags &
               phkdfCtx_finalize endPad1 (word32 "KEY1") domainTag
        args = BCryptXsCtr
          { bcryptXsCtr_key0 = key0
          , bcryptXsCtr_key1 = key1
          , bcryptXsCtr_tag  = longTag <> "\x00"
          , bcryptXsCtr_name = formatFnName fnName
          }

        (tagPos', bcrypt1) = bcryptXsCtrSuperRound args
                                tagPos (fromIntegral miniRounds) ctr mBcrypt0
        -- Now we need to do the local commitment for the *next* superround,
        -- or end-of-key-stretching finalization.

        -- Here's the next local commitment:
        -- offset of the tag used for the last miniround:

        lastOffset = fromIntegral tagPos' + 127 * miniRoundBytes

        (ltA : ltAs) = take halfBlocks (tagBytesFrom (fromIntegral tagPos'))
        ltZ = take (halfBlocks + 3) (tagBytesFrom lastOffset)

        (pBit, pBox) = B.splitAt 8 (bcryptState_toByteString bcrypt1)

        chunksR = key0 : key1 : orpheanBeholderScryDoubt <> pBit :
                      chunkify 32 pBox ++ [ltA]

        list2 x y = [x,y]

        nextChunks = assert (length ltZ == length chunksR) $
                        concat (zipWith list2 ltZ chunksR) ++ ltAs

        ("",nextSha) = hmacKeyPrefixed_feeds nextChunks sha0

        -- If we are finishing up, we just repeat the most recent tag:

        endOffset = fromIntegral tagPos' - 32 * (fromIntegral halfBlocks + 2)

        endChunksL = take (halfBlocks + 2) (tagBytesFrom endOffset)

        endChunksR = key0 : key1 : orpheanBeholderScryDoubt <> pBit :
                        chunkify 32 pBox

        endChunks = assert (length endChunksL == length endChunksR) $
                       concat (zipWith list2 endChunksL endChunksR)

        ("",endSha) = hmacKeyPrefixed_feeds endChunks sha0

       in if superRounds == 0
          then (fromIntegral tagPos', endSha)
          else superRound tagPos' nextSha (Just bcrypt1)
                          (ctr - miniRounds) 128 (superRounds - 1)
