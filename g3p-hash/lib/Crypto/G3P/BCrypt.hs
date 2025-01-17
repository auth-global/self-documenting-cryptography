{-# LANGUAGE ViewPatterns, OverloadedStrings, BangPatterns, ScopedTypeVariables #-}

-------------------------------------------------------------------------------
-- |
-- Module:      Crypto.G3P.BCrypt
-- Copyright:   (c) 2024 Auth Global
-- License:     Apache2
--
--    A very minimal binding to the core of the bcrypt algorithm, adapted from
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
--    Note that this binding doesn't (currently?) support the @2a@ and @2x@
--    variants.  On the other hand, at least the 2a variant depends on
--    overflow, which as undefined behavior in C is allowed to compile to
--    whatever it wants... so there might be multiple variants of the @2a@
--    "variant" of bcrypt floating around out there, depending on particular
--    C implementations and possibly even specific to architectures, compiler
--    flags, and versions
--
-------------------------------------------------------------------------------

module Crypto.G3P.BCrypt
  ( bcrypt
  , bcrypt_saltLength
  , bcrypt_maxPasswordLength
  , bcrypt_formatSaltString
  , bcrypt_parseSaltString
  , bcrypt_outputLength
  , bcryptRaw
  , bcryptRaw_maxInputLength
  , bcryptRaw_outputLength
  , bcryptXsFree
  ) where

import           Control.Exception(assert)

import           Data.Bits((.&.))
import           Data.ByteString(ByteString)
import qualified Data.ByteString as B
import           Data.ByteString.Internal(c2w, w2c)
import qualified Data.Char as Char
import           Data.Function((&))
import           Data.Int
import           Data.Word

import           Network.ByteOrder(word32, bytestring32)

import           Crypto.PHKDF.HMAC (HmacKeyPrefixed, hmacKeyPrefixed_feeds)
import           Crypto.PHKDF (PhkdfCtx, phkdfCtx_initPrefixed, phkdfCtx_feedArgsBy, phkdfCtx_feedArg, phkdfCtx_finalize, phkdfCtx_byteCount, phkdfCtx_endPaddingLength)
import           Crypto.PHKDF.Assert

import           Crypto.Encoding.PHKDF (chunkify, chunkifyCycle, takeBs, nullBuffer)
import           Crypto.G3P.BCrypt.Subtle

-- | OpenBSD-compatible bcrypt

bcrypt :: ByteString -- ^ password
       -> ByteString -- ^ unix-style salt string
       -> Maybe ByteString -- ^ unix-style password hash string
bcrypt key saltString =
  case  bcrypt_parseSaltString saltString of
    Just (_, cost, salt, _) ->
      let hash = bcryptRaw key' salt (2 ^ cost - 1)
       in Just ( B.take 29 saltString <> base64Encode (B.take 23 hash))
    Nothing -> Nothing
  where
    key' =
      case (B.elemIndex 0 (B.take bcrypt_maxPasswordLength key)) of
        Nothing -> key
	Just n -> B.take n key

-- | produce a standard salt string for bcrypt, with or without a password
--   hash.

bcrypt_formatSaltString
   :: Char -- ^ Variant, must be @\'b\'@ for now
   -> Word8 -- ^ Cost factor, must be between 4 and 31 inclusive
   -> ByteString -- ^ Binary salt, must be 16 bytes long
   -> ByteString -- ^ Binary hash, must be 0 or 23 bytes long
   -> Maybe ByteString
bcrypt_formatSaltString variant cost salt hash
  | B.length salt /= 16 = Nothing
  | B.length hash `notElem` [0,23] = Nothing
  | not ( 4 <= cost && cost <= 31 ) = Nothing
  | variant `notElem` ['b'] = Nothing
  | otherwise =
      Just (B.concat [ "$2", B.singleton (c2w variant),
                        "$", x, y, "$",
                        base64Encode salt,
                        base64Encode hash ])
  where
    (toDigit -> x, toDigit -> y) = (cost `divMod` 10)

toDigit :: Word8 -> ByteString
toDigit a = B.singleton (fromIntegral a + c2w '0')

-- | Given a salt string (e.g. "@\$2b\$12\$...@") in the OpenBSD format,
--   returns (variant, work cost, binary salt, binary hash). The only supported
--   variant is currently @\'b\'@. The cost must be between 4 and 31, and the
--   input string must be either 29 or 60 bytes long, depending on whether the
--   salt string includes a password hash.

bcrypt_parseSaltString :: ByteString -> Maybe (Char, Word8, ByteString, ByteString)
bcrypt_parseSaltString salt
  | not (B.length salt `elem` [29, 60]) = Nothing
  | not ("$2" `B.isPrefixOf` salt
         && w2c variant `elem` [ 'b' ]
         && B.index salt 3 == c2w '$' ) = Nothing
  | not (  Char.isDigit (w2c (B.index salt 4))
        && Char.isDigit (w2c (B.index salt 5))
        && B.index salt 6 == c2w '$' ) = Nothing
  | not ( 4 <= cost && cost <= 31 ) = Nothing
  | Just binarySalt <- base64Decode (B.drop 7 (B.take 29 salt))
  , Just binaryHash <- base64Decode (B.drop 29 salt)
    = Just (w2c variant, cost, binarySalt, binaryHash)
  | otherwise = Nothing
  where
    variant = B.index salt 2
    cost = 10 * (B.index salt 4 - c2w '0')
              + (B.index salt 5 - c2w '0')

bcrypt_saltLength :: Int
bcrypt_saltLength = 16

bcrypt_maxPasswordLength :: Int
bcrypt_maxPasswordLength = bcryptXs_maxKeyLength

bcrypt_outputLength :: Int
bcrypt_outputLength = B.length bcrypt_outputSalt

-- | Any input longer than 72 bytes will be truncated.

bcryptRaw_maxInputLength :: Int
bcryptRaw_maxInputLength = bcryptXs_maxKeyLength

-- | Any output hash from 'bcryptRaw' will be exactly 24 bytes long.

bcryptRaw_outputLength :: Int
bcryptRaw_outputLength = B.length bcryptRaw_outputSalt

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

formatFnName :: ByteString -> ByteString
formatFnName (B.take 28 -> name) = B.concat [bytestring32 0, name, nameExt]
  where
    nameExt = B.take (28 - B.length name) nullBuffer

bcryptXsFree_tagBytesPerRound :: Int
bcryptXsFree_tagBytesPerRound = bcryptXsCtr_outputLength - 32

concatTakeBs :: Int -> [ByteString] -> ByteString
concatTakeBs n bs = B.concat (takeBs (fromIntegral n) bs)

bcryptXsFree :: forall f a. Foldable f => (a -> ByteString) -> ByteString
             -> f a -> ByteString -> f a -> ByteString -> Word32
             -> HmacKeyPrefixed -> (Int, HmacKeyPrefixed)
bcryptXsFree toString fnName creds longTag contextTags domainTag ctr0 = initRound
  where
    rounds :: Int64 = fromIntegral ctr0 + 1
    -- Do 1-128 minirounds in the first superround, so that we end on an
    -- exact multiple of 128
    miniRoundBytes :: Int64 = fromIntegral bcryptXsFree_tagBytesPerRound
    miniRounds0 = let x = rounds .&. 127
                   in if x == 0 then 128 else x
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
        ltZ = take (halfBlocks + 4) $ tagBytesFrom lastOffset

        -- Now actually perform the commitment:
        ("", sha1) = hmacKeyPrefixed_feeds (ltA ++ ltZ) sha0

      in superRound 0 sha1 (Just creds) Nothing ctr0 (fromIntegral miniRounds0) (fromIntegral superRounds0)

    superRound :: Word32 -> HmacKeyPrefixed -> Maybe (f a) -> Maybe BCryptState -> Word32 -> Word32 -> Word32 -> (Int, HmacKeyPrefixed)
    superRound tagPos !sha0 mCreds mBcrypt0 ctr miniRounds superRounds =
      let
        -- The derivation of the keys for the superround will locally commit
        -- to the first 96 - 222 bytes of the extended salt of the
        -- penultimate miniround.
        penOffset = fromIntegral tagPos + (fromIntegral miniRounds - 2) * miniRoundBytes
        penBytes  = tagBytesFrom penOffset
        endPad0 n = concatTakeBs n (tagBytesFrom (penOffset + 96))
        endPad1 n = concatTakeBs n (tagBytesFrom (penOffset + 96 + fromIntegral n))
        addCredentials :: f a -> PhkdfCtx -> PhkdfCtx
        addCredentials cs ctx0 = ctx2
          where
            n0 = phkdfCtx_byteCount ctx0 `mod` 64
            n1 = phkdfCtx_byteCount ctx1 `mod` 64
            ctx1 = phkdfCtx_feedArgsBy toString cs ctx0
            ctx2 = phkdfCtx_feedArg credsPad ctx1 &
                   phkdfCtx_assertBufferPosition n0
            -- Length of PHKDF end-of-args padding
            endPadLen = phkdfCtx_endPaddingLength ctx0
            -- Encoded length of credentials vector, mod 64
            credsLen = (n1 - n0) `mod` 64
            -- We want to add 32 - 95 bytes as needed to bring the length
            -- of the encoded credentials vector + padding equivalent to
            -- 0 (mod 64).  Then use endPaddingLen to commit to more extended
            -- salt  (Note that this padding will require 3 bytes to
            -- encode it's length.)
            credsPadLen = 32 + (29 - fromIntegral credsLen) `mod` 64
            -- Now we'll commit to the next 32-95 bytes of the extended salt
            -- on the penultimate miniround:
            credsPadOffset = penOffset + 96 + 2 * fromIntegral endPadLen
            credsPad = B.concat (takeBs credsPadLen (tagBytesFrom credsPadOffset))

        key0 = phkdfCtx_initPrefixed (penBytes !! 0) sha0 &
               phkdfCtx_feedArgsBy toString contextTags &
               maybe id addCredentials mCreds &
               phkdfCtx_finalize endPad0 (word32 "KEY0") domainTag

        ("",sha1) = hmacKeyPrefixed_feeds [penBytes !! 1, key0] sha0

        key1 = phkdfCtx_initPrefixed (penBytes !! 2) sha1 &
               phkdfCtx_feedArgsBy toString contextTags &
               phkdfCtx_finalize endPad1 (word32 "KEY1") domainTag

        args = BCryptXsCtr
          { bcryptXsCtr_key0 = key0
          , bcryptXsCtr_key1 = key1
          , bcryptXsCtr_tag  = longTag
          , bcryptXsCtr_name = formatFnName fnName
          }

        (tagPos', bcrypt1) = bcryptXsCtrSuperRound args
                                tagPos (fromIntegral miniRounds) ctr mBcrypt0

        (pBit, pBox) = B.splitAt 8 (bcryptState_toByteString bcrypt1)

        chunksR = key1 : key0 : orpheanBeholderScryDoubt <> pBit :
                      chunkify 32 pBox

        list2 x y = [x,y]
      in
        if assert (fromIntegral tagPos' == (penOffset + 2*miniRoundBytes) `mod` fromIntegral (B.length longTag + 1)) $
             superRounds > 0
        then let

            -- Now we need to do the local commitment for the *next* superround

            -- The next local commitment needs the offset into the tag used
            -- for the last miniround. There is always 128 minirounds in the
            -- next superround.

            lastOffset = fromIntegral tagPos' + 127 * miniRoundBytes

            ltA = take halfBlocks (tagBytesFrom (fromIntegral tagPos'))
            ltZ = tagBytesFrom lastOffset

            nextChunks = concat (zipWith list2 ltZ chunksR) ++ ltA

            ("",nextSha) = hmacKeyPrefixed_feeds nextChunks sha0
          in
            superRound tagPos' nextSha Nothing (Just bcrypt1)
                       (ctr - miniRounds) 128 (superRounds - 1)
        else let
            -- Now we need to do the end-of-key-stretching finalization.

            -- Repeat the most recent tag:

            endOffset = fromIntegral tagPos' - 32*(fromIntegral (length chunksR))

            endChunksL = tagBytesFrom endOffset

            endChunks = concat (zipWith list2 endChunksL chunksR)

            ("",endSha) = hmacKeyPrefixed_feeds endChunks sha0
          in
            ((,) $! fromIntegral tagPos') $! endSha
