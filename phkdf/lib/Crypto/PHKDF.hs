{-# LANGUAGE OverloadedStrings, BangPatterns, ScopedTypeVariables #-}

-------------------------------------------------------------------------------
-- |
-- Module:      Crypto.PHKDF
-- Copyright:   (c) 2024 Auth Global
-- License:     Apache2
--
-------------------------------------------------------------------------------

{- |

This module provides an interface to Version 2 of PHKDF, especially the
following function:

@
phkdfStream :: BitString -> [BitString] -> Word32 -> BitString -> Stream ByteString
phkdfStream key args counter tag = [output0, output1 ..]
  where
    output0 = hmac key (encode args ++ encode  counter      ++ tag)
    output1 = hmac key (output0     ++ encode (counter + 1) ++ tag)
    output2 = hmac key (output1     ++ encode (counter + 2) ++ tag)
    ...
@

This hash function exhibits a misleading resemblance to HKDF, with the @key@
corresponding to HKDF's @salt@, the @msgs@ parameter corresponding to HKDF's
@ikm@ (initial keying material), and the @counter@ and @tag@ parameters
corresponding to HKDF's info parameter.

@
hkdf :: BitString -> BitString -> ByteString -> [ByteString]
hkdf salt ikm info = [output1, output2 .. output255]
  where
    key = hmac salt ikm
    output1 = hmac key            (info ++ encodeWord8 1)
    output2 = hmac key (output1 ++ info ++ encodeWord8 2)
    output3 = hmac key (output2 ++ info ++ encodeWord8 3)
    ...
@

However this is a false cognate. The first thing to notice about @phkdfStream@
is that it doesn't matter how secure the @args@ parameter is, if you use a
publicly known key, counter, and tag, then revealing a full output block reveals
the remainder of the output stream.

This is in contrast to @hkdf@, which allows secret initial keying material and
publicly-known salt and info parameters to be expanded into a large number of
output blocks. These blocks can be divvied up into non-overlapping pieces that
may be revealed independently of each other.

Thus @phkdfStream@ is actually a much lower-level hash function than @hkdf@. As
such has it's own /modes of operation/, which provide various different answers
for this issue of output stream predictability. Building a proper replacement
for @hkdf@ requires combining two or more calls to @phkdfStream@ in different
modes of operation.

The first and simplest mode of operation for @phkdfStream@ is to simply discard
all but the first output block. In this case, @phkdfStream@ simplifies to a call
to HMAC with the addition of TupleHash style encoding, and custom end-of-message
padding determined by the counter and tag. Thus we can use this mode to
implement the key extraction portion of an HKDF-like hash function.

In this mode of operation, we can safely use @phkdfStream@ with secret initial
keying materials and optionally non-secret salt, counter, and tag, and possibly
even reveal the output.  After all it doesn't matter if anybody can predict the
remainder of the stream if it's never been granted any meaning.

The second mode of operation is to use @phkdfStream@ with a secret key,
non-secret arguments, and optionally secret counter and tag.  In this mode, we
can reveal arbitrary non-overlapping portions of the output stream to third
parties, without worry that one portion can be derived from another.

Thus we can implement a variant of the HKDF construction using these two modes
of operation in conjunction with each other:

@
hkdfSimple :: BitString -> [BitString] -> BitString -> Stream ByteString
hkdfSimple salt ikms tag = out
  where
    key = head $ phkdfStream salt ikms inCtr tag
    out = phkdfStream key echoArgs outCtr tag

    echoArgs = ["hkdf-simple"]
    inCtr    = word32 "IN\x00\x00"
    outCtr   = word32 "OUT\x00"
@

If the recommendations of NIST SP 800-108 are to be followed strictly, one
shouldn't examine more than 2^32 output blocks which is about 137.4 GB of
output from @hkdfSimple@. I don't think this will be a problem in practice,
as this particular CSPRNG is not overly well suited to generating large amounts
of pseudorandom data.

However, we must be aware of the /echo args gotcha/: for reasons intimately
related to the predictability of @phkdfStream@ with a non-secret key, counter,
and tag, the @echoArgs@ parameter must not include any important new secrets.

This time we are deriving a secret key using initial keying material. However,
if that material is potentially guessable, then introducing a high-entropy
secret in the @echoArgs@ parameter will secure the first output block, but
revealing two output blocks would re-reveal the ability to guess the original
keying material.

Thus all secrets should be included in the derivation of the key, or possibly
included in the tag parameter. A secret counter can also help, but cannot
provide a sufficient level of entropy tmo secure the output all by itself.

One of HKDF's design principles was to obtain a clean seperation between the
extraction and expansion phases.  This seperation allows HKDF's design to avoid
the /echo args gotcha/ by specifying that the echo args is the empty string.

In a literal, low-level sense, @phkdfStream@ intentionally violates this
seperation. In a metaphorical, higher-level sense, @phkdf@ affirms this design
principle, rather @phkdf@'s' goal is to allow a single primitive to serve both
roles. This unification makes it easy to create cryptographic hash protocols
where every call to HMAC is covered by a directly self-documenting plaintext tag.

Moreover, the alternative to PBKDF2 is phkdf's slow extraction function, which
makes crucial use of the /echo args gotcha/.  This brings us to the third mode
of operation, which keeps the output stream secret, except possibly for the very
last output block examined.

Each mode of operation provides an answer to the predictability of @phkdfStream@.
Our first answer is to make it irrelevant that the output stream is predictable.
Our second answer achieves unpredictability by using a key, counter, and/or tag
that is secret. The third answer achieves unpredictability by keeping the output
stream secret, allowing a publicly-known key, counter, and tag to be used as
self-documenting domain seperation constants.

Thus phkdf's slow extraction function calls @phkdfStream@ to generate a stream
that is allowed to be predictable, but at an unpredictable starting point. This
predictable stream remains secret, and is immediately consumed by a second call
to @phkdfStream@. After @rounds + 1@ blocks have been produced and consumed, the
second call to @phkdfStream@ has an opportunity to add some additional
post-key-stretching tweaks before the output stream is finalized.

Conceptually, the slow extraction function looks like this:

@
phkdfSlowExtract ::
    BitString -> [BitString] -> Word32 -> BitString ->
    ByteString -> Word32 -> [BitString] -> Stream ByteString
phkdfSlowExtract key args counter tag fnName rounds tweaks = out
  where
    blocks = take (rounds + 1) $ phkdfStream key args counter tag
    header = [makePadding fnName rounds, makeLongString tag blocks]
    out = phkdfStream key (header ++ tweaks) (counter + rounds + 1) tag
@

Compared to PBKDF2, @phkdfSlowExtract@ uses essentially the same stream
generator, but enhanced with counters and contextual parameters.  PBKDF2 proper
then condenses that stream by xor-ing all the output blocks together.
@phkdfSlowExtract@ condenses it's internal stream by feeding it to another call
to HMAC. So @phkdfSlowExtract@ is very likely at least as strong as PBKDF2.

Again, assuming key, counter, rounds, and tag are all publicly known, which is
the primary intended use case of this function, then the output stream is
predictable. Thus the output of @phkdfSlowExtract@ must itself be subjected to
the first or third mode of operation.

If more than 32 bytes ever need to be revealed, then another call to
@phkdfStream@ with a secret key in the second mode of operation is required
for final output expansion. We do just this in our next example.

@phkdfVerySimple@ uses our flavor of not-quite-PBKDF2 to produce a pseudorandom
key to use with our flavor of not-quite-HKDF for final output expansion. Thus
the algorithm behind this construction is a portmanteau of the algorithms behind
PBKDF2 and HKDF. Thus the name.

@
phkdfVerySimple ::
    BitString -> BitString -> BitString -> BitString ->
    Word32 -> Stream ByteString
phkdfVerySimple seguid tag username password rounds = out
  where
    inArgs = [myLabel, username, password, encode rounds]

    key = head $ phkdfSlowExtract seguid inArgs inCtr tag myLabel rounds []

    out = phkdfStream key [myLabel] outCtr tag

    myLabel = "phkdf-very-simple"
    inCtr   = word32 "IN\x00\x00"
    outCtr  = word32 "OUT\x00"
@

@phkdfVerySimple@ is a distillation of the core features of the @phkdfSimple@
function exported from the @Crypto.PHKDF@ module, containing the most salient
features of that more fully worked construction.

Not only does @phkdfVerySimple@ provide key stretching very similar in flavor
to PBKDF2, but it also infuses the entire key-stretching process with
cryptoacoustic repetitions of the plaintext of the tag. This amplifies the
minimum obfuscation overhead associated with any tag obscuration attack that is
truly secure against the best reverse engineers. This in turns reduces the
minimum obfuscation overhead associated with a single application of SHA256
in order for the overall construction to be cryptoacoustically viable.

@phkdfVerySimple@ encodes the number of rounds to be performed in the
key-stretching phase in order to ensure that changing the number of rounds
requires a full key-stretching recomputation. This is necessary because it is
possible to share portions of @phkdfSlowExtract@'s key-stretching computation
when the @rounds@ parameter is varied while holding the input arguments
constant. Including an encoding of the @rounds@ parameter in the input arguments
forces both to be varied, thus forcing a full recomputation.
-}

module Crypto.PHKDF
  ( HmacKey()
  , hmacKey
  , PhkdfCtx()
  , phkdfCtx
  , phkdfCtx_init
  , phkdfCtx_initHashed
  , phkdfCtx_initPrefixed
  , phkdfCtx_initLike
  , phkdfCtx_hmacKeyPlain
  , phkdfCtx_hmacKeyHashed
  , phkdfCtx_hmacKeyPrefixed
  , phkdfCtx_hmacKey
  , phkdfCtx_hmacKeyLike
  , phkdfCtx_toResetHmacCtx
  , phkdfCtx_reset
  , phkdfCtx_feedArg
  , phkdfCtx_feedArgs
  , phkdfCtx_feedArgsBy
  , phkdfCtx_feedArgConcat
  , phkdfCtx_finalize
  , phkdfCtx_finalizeHmac
  , phkdfCtx_toHmacCtx
  , phkdfCtx_toHmacKeyPrefixed
  , phkdfCtx_toStream
  , phkdfCtx_toGen
  , phkdfCtx_byteCount
  , phkdfCtx_blockCount
  , phkdfCtx_bufferLength
  , phkdfCtx_endPaddingLength
  , phkdfCtx_blockPaddingLength
{--
--- FIXME: add an updated xor-based SlowCtx, closer to PBKDF2
  , PhkdfSlowCtx()
  , phkdfSlowCtx_extract
  , phkdfSlowCtx_feedArg
  , phkdfSlowCtx_feedArgs
  , phkdfSlowCtx_finalize
  , phkdfSlowCtx_toStream
--}
  , PhkdfGen()
  , phkdfGen
  , phkdfGen_init
  , phkdfGen_initHashed
  , phkdfGen_initPrefixed
  , phkdfGen_initLike
  , phkdfGen_hmacKeyPlain
  , phkdfGen_hmacKeyHashed
  , phkdfGen_hmacKeyPrefixed
  , phkdfGen_hmacKey
  , phkdfGen_hmacKeyLike
  , phkdfGen_head
  , phkdfGen_read
  , phkdfGen_peek
  , phkdfGen_toStream
  ) where

import           Control.Arrow((>>>))
import           Data.Bits((.&.), complement)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Function((&))
import           Data.Foldable(Foldable, foldl')
import           Data.Word
import           Data.Stream (Stream(..))
import qualified Data.Stream as Stream
import           Network.ByteOrder (bytestring32)

import           Crypto.Sha256 as Sha256
import           Crypto.PHKDF.HMAC
import           Crypto.PHKDF.HMAC.Subtle
import           Crypto.PHKDF.Subtle
import           Crypto.Encoding.PHKDF
import           Crypto.Encoding.SHA3.TupleHash

import           Control.Exception(assert)

-- | initialize an empty @phkdfStream@ context from a plaintext HMAC key.

phkdfCtx :: ByteString -> PhkdfCtx
phkdfCtx = phkdfCtx_init . hmacKey

-- | initialize an empty @phkdfStream@ context from a plaintext or precomputed HMAC key.

phkdfCtx_init :: HmacKey -> PhkdfCtx
phkdfCtx_init = phkdfCtx_initLike . hmacKeyLike_init

-- | initialize an empty @phkdfStream@ context from a plaintext, precomputed, or buffer-prefixed HMAC key.

phkdfCtx_initLike :: HmacKeyLike -> PhkdfCtx
phkdfCtx_initLike key =
  PhkdfCtx {
    phkdfCtx_state = hmacKeyLike_ipadCtx key,
    phkdfCtx_hmacKeyLike = key
  }

-- | initialize an empty @phkdfStream@ context from a precomputed HMAC key.

phkdfCtx_initHashed :: HmacKeyHashed -> PhkdfCtx
phkdfCtx_initHashed = phkdfCtx_init . hmacKeyHashed_toKey

-- | initialize an empty @phkdfStream@ context from a buffer-prefixed HMAC key.

phkdfCtx_initPrefixed :: ByteString -> HmacKeyPrefixed -> PhkdfCtx
phkdfCtx_initPrefixed str key = PhkdfCtx
    { phkdfCtx_state = sha256_update (hmacKeyPrefixed_ipadCtx key) str
    , phkdfCtx_hmacKeyLike = hmacKeyLike_initPrefixed key
    }

-- | Retrieve the HmacKeyPlain that the phkdfCtx was originally
--   initialized with, if possible

phkdfCtx_hmacKeyPlain :: PhkdfCtx -> Maybe HmacKeyPlain
phkdfCtx_hmacKeyPlain = hmacKeyLike_toPlain . phkdfCtx_hmacKeyLike

-- | Retrieve the HmacKeyHashed that the phkdfCtx was originally
--   initialized with, if possible

phkdfCtx_hmacKeyHashed :: PhkdfCtx -> Maybe HmacKeyHashed
phkdfCtx_hmacKeyHashed = hmacKeyLike_toHashed . phkdfCtx_hmacKeyLike

-- | Retrieve the HmacKeyPrefixed that the phkdfCtx was originally
--   initialized with.

phkdfCtx_hmacKeyPrefixed  :: PhkdfCtx -> HmacKeyPrefixed
phkdfCtx_hmacKeyPrefixed = hmacKeyLike_toPrefixed . phkdfCtx_hmacKeyLike

-- | Retrieve the HmacKey that the phkdfCtx was originally
--   initialized with, if possible.

phkdfCtx_hmacKey :: PhkdfCtx -> Maybe HmacKey
phkdfCtx_hmacKey = hmacKeyLike_toKey . phkdfCtx_hmacKeyLike

-- | initialize a new empty @phkdfStream@ context from the HMAC key
--   originally supplied to the context, discarding all arguments already added.

phkdfCtx_reset :: PhkdfCtx -> PhkdfCtx
phkdfCtx_reset = phkdfCtx_initLike . phkdfCtx_hmacKeyLike

-- | initialize a new empty HMAC context from the key originally supplied to
--   the PHKDF context, discarding all arguments already added.

phkdfCtx_toResetHmacCtx :: PhkdfCtx -> HmacCtx
phkdfCtx_toResetHmacCtx = hmacKeyLike_run . phkdfCtx_hmacKeyLike

-- FIXME? what should happen when the SHA256 counters overflow?
--        (As SHA-256 can handle 2.3e6 TB, this isn't a pressing issue.)

-- | append a single string onto the end of @phkdfStream@'s list of
--   arguments.

phkdfCtx_feedArg :: ByteString -> PhkdfCtx -> PhkdfCtx
phkdfCtx_feedArg str = phkdfCtx_unsafeFeed [len, str]
  where
    len = leftEncodeFromBytes (B.length str)
-- | append zero or more strings onto the end of @phkdfStream@'s list of
--   arguments.

phkdfCtx_feedArgs :: Foldable f => f ByteString -> PhkdfCtx -> PhkdfCtx
phkdfCtx_feedArgs params ctx = foldl' (flip phkdfCtx_feedArg) ctx params

phkdfCtx_feedArgsBy :: Foldable f => (a -> ByteString) -> f a -> PhkdfCtx -> PhkdfCtx
phkdfCtx_feedArgsBy f params ctx0 = foldl' delta ctx0 params
  where delta ctx a = phkdfCtx_feedArg (f a) ctx

phkdfCtx_feedArgConcat :: Foldable f => f ByteString -> PhkdfCtx -> PhkdfCtx
phkdfCtx_feedArgConcat strs =
    phkdfCtx_unsafeFeed [len] >>>
    phkdfCtx_unsafeFeed strs
  where
    len = leftEncodeFromBytes (foldl' delta 0 strs)
    delta tot str = tot + B.length str

-- | close out a @phkdfStream@ context using the first mode of operation,
--   examining only the first output block and discarding the rest of the
--   stream.

phkdfCtx_finalize
  :: (Int -> ByteString) -- ^ end-of-message padding, output length must be equal to the number provided
  -> Word32 -- ^ counter
  -> ByteString -- ^ tag
  -> PhkdfCtx
  -> ByteString
phkdfCtx_finalize genFillerPad counter tag ctx =
    phkdfCtx_toGen genFillerPad counter tag ctx &
    phkdfGen_head

-- | Turn a 'PhkdfCtx' into a incomplete call to @hmac@, with the option of
--   adding additional data to the end of the message that need not be
--   TupleHash encoded.

phkdfCtx_toHmacCtx :: PhkdfCtx -> HmacCtx
phkdfCtx_toHmacCtx ctx =
  (phkdfCtx_toResetHmacCtx ctx) {
    hmacCtx_ipadCtx = phkdfCtx_state ctx
  }

-- | Turn a 'PhkdfCtx' into a 'HmacKeyPrefixed' by adding a null byte followed
--   by 0-63 bytes as needed to get to a SHA256 block boundary

phkdfCtx_toHmacKeyPrefixed
  :: (Int -> ByteString) -- ^ block synchronization padding, ouput length must be equal to the number provided
  -> PhkdfCtx
  -> HmacKeyPrefixed
phkdfCtx_toHmacKeyPrefixed genFillerPad ctx =
  HmacKeyPrefixed
  { hmacKeyPrefixed_ipadCtx = ipadCtx'
  , hmacKeyPrefixed_opad = hmacKeyLike_opad (phkdfCtx_hmacKeyLike ctx)
  }
  where
    blockPadLen = phkdfCtx_blockPaddingLength ctx

    blockPadding = genFillerPad blockPadLen

    ctx' = phkdfCtx_unsafeFeed ["\x00",blockPadding] ctx

    paddingIsValid = phkdfCtx_bufferLength ctx' == 0
                  && B.length blockPadding == blockPadLen

    ipadCtx' = assert paddingIsValid $ phkdfCtx_state ctx'

-- | "improperly" close out a 'PhkdfCtx' as if it were a call to @hmac@ instead
--   of @phkdfStream@, though with a TupleHash message encoding.

phkdfCtx_finalizeHmac :: PhkdfCtx -> ByteString
phkdfCtx_finalizeHmac = hmacCtx_finalize_toByteString . phkdfCtx_toHmacCtx

-- | close out a @phkdfStream@ context with a given counter and tag

phkdfCtx_toStream :: (Int -> ByteString) -> Word32 -> ByteString -> PhkdfCtx -> Stream ByteString
phkdfCtx_toStream genFillerPad counter0 tag ctx =
  phkdfCtx_toGen genFillerPad counter0 tag ctx &
  phkdfGen_toStream

-- | How long would the end padding be if the PhkdfCtx was finalized?

phkdfCtx_endPaddingLength :: PhkdfCtx -> Int
phkdfCtx_endPaddingLength ctx =
  fromIntegral ((31 - phkdfCtx_byteCount ctx) .&. 63)

-- | How long would the block padding be if 'phkdfCtx_toHmacKeyPrefixed' is
--   called?

phkdfCtx_blockPaddingLength :: PhkdfCtx -> Int
phkdfCtx_blockPaddingLength ctx =
  fromIntegral ((63 - phkdfCtx_byteCount ctx) .&. 63)

-- | How many bytes long is the current phkdf message? This doesn't count the
--   very first block of the SHA256 message, which is dedicated to the HMAC key.
--   Thus it is always 64 bytes less than what 'sha256_byteCount' would report.

phkdfCtx_byteCount :: PhkdfCtx -> Word64
phkdfCtx_byteCount = (\x -> x - 64) . sha256_byteCount . phkdfCtx_state

-- | How many complete blocks have been processed in the current phkdf message?
--   This doesn't count the very first block of the SHA256 message, which is
--   dedicated to the HMAC key.  Thus it is always one less than what
--   'sha256_blockCount' would report

phkdfCtx_blockCount :: PhkdfCtx -> Word64
phkdfCtx_blockCount = (\x -> x - 1) . sha256_blockCount . phkdfCtx_state

-- | How long is the buffer of unprocessed data?  Always returns a number
--   between 0 and 63, inclusive, and returns the same number that
--   'sha256_bufferLength' would report.

phkdfCtx_bufferLength :: PhkdfCtx -> Word8
phkdfCtx_bufferLength = sha256_bufferLength . phkdfCtx_state

-- actually I should probably offer a version of this function with permuted
-- arguments, as there is at least one potentially useful partial application
-- here, namely the block computations involved in processing the
-- end-of-message padding. This partial application requires that PhkdfCtx
-- and genFillerPad must come first.

phkdfCtx_toGen
  :: (Int -> ByteString) -- ^ end-of-message padding, output length must be equal to the number provided
  -> Word32  -- ^ counter
  -> ByteString -- ^ tag
  -> PhkdfCtx
  -> PhkdfGen
phkdfCtx_toGen genFillerPad counter0 tag ctx =
    PhkdfGen
      { phkdfGen_hmacKeyLike = phkdfCtx_hmacKeyLike ctx
      , phkdfGen_extTag = extendTag tag
      , phkdfGen_counter = counter0
      , phkdfGen_state = ""
      , phkdfGen_initCtx = Just context0
      }
  where
    endPadLen = phkdfCtx_endPaddingLength ctx

    endPadding = genFillerPad endPadLen

    ctx' = phkdfCtx_unsafeFeed ["\x00",endPadding] ctx

    endPaddingIsValid = phkdfCtx_bufferLength ctx' == 32
                     && B.length endPadding == endPadLen

    context0 = assert endPaddingIsValid $ phkdfCtx_state ctx'

phkdfGen :: ByteString -> ByteString -> Word32 -> ByteString -> PhkdfGen
phkdfGen = phkdfGen_init . hmacKey

phkdfGen_init :: HmacKey -> ByteString -> Word32 -> ByteString -> PhkdfGen
phkdfGen_init = phkdfGen_initLike . hmacKeyLike_init

phkdfGen_initLike :: HmacKeyLike -> ByteString -> Word32 -> ByteString -> PhkdfGen
phkdfGen_initLike key initBytes = initGen
  where
    -- Round down to the previous buffer boundary
    n = B.length initBytes .&. complement 63
    (blocks, state0) = B.splitAt n initBytes
    ipad0 = sha256_update (hmacKeyLike_ipadCtx key) blocks

    initGen counter0 tag = PhkdfGen
      { phkdfGen_hmacKeyLike = key
      , phkdfGen_extTag = extendTag tag
      , phkdfGen_counter = counter0
      , phkdfGen_state = state0
      , phkdfGen_initCtx = Just ipad0
      }

phkdfGen_initHashed :: HmacKeyHashed -> ByteString -> Word32 -> ByteString -> PhkdfGen
phkdfGen_initHashed = phkdfGen_initLike . hmacKeyLike_initHashed

phkdfGen_initPrefixed :: HmacKeyPrefixed -> ByteString -> Word32 -> ByteString -> PhkdfGen
phkdfGen_initPrefixed = phkdfGen_initLike . hmacKeyLike_initPrefixed

phkdfGen_hmacKeyPlain :: PhkdfGen -> Maybe HmacKeyPlain
phkdfGen_hmacKeyPlain = hmacKeyLike_toPlain . phkdfGen_hmacKeyLike

phkdfGen_hmacKeyHashed :: PhkdfGen -> Maybe HmacKeyHashed
phkdfGen_hmacKeyHashed = hmacKeyLike_toHashed . phkdfGen_hmacKeyLike

phkdfGen_hmacKeyPrefixed :: PhkdfGen -> HmacKeyPrefixed
phkdfGen_hmacKeyPrefixed = hmacKeyLike_toPrefixed . phkdfGen_hmacKeyLike

phkdfGen_hmacKey :: PhkdfGen -> Maybe HmacKey
phkdfGen_hmacKey = hmacKeyLike_toKey . phkdfGen_hmacKeyLike

phkdfGen_peek :: PhkdfGen -> Maybe ByteString
phkdfGen_peek gen =
  case phkdfGen_initCtx gen of
    Nothing -> Just $ phkdfGen_state gen
    Just _  -> Nothing

phkdfGen_toHmacCtx :: PhkdfGen -> HmacCtx
phkdfGen_toHmacCtx gen =
  (hmacKeyLike_run (phkdfGen_hmacKeyLike gen)) {
     hmacCtx_ipadCtx = sha256_update ipad (phkdfGen_state gen)
    }
  where
    ipad =
      case phkdfGen_initCtx gen of
        Nothing -> hmacCtx_ipadCtx . hmacKeyLike_run $ phkdfGen_hmacKeyLike gen
        Just x -> x

phkdfGen_head :: PhkdfGen -> ByteString
phkdfGen_head gen =
  if B.length (phkdfGen_extTag gen) <= 19 then
    phkdfGen_toHmacCtx gen &
    hmacCtx_feeds [ bytestring32 (phkdfGen_counter gen)
                  , phkdfGen_extTag gen
                  ] &
    hmacCtx_finalize_toByteString
  else
    phkdfGen_toHmacCtx gen &
    hmacCtx_feeds [ bytestring32 (phkdfGen_counter gen)
                  , B.init (phkdfGen_extTag gen)
                  ] &
    hmacCtx_finalizeBits_toByteString (B.singleton (B.last (phkdfGen_extTag gen))) 7


phkdfGen_read :: PhkdfGen -> (ByteString, PhkdfGen)
phkdfGen_read gen = (state', gen')
  where
    state' = phkdfGen_head gen

    gen' = PhkdfGen
      { phkdfGen_hmacKeyLike = phkdfGen_hmacKeyLike gen
      , phkdfGen_initCtx = Nothing
      , phkdfGen_state = state'
      , phkdfGen_counter = phkdfGen_counter gen + 1
      , phkdfGen_extTag = phkdfGen_extTag gen
      }

phkdfGen_toStream :: PhkdfGen -> Stream ByteString
phkdfGen_toStream = Stream.unfold phkdfGen_read
