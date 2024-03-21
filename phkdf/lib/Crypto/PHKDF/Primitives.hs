{-# LANGUAGE OverloadedStrings, BangPatterns, ScopedTypeVariables #-}

{- |

This module provides an interface to the following function.  This simplified
presentation elides the fact that the variable-length padding between the
@args@ parameter and the initial counter depends on the tag itself.

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

module Crypto.PHKDF.Primitives
  ( HmacKey()
  , hmacKey_init
  , PhkdfCtx()
  , phkdfCtx_init
  , phkdfCtx_initFromHmacKey
  , phkdfCtx_hmacKey
  , phkdfCtx_resetCtx
  , phkdfCtx_reset
  , phkdfCtx_addArg
  , phkdfCtx_addArgs
  , phkdfCtx_addArgsBy
  , phkdfCtx_finalize
  , phkdfCtx_finalizeHmac
  , phkdfCtx_finalizeHmacCtx
  , phkdfCtx_finalizeStream
  , phkdfCtx_finalizeGen
  , PhkdfSlowCtx()
  , phkdfSlowCtx_extract
  , phkdfSlowCtx_addArg
  , phkdfSlowCtx_addArgs
  , phkdfSlowCtx_finalize
  , phkdfSlowCtx_finalizeStream
  , PhkdfGen()
  , phkdfGen_initFromHmacKey
  , phkdfGen_read
  , phkdfGen_peek
  , phkdfGen_finalizeStream
  ) where

import           Data.Bits((.&.))
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Function((&))
import           Data.Foldable(Foldable, foldl')
import           Data.Int
import           Data.Word
import           Data.Stream (Stream(..))
import qualified Data.Stream as Stream
import           Network.ByteOrder (bytestring32)

import qualified Crypto.Hash.SHA256 as SHA256
import           Crypto.PHKDF.HMAC
import           Crypto.PHKDF.HMAC.Subtle
import           Crypto.PHKDF.Primitives.Subtle
import           Crypto.Encoding.PHKDF
import           Crypto.Encoding.SHA3.TupleHash

import           Control.Exception(assert)

-- | initialize an empty @phkdfStream@ context from a plaintext HMAC key.

phkdfCtx_init :: ByteString -> PhkdfCtx
phkdfCtx_init = phkdfCtx_initFromHmacKey . hmacKey_init

-- | initialize an empty @phkdfStream@ context from a precomputed HMAC key.

phkdfCtx_initFromHmacKey :: HmacKey -> PhkdfCtx
phkdfCtx_initFromHmacKey key =
  PhkdfCtx {
    phkdfCtx_byteLen = 0,
    phkdfCtx_state   = hmacKey_ipad key,
    phkdfCtx_hmacKey = key
  }

-- | initialize a new empty @phkdfStream@ context from the HMAC key
--   originally supplied to the context, discarding all arguments already added.

phkdfCtx_reset :: PhkdfCtx -> PhkdfCtx
phkdfCtx_reset = phkdfCtx_initFromHmacKey . phkdfCtx_hmacKey


-- | initialize a new empty HMAC context from the key originally supplied to
--   the PHKDF context, discarding all arguments already added.

phkdfCtx_resetCtx :: PhkdfCtx -> HmacCtx
phkdfCtx_resetCtx = hmacKey_run . phkdfCtx_hmacKey

-- FIXME? what should happen when the SHA256 counters overflow?

-- | append a single string onto the end of @phkdfStream@'s list of
--   arguments.

phkdfCtx_addArg :: ByteString -> PhkdfCtx -> PhkdfCtx
phkdfCtx_addArg b ctx = phkdfCtx_unsafeFeed [ leftEncodeFromBytes (B.length b), b ] ctx

-- | append zero or more strings onto the end of @phkdfStream@'s list of
--   arguments.

phkdfCtx_addArgs :: Foldable f => f ByteString -> PhkdfCtx -> PhkdfCtx
phkdfCtx_addArgs params ctx = foldl' (flip phkdfCtx_addArg) ctx params

phkdfCtx_addArgsBy :: Foldable f => (a -> ByteString) -> f a -> PhkdfCtx -> PhkdfCtx
phkdfCtx_addArgsBy f params ctx0 = foldl' delta ctx0 params
  where delta ctx a = phkdfCtx_addArg (f a) ctx


-- | close out a @phkdfStream@ context using the first mode of operation,
--   examining only the first output block and discarding the rest of the
--   stream.

phkdfCtx_finalize :: (Int -> ByteString) -> Word32 -> ByteString -> PhkdfCtx -> ByteString
phkdfCtx_finalize genFillerPad counter tag ctx =
    phkdfCtx_finalizeGen genFillerPad counter tag ctx &
    phkdfGen_read &
    fst

-- | Turn a 'PhkdfCtx' into a incomplete call to @hmac@, with the option of
--   adding additional data to the end of the message that need not be
--   TupleHash encoded.

phkdfCtx_finalizeHmacCtx :: PhkdfCtx -> HmacCtx
phkdfCtx_finalizeHmacCtx ctx =
  (phkdfCtx_resetCtx ctx) {
    hmacCtx_ipad = phkdfCtx_state ctx
  }

-- | "improperly" close out a 'PhkdfCtx' as if it were a call to @hmac@ instead
--   of @phkdfStream@, though with a TupleHash message encoding.

phkdfCtx_finalizeHmac :: PhkdfCtx -> ByteString
phkdfCtx_finalizeHmac = hmacCtx_finalize . phkdfCtx_finalizeHmacCtx

-- | close out a @phkdfStream@ context with a given counter and tag

phkdfCtx_finalizeStream :: (Int -> ByteString) -> Word32 -> ByteString -> PhkdfCtx -> Stream ByteString
phkdfCtx_finalizeStream genFillerPad counter0 tag ctx =
  phkdfCtx_finalizeGen genFillerPad counter0 tag ctx &
  phkdfGen_finalizeStream

phkdfCtx_finalizeGen :: (Int -> ByteString) -> Word32 -> ByteString -> PhkdfCtx -> PhkdfGen
phkdfCtx_finalizeGen genFillerPad counter0 tag ctx =
    PhkdfGen
      { phkdfGen_hmacKey = phkdfCtx_hmacKey ctx
      , phkdfGen_extTag = extendTag tag
      , phkdfGen_counter = counter0
      , phkdfGen_state = ""
      , phkdfGen_initCtx = Just context0
      }
  where
    n = phkdfCtx_byteLen ctx
    endPadLen = fromIntegral ((31 - n) .&. 63)

    endPadding = genFillerPad endPadLen

    ctx' = phkdfCtx_unsafeFeed ["\x00",endPadding] ctx

    endPaddingIsValid = phkdfCtx_byteLen ctx' `mod` 64 == 32
                     && B.length endPadding == endPadLen

    context0 = assert endPaddingIsValid $ phkdfCtx_state ctx'

phkdfGen_initFromHmacKey :: ByteString -> Word32 -> ByteString -> HmacKey -> PhkdfGen
phkdfGen_initFromHmacKey state0 counter0 tag hmacKey = PhkdfGen
    { phkdfGen_hmacKey = hmacKey
    , phkdfGen_extTag = extendTag tag
    , phkdfGen_counter = counter0
    , phkdfGen_state = state0
    , phkdfGen_initCtx = Just $ hmacKey_ipad hmacKey
    }

phkdfGen_peek :: PhkdfGen -> Maybe ByteString
phkdfGen_peek gen =
  case phkdfGen_initCtx gen of
    Nothing -> Just $ phkdfGen_state gen
    Just _  -> Nothing

phkdfGen_finalizeHmacCtx :: PhkdfGen -> HmacCtx
phkdfGen_finalizeHmacCtx gen =
  (hmacKey_run (phkdfGen_hmacKey gen)) {
     hmacCtx_ipad = SHA256.update ipad (phkdfGen_state gen)
    }
  where
    ipad =
      case phkdfGen_initCtx gen of
        Nothing -> hmacCtx_ipad . hmacKey_run $ phkdfGen_hmacKey gen
        Just x -> x

phkdfGen_read :: PhkdfGen -> (ByteString, PhkdfGen)
phkdfGen_read gen = (state', gen')
  where
    state' =
      phkdfGen_finalizeHmacCtx gen &
      hmacCtx_updates [ bytestring32 (phkdfGen_counter gen)
                      , phkdfGen_extTag gen
                      ] &
      hmacCtx_finalize

    hmacKey = phkdfGen_hmacKey gen

    gen' = PhkdfGen
      { phkdfGen_hmacKey = hmacKey
      , phkdfGen_initCtx = Nothing
      , phkdfGen_state = state'
      , phkdfGen_counter = phkdfGen_counter gen + 1
      , phkdfGen_extTag = phkdfGen_extTag gen
      }

phkdfGen_finalizeStream :: PhkdfGen -> Stream ByteString
phkdfGen_finalizeStream = Stream.unfold phkdfGen_read

-- | close out a @phkdfStream@ context with a call to @phkdfSlowExtract@,
--   providing the counter, tag, @fnName@, and number of rounds to compute.
--   Note that @fnName@ is truncated to a length of 25-29 bytes long,
--   depending upon the number of rounds specified. Thus the @fnName@ is
--   primarily intended to be a protocol constant.

phkdfSlowCtx_extract :: (Int -> ByteString) -> Word32 -> ByteString -> ByteString -> Word32 -> PhkdfCtx -> PhkdfSlowCtx
phkdfSlowCtx_extract genFillerPad counter tag fnName rounds ctx0 = out
  where
    (Cons block0 innerStream) = phkdfCtx_finalizeStream genFillerPad counter tag ctx0

    approxByteLen = ((fromIntegral rounds :: Int64) + 1) * 64 + 32
    encodedLengthByteLen = lengthOfLeftEncodeFromBytes approxByteLen
    exactByteLen = approxByteLen - fromIntegral encodedLengthByteLen
    encodedLength = leftEncodeFromBytes exactByteLen
    -- Encoding the length won't ever cause the length of encodedLength
    -- to change, which would cause the loss of buffer alignment.
    -- Fact:
    --      lengthOfLeftEncodeBytes exactByteLen
    --   == lengthOfLeftEncodeBytes approxByteLen
    -- Because:
    --      approxByteLen >= 96
    --   && approxByteLen <= 2^32 * 64 + 32
    --   && approxByteLen `mod` 64 == 32

    extFnNameByteLen = 32 - encodedLengthByteLen

    fnNameByteLen = B.length fnName

    extFnName =
      if fnNameByteLen >= extFnNameByteLen
      then encodedLength <> B.take extFnNameByteLen fnName
      else let padLen = 31 - encodedLengthByteLen - fnNameByteLen
               pad = cycleByteStringWithNull tag padLen
            in B.concat [encodedLength, fnName, "\x00", pad]

    outerCtx =
        phkdfCtx_reset ctx0 &
        phkdfCtx_unsafeFeed [extFnName, block0]

    fillerTag = flip cycleByteString 32 $ B.concat
        [ tag, "\x00", fnName, "\x00"]

    go n !ctx ~(Cons block stream)
      | n <= 0 = PhkdfSlowCtx {
         phkdfSlowCtx_phkdfCtx = phkdfCtx_unsafeFeed [fillerTag] ctx,
         phkdfSlowCtx_counter = counter + rounds + 1,
         phkdfSlowCtx_tag = tag
        }
      | otherwise = go (n-1) (phkdfCtx_unsafeFeed [fillerTag, block] ctx) stream

    out = go rounds outerCtx innerStream

-- | Add a tweak to a call to @phkdfSlowExtract@.

phkdfSlowCtx_addArg :: ByteString -> PhkdfSlowCtx -> PhkdfSlowCtx
phkdfSlowCtx_addArg = phkdfSlowCtx_lift . phkdfCtx_addArg

-- | Add zero or more tweaks to a call to @phkdfSlowExtract@.

phkdfSlowCtx_addArgs :: Foldable f => f ByteString -> PhkdfSlowCtx -> PhkdfSlowCtx
phkdfSlowCtx_addArgs = phkdfSlowCtx_lift . phkdfCtx_addArgs

-- | finalize a call to @phkdfSlowExtract@, discarding all but the first block
--   of the output stream

phkdfSlowCtx_finalize :: (Int -> ByteString) -> PhkdfSlowCtx -> ByteString
phkdfSlowCtx_finalize genFillerPad = Stream.head . phkdfSlowCtx_finalizeStream genFillerPad

-- | finalize a call to @phkdfSlowExtract@

phkdfSlowCtx_finalizeStream :: (Int -> ByteString) -> PhkdfSlowCtx -> Stream ByteString
phkdfSlowCtx_finalizeStream genFillerPad ctx =
    phkdfCtx_finalizeStream genFillerPad
        (phkdfSlowCtx_counter ctx)
        (phkdfSlowCtx_tag ctx)
        (phkdfSlowCtx_phkdfCtx ctx)
