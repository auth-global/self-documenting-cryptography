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
such has it's own modes of operation, which provide various different answers
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
provide a sufficient level of entropy to secure the output all by itself.

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
that is allowed to be predictable, but at an unpredictable starting point.
This stream remains secret, and is immediately consumed by a second call to
@phkdfStream@. After @rounds + 2@ blocks have been produced and consumed, the
second call to @phkdfStream@ has an opportunity to add some additional
post-key-stretching tweaks before the output stream is finalized.

Conceptually, the slow extraction function looks like this:

@
phkdfSlowExtract ::
     BitString -> [BitString] -> Word32 -> BitString
  -> ByteString -> Word32 -> [BitString] -> Stream ByteString
phkdfSlowExtract key args counter tag fnName rounds tweaks = out
  where
    blocks = take (rounds + 2) $ phkdfStream key args counter tag
    header = [makePadding fnName rounds, makeLongString blocks]
    out = phkdfStream key (header ++ tweaks) (counter + rounds + 2) tag
@

Again, assuming key, counter, rounds, and tag are all publicly known, which is
the primary intended use case of this function, then the output stream of this
slow extract is predictable. Thus it must be subjected to the first or third
mode of operation.  If more than 32 bytes need to be revealed, then another
call to @phkdfStream@ with a secret key in the second mode of operation
is required for final output expansion.

The purpose of this function is that it provides a bit of key-stretching very
similar in flavor to PBKDF2. Also, this extraction function repeatedly hashes
the plaintext of the tag in order to amplify the overhead plausibly associated
with any hypothetical virtual black-box obscuration attacks.

Note that @phkdfSlowExtract@ is not hardened against changes to the number
of rounds to be computed: it's possible to share portions of the key-stretching
computation when the @rounds@ parameter is varied. To avoid this issue, our
complete worked PHKDF examples include the number of PHKDF rounds to be computed
among the initial arguments to @phkdfSlowExtract@. This means that any change
to the phkdf rounds parameter must restart the key-stretching to some time
before the slow extraction computation began.
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
  , phkdfCtx_finalize
  , phkdfCtx_finalizeHmac
  , phkdfCtx_finalizeHmacCtx
  , phkdfCtx_finalizeStream
  , PhkdfSlowCtx()
  , phkdfSlowCtx_extract
  , phkdfSlowCtx_addArg
  , phkdfSlowCtx_addArgs
  , phkdfSlowCtx_finalize
  , phkdfSlowCtx_finalizeStream
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

import           Crypto.PHKDF.HMAC
import           Crypto.PHKDF.HMAC.Subtle
import           Crypto.PHKDF.Primitives.Subtle
import           Crypto.Encoding.PHKDF
import           Crypto.Encoding.SHA3.TupleHash


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


-- | initialze a new empty HMAC context from the key originally supplied to
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

phkdfCtx_finalize :: Word32 -> ByteString -> PhkdfCtx -> ByteString
phkdfCtx_finalize counter tag ctx = Stream.head (phkdfCtx_finalizeStream counter tag ctx)

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

phkdfCtx_finalizeStream :: Word32 -> ByteString -> PhkdfCtx -> Stream ByteString
phkdfCtx_finalizeStream counter0 tag ctx = go counter0 hmacState0
  where
    -- we want to add 1-64 padding bytes to land on a half-block boundary
    n = phkdfCtx_byteLen ctx
    endPadLen = fromIntegral (64 - ((n - 32) .&. 63))

    endPadding = cycleByteStringToList endPadLen ("\x00" <> tag)

    resetCtx = phkdfCtx_resetCtx ctx

    hmacState0 =
        phkdfCtx_finalizeHmacCtx ctx &
        hmacCtx_updates endPadding

    go !counter hmacState = Cons nextBlock (go (counter + 1) hmacState')
      where
        !nextBlock =
            hmacState &
            hmacCtx_updates [bytestring32 counter, tag] &
            hmacCtx_finalize
        hmacState' =
            resetCtx &
            hmacCtx_update nextBlock

-- | close out a @phkdfStream@ context with a call to @phkdfSlowExtract@,
--   providing the counter, tag, @fnName@, and number of rounds to compute.
--   Note that @fnName@ is truncated to a length of 23-27 bytes long,
--   depending upon the number of rounds specified. Thus the @fnName@ is
--   primarily intended to be a protocol constant.

phkdfSlowCtx_extract :: Word32 -> ByteString -> ByteString -> Word32 -> PhkdfCtx -> PhkdfSlowCtx
phkdfSlowCtx_extract counter tag fnName rounds ctx0 = out
  where
    (Cons block0 innerStream) = phkdfCtx_finalizeStream counter tag ctx0

    phkdfLen = ((fromIntegral rounds :: Int64) + 1) * 512
    phkdfLenTag = leftEncode phkdfLen

    extFnNameLen = 30 - B.length phkdfLenTag

    extFnName = cycleByteStringWithNull extFnNameLen fnName

    outerCtx =
        phkdfCtx_reset ctx0 &
        phkdfCtx_addArg extFnName &
        phkdfCtx_unsafeFeed [phkdfLenTag, block0]

    fillerTag = cycleByteStringWithNull 32 tag

    go n !ctx (Cons block stream)
      | n <= 0 = PhkdfSlowCtx {
         phkdfSlowCtx_phkdfCtx = phkdfCtx_unsafeFeed [block] ctx,
         phkdfSlowCtx_counter = counter + rounds + 2,
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

phkdfSlowCtx_finalize :: PhkdfSlowCtx -> ByteString
phkdfSlowCtx_finalize = Stream.head . phkdfSlowCtx_finalizeStream

-- | finalize a call to @phkdfSlowExtract@

phkdfSlowCtx_finalizeStream :: PhkdfSlowCtx -> Stream ByteString
phkdfSlowCtx_finalizeStream ctx =
    phkdfCtx_finalizeStream
        (phkdfSlowCtx_counter ctx)
        (phkdfSlowCtx_tag ctx)
        (phkdfSlowCtx_phkdfCtx ctx)
