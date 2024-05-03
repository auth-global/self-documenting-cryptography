{-# LANGUAGE OverloadedStrings, ViewPatterns #-}

{- |

The [Global Password Prehash Protocol (G3P)](https://github.com/auth-global/self-documenting-cryptography/blob/prerelease/design-documents/g3p.md)
is a slow, attribution-armored password hash and key derivation function. Its
intented purpose is to ensure the delivery of plaintext salts from deployed
authentication databases to password crackers in order to support
[self-documenting deployments](https://www.cut-the-knot.org/Curriculum/Algebra/SelfDescriptive.shtml)
whose password hashes are /traceable/ or /useless/ after they have been /stolen/.
This secondary security goal seeks to use [/cryptoacoustics/](https://github.com/auth-global/self-documenting-cryptography/)
to provide [/embedded attributions/](https://joeyh.name/blog/entry/attribution_armored_code/)
that are as difficult as possible for an adversarial implementation to remove.

The G3P revisits the role of cryptographic salt, splitting the salt into the
cartesian product of the /seguid/, /username/, and /tag/ parameters. Any
parameter with "tag" as part of the name is an embedded attribution to anybody
providing the inputs to the /username/ or /password/ parameters. Tags are
themselves directly self-documenting embedded plaintext salts, in the sense
that one cannot easily or efficiently replace the tag with anything else
without losing the ability to compute the correct hash function.

There are several themes worked into this design:

1.  Always Be enCoding: one of the plaintext salts or another should be mixed
    into the final state as often and frequently as possible. If an attacker
    chooses to deploy fully homomorphic encryption in a password cracker,
    let there be no rest for the wicked.

2.  Always Be Forgetting: it should be possible to transfer the key stretching
    process to another semi-trusted computing element without providing that
    element with a password cracking attack that is signficantly less expensive
    than the work done so far. These opportunities occur at every PHKDF round,
    and at every bcrypt superround. Furthermore, any device that completes the
    PHKDF key-stretching computation can outsource some or all of the bcrypt
    superrounds without losing control of the end result.

3.  Excess Salt: our philosophy of applying salt is that it's the first thing
    you do, it's the last thing you do, it's something you do at every
    opportunity, and sometimes we even create new opportunities to add more
    salt. We have certainly found new justifications and applications for
    underappreciated yet pre-existing forms of salt.

4.  Unlimited Free Salt by Countering Excess Freedom: the G3P starts from
    conventional keys as it's first and primary layer of security.  Excessively
    long keys are often considered suspect, but very long keys that likely
    result in totally unique hash functions is also exactly what is needed
    in the information theoretic sense in order for there to plausibly be
    much if any cryptoacoustic advantage. Therefore, we use long
    plaintext salts with low average entropy, and use short, fixed-length,
    (ideally) high-entropy HMAC keys as both the starting and ending point.

5.  These goals align extremely well, and often lead to similar outcomes as,
    the advice found in [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://datatracker.ietf.org/doc/html/rfc5869)
    and [NIST SP 108r1 Recommendation for Key Derivation Using Pseudorandom Functions](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final).
    Both of these documents have profoundly contributed to the design of the
    G3P. PHKDF can be thought of as backporting the advice of these newer
    documents to the older PBKDF2 design, as well as finding new applications
    and justifications for the use of context parameters in password hash
    functions and key derivation protocols.

6.  From the viewpoint of an implementer, standard PBKDF2, HKDF, and bcrypt
    interfaces cannot be used to implement this design. HMAC-SHA256 is the
    only standard library primitive this password hash function relies upon.
    However, most library implementations of HMAC-SHA256 won't do, as G3Pb2
    uses bitstring end-of-message padding. Moreover, any reasonably practical
    implementation of the G3P requires an HMAC implementation that supports
    precomputed HMAC keys (for PHKDF) and backtracking (for bcrypt).

7.  From the viewpoint of an academic cryptographer, morally speaking, this
    design is literally a PBKDF2, an HKDF, and a bcrypt all at the same time,
    via a carefully designed pun.

-}

module Crypto.G3P.V2
  ( G3PSalt(..)
  , G3PInputs(..)
  , G3PSeedInputs(..)
  , g3pHash
  , G3PSpark()
  , g3pSpark_init
  , g3pSpark_toSeed
  , G3PSeed()
  , g3pSeed_toSprout
  , G3PSprout()
  , g3pSprout_addArg
  , g3pSprout_addArgs
  , g3pSprout_toTree
  , G3PTree()
  , g3pTree_toKey
  , G3PKey()
  , g3pKey_toGen
  , g3pKey_toStream
  ) where

import           Data.Bits (xor)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Function((&))
import           Data.Word
import           Data.Stream (Stream(..))
import qualified Data.Stream as Stream
import           Data.Vector (Vector)
import qualified Data.Vector as V
import           Network.ByteOrder (word32, bytestring64)

import           Crypto.Encoding.PHKDF
                    ( add64WhileLt
                    , takeBs
                    , nullBuffer
                    )
import           Crypto.Encoding.SHA3.TupleHash
import           Crypto.PHKDF.HMAC
import           Crypto.PHKDF.Primitives
import           Crypto.PHKDF.Primitives.Assert
import           Crypto.G3P.BCrypt (bcryptXsFree)
import           Crypto.G3P.V2.Subtle

-- | These input parameters are grouped together because they are the
--   parameters that will have to persist in memory for most or all of
--   the PHKDF-based key-stretching computation.
--
--   It is intended that deployments of an authentication database will
--   specify these as constants or near-constants. User-supplied inputs
--   would typically not go here. In this role, all these parameters
--   function as salt.
--
--   The seguid parameter acts as a deployment-wide salt. Cryptographically
--   speaking, the most important thing a deployment can do is specify a
--   constant seguid.  It is highly recommended that the seguid input be a
--   genuine Self-Documenting Globally Unique Identifier attesting to the
--   parameters, purposes, and public playbook of the protocol for y'all
--   to follow to use the deployment to spec.
--
--   The remaining string parameters are all directly-documenting, embedded
--   attributions. A deployment can use these tags to encode a message into the
--   password hash function so that it must be known to whomever can compute it.
--   There are a variety of different parameters because there are different
--   lengths of messages that can be expressed for free, and there are different
--   incremental costs for exceeding that limit.
--
--   It is particularly important to include some kind of actionable message
--   in the @domainTag@ and @longTag@ parameter. Specifying an empty string
--   in either of these parameters means that a significant quantity of
--   cryptoacoustic messaging space will be filled with silence.
--
--   Especially useful messages include URIs, legal names, and domain names.

data G3PSalt = G3PSalt
  { g3pSalt_seguid :: !HmacKey
    -- ^ usable as a high-repetition indirect tag via
    --   self-documenting globally unique identifiers (seguids)
  , g3pSalt_domainTag :: !ByteString
    -- ^ plaintext tag with one repetition per PHKDF round. 0-19 bytes are
    --   free, 20-83 bytes cost a additional sha256 block /per PHKDF round/,
    --   with every 64 bytes thereafter incurring a similar cost.
    --
    --   In the case of long domain tags, it is strategically advantageous
    --   to ensure that the first 32 bytes are highly actionable, as these
    --   bytes are commonly used as filler padding.
    --
    --   This parameter provides [domain separation](https://csrc.nist.gov/glossary/term/domain_separation).
    --   A suggested value is a ICANN domain name controlled by the deployment.
    --   The name is also a bit of an homage to the "realm" parameter of HTTP
    --   basic authentication, which in part inspired it.
  , g3pSalt_longTag :: !ByteString
    -- ^ plaintext tag with 1x repetition, then cycled for roughly
    --   8 kilobytes which is used as filler padding after the password.
    --
    --   This is typically duplicated as the 'g3pSeedInputs_bcryptLongTag'
    --   parameter, which provides a very large number of cryptoacoustic
    --   repetitions. If this step is not taken, most or all of this parameter
    --   can be discarded after the first call to HMAC is complete, making
    --   it essentially horn-loaded which would be a bit of an anomaly for
    --   this input block.
    --
    --   The first 0-63 bytes is also used as filler padding after the
    --   contextTags, possibly making part of this parameter not horn-loaded.
    --
    --   Constant time on inputs up to 4 kilobytes.  Overages incur one sha256
    --   block per 64 bytes.
  , g3pSalt_contextTags :: !(Vector ByteString)
    -- ^ plaintext tags with 4x repetition. Constant-time on 0-63 encoded bytes,
    --   which includes the length encoding of each string. Thus 60 of those
    --   free bytes are usable if the tags vector is a single string, or less if
    --   it contains two or more strings. The empty vector is a good default
    --   choice here.
    --
    --   Overages incur four sha256 blocks per 64 bytes.
    --
    --   This parameter is notable because it is the least expensive purely
    --   auxiliary input that is not horn-loaded. Thus if you want a very long
    --   salt input that provides a bit of extra collision resistance, this
    --   would be a logical candidate input location to consider.
    --
    --   If your deployment uses a random salt per account, this is an ideal
    --   location in which to place a copy of that salt.
  , g3pSalt_phkdfRounds :: !Word32
    -- ^ How expensive will the PHKDF component be? An optimal implementation
    --   computes exactly two SHA256 blocks per round if the domain tag is
    --   19 bytes or less, plus a reasonably large but constant number of
    --   additional blocks. I recommend 20,000 rounds or so. You might
    --   consider adjusting that recommendation downward in the case of
    --   domain tags that exceed 19 bytes in length: 13,333 rounds of PHKDF
    --   with a domain tag that is 83 bytes long should cost about
    --   the same number of SHA256 blocks as 20,000 rounds of PHKDF with a
    --   domain tag that is 19 bytes long.
  } deriving (Eq)

-- | These parameters are grouped together because they are hashed once
--   near the beginning of the protocol and then are no longer needed, unless
--   a deployment specifies duplicating (part of) one of these parameters
--   into another.  Thus all of these parameters are horn-loaded.
--
--   The input string to the "username" parameter could be provided directly
--   by the user.  Alternatively, it could be a random salt retrieved from
--   a server or database, typically looked up via a plaintext username.
--   The password is normally expected to be supplied by the users of a
--   deployment.
--
--   Furthermore, the credentials vector is here because it is an ideal
--   location to include other input. For example, one could implement
--   a Two-Secret Key Derivation (2SKD) scheme analogous to 1Password's.
--
--   A deployment can also specify additional constant tags as part of the
--   credentials vector.  As the plaintext of these tags is only ever hashed
--   into the output a single time, this alongside the bcrypt tag and long tag
--   are incrementally the least expensive options for plaintext tagging.
--
--   Note that the username and password are subjected to additional length
--   hardening. The G3P operates in a constant number of SHA256 blocks so long
--   as the combined length of the username and password is less than about
--   4 KiB,  or the combined length of the username, password, and long tag is
--   less than about 8 KiB. The actual numbers are somewhat less in both cases,
--   but this is a reasonable approximation.
--
--   In the case of all of the inputs in this record, longer values incur one
--   SHA256 block per 64 bytes.

data G3PInputs = G3PInputs
  { g3pInputs_username :: !ByteString
  -- ^ constant time on 0-293 bytes, or if the combined length of the
  --   username and password is less than about 4 kilobytes, or if the
  --   combined length of the username, password, and long tag is
  --   less than about 8 kilobytes.
  --
  --   Using a deployment-identifying seguid and domain tags makes
  --   it perfectly safe to put normalized usernames here, as then
  --   this salt would then only need to be unique within that deployment.
  --
  --   This approach comes with the cost that you will have to reliably
  --   perform username normalization everywhere this hash function is
  --   computed. Offering a server-side remote procedure call to perform
  --   this normalization would be recommended.
  --
  --   The G3P is intentionally designed to allow the plaintext of this
  --   parameter to be hidden from a password cracker, preventing
  --   the cracker from immediately logging in if successful. However,
  --   this partial application doesn't apply any key-stretching, meaning
  --   that guessable login names can be cracked relatively quickly.
  --
  --   A deployment could specify that the username be hashed before being
  --   placed into this parameter, thus providing key-stretching themselves.
  --
  --   Thus this approach is less a defensive line than more a "sand in
  --   the gears" tactic. It might also be useful as a legal damages
  --   enhancement strategy against unauthorized password crackers who
  --   fail to take this step to help protect users' privacy.
  --
  --   The advantage of this approach is that in a client-side prehashing
  --   scenario, it is simple and easy to ensure that the salting process
  --   does not leak anything about the existence or non-existence of
  --   accounts, does not leak anything about recent account activity, and
  --   cannot be used as reidentification hooks in deanonymization attacks.
  --
  --   On the other hand, using a random per-account salt has the potential
  --   to be a far more meaningful defensive line. This can serve both the
  --   interests of legitimate deployments and the password hash thieves
  --   that attack them. Some thieves will want to be able to outsource
  --   password cracking work without giving successful crackers an
  --   opportunity to log in.
  --
  --   The cost is that in typical client-side prehashing scenarios, your
  --   server will have to reveal the actual salt for arbitrary accounts
  --   to arbitrary members of the public.
  --
  --   This has the potential to leak information about the (non-)existence
  --   of accounts, to leak information about recent account activity, and
  --   to provide reidentification hooks for deanonymization attacks.
  --
  --   It should be possible to largely mitigate these issues; for example,
  --   one might generate consistent nonsense as the salt for non-existent
  --   accounts by having the server normalize the username and hash it with
  --   a secret key. While such a simple approach might not be perfect, it
  --   would likely go a long way towards mitigation.
  --
  --   In a few specialized cases it might be possible to hide a salt
  --   from members of the general public by requiring pre-authentication
  --   before the password can even be attempted. However, this cannot
  --   be a general-purpose solution, as passwords are one of the fundamental
  --   solutions to the problem of key management, and key management is
  --   the fundamental problem behind authentication.
  --
  --   One can also supplement any salt applied here with an oblivious
  --   pseudorandom function (OPRF) in your authentication flow, especially if
  --   password-authenticated key agreement (PAKE) is used. Through the magic
  --   of multiparty computation, it's possible to apply a salt that only the
  --   server knows to a password attempt that only the client knowns. However,
  --   OPRF cannot be directly integrated into the G3P, though the G3P should
  --   be an excellent choice for a key derivation function to prepare a
  --   password for OPRF.
  --
  --   I see this choice of plain usernames versus random salts as a fairly
  --   fundamental tradeoff in the design of G3P deployments. I took the time
  --   to ensure that both are possible. Either can be executed poorly,
  --   and both can be executed well. This decision has significant strategic
  --   consequences. Pick your poison carefully.
  , g3pInputs_password :: !ByteString
  -- ^ constant time on 0-293 bytes, or if any of the other conditions are met.
  , g3pInputs_credentials :: !(Vector ByteString)
  -- ^ constant time on 0-281 encoded bytes. This includes a variable-length
  -- field that encodes the bit length of each string; this field itself
  -- requires two or more bytes per string.
  } deriving (Eq)

data G3PSeedInputs = G3PSeedInputs
  { g3pSeedInputs_bcryptKey :: !HmacKey
    -- ^ Key to used to generate keys for bcrypt superrounds and to soak up
    --   the entropy from bcrypt's state at the end of each superround.
    --   Duplicating the 'g3pSalt_seguid' is a good default choice.
  , g3pSeedInputs_bcryptRounds :: !Word32
    -- ^ How expensive will the bcrypt component be? 4000 rounds recommended,
    --   give or take a factor of 2 or so. Each bcrypt round is approximately
    --   as time consuming as 60 PHKDF rounds. Using the recommended cost,
    --   parameters, the cost should be dominated by bcrypt.
  , g3pSeedInputs_bcryptLongTag :: !ByteString
    -- ^ Be aware this is truncated to (rounds + 1) * 4176 bytes, but
    --   length still matters after that. The primary intended use is to
    --   duplicate 'g3pSalt_longTag' a very large number of times.
    --
    --   Also be aware that nobody should trust this parameter with arbitrary,
    --   potentially hostile input that is selected after all of the other
    --   inputs to the bcrypt comptuation are known. There are, however,
    --   a large number of ways to avoid any potential issues, including:
    --
    --   1.  Ensuring that this input is fully commited to before looking
    --       at all of the other input parameters /by convention/, which is
    --       true in the primary intended use case as an extended salt for
    --       password hashing.
    --
    --   2.  Ensure that this input has been committed to by including the
    --       entirety of its contents in the derivation of at least one other
    --       input parameter. Note that duplicating 'g3pSalt_longTag' is
    --       sufficient to meet this requirement, as is duplicating
    --       any other 'G3PSalt' parameter.
    --
    --   3.  Ensure that this input is less than 4448 bytes long. Local HMAC
    --       computations ensure at least this many bytes are automatically
    --       committed to before the bcrypt key stretching is allowed to
    --       move forward.
    --
    --   4.  Ensure that this input has some kind, any kind, of recognizable
    --       pattern. If this input is a valid UTF8 encoding, it doesn't matter
    --       if the textual content is random gibberish. It's extremely
    --       doubtful that an attacker could achieve any particularly
    --       nefarious goal under this restriction.
    --
    --   Note that any single one of these conditions should be sufficient
    --   to avoid problems, and that the primary intended use case for this
    --   parameter meets all of them. After all, the entire point of this
    --   parameter is to ensure the delivery of plaintext salts from
    --   authentication database deployments to password crackers.
    --
    --   Failing all of that, there's still an attempt to make the G3P
    --   resistant to hostile inputs. Within each bcrypt round, the exact same
    --   longTag bytes are repeated twice in a combinatorial block design that
    --   ensures nonlinear effects.
    --
    --   I wouldn't want to rely on this design feature of last resort without
    --   careful study, which is likely to suggest further improvements.
    --   Yet this hedge doesn't cost anything with respect to the intended
    --   use case, and seems plausibly strong in situations that fall well
    --   outside any intended use case.
    --
    --   Regarding condition 2, any of the 'G3PInput' parameters would also
    --   qualify. However, it would be rather silly to repeat the user's
    --   password here, as that would prevent the bcrypt key stretching
    --   computation from being securely outsourced to a semi-trusted device.
    --
    --   Regarding condition 3, the actual size of a parameter that is fully
    --   committed to via baked-in hashing is likely a bit more than 8352
    --   bytes, but this would require further verification.
    --
    --   The shortest plausible attack string would seem to need to be as long
    --   as the truncation limit, which is north of 16 megabytes if you specify
    --   the suggested 4000 rounds.
  , g3pSeedInputs_bcryptDomainTag :: !ByteString
    -- ^ Used to derive the keys for a super round in bcrypt-xs-ctr mode.
    --   Duplicating the 'g3pSalt_domainTag' is a good default choice.
  , g3pSeedInputs_bcryptContextTags :: !(Vector ByteString)
    -- ^ Also used to derive super round keys for bcrypt. Leaving this
    --   empty is a good default choice. In particular, one /should not/
    --   default to duplicating anything between this parameter and
    --   the 'g3pSeed_contextTags' parameter.
    --
    --   For example, if your deployment uses a random per-user salt, then
    --   it's a good idea to include that salt in the 'username' and
    --   'contextTags' parameters, but exclude the plaintext of the salt
    --   from 'bcryptContextTags'.
    --
    --   The use of a random salt implies that if some or all of the bcrypt
    --   computation is outsourced to another device, that device cannot
    --   break even weak passwords without knowing the salt.
    --
    --   Directly including that random per-user salt in the
    --   'bcryptContextTags' vector would require that the plaintext of this
    --   salt be known to the device performing the key-stretching computation,
    --   thus automatically obviating this possible line of defense.
    --
    --   If one is absolutely set on including that random salt here, one
    --   could hash the salt first to derive a new salt that cannot itself
    --   be used to crack the password. What things are forgotten and when
    --   are important details in cryptographic processes, and these choices
    --   have strategic implications.
    --
    --   If some unusual deployment of the G3P accepts arbitrary external
    --   inputs into the 'bcryptLongTag', one possible way to handle this
    --   situation efficiently and safely would be to hash the entire input,
    --   and include that hash in this parameter.
  }

-- | The Global Password Prehash Protocol (G3P). Note that this function is very
--   intentionally implemented in such a way that the following idiom is
--   efficient. It performs the expensive key stretching phase only once,
--   and results in 3 cryptographically independent output streams, i.e.
--   statistically independent to any efficient attacker that does not have
--   access to the underlying password and other secrets.
--
-- @
--  let mySprout = g3pHash salt inputs seedInputs seguid
--      myAuthKey = mySprout ["auth", "user salt: ec8296b96e939f"] "login.my.domain.example" ""
--      myDiskKey = mySprout ["disk",longTag,"key","bf94facc27b76328"] "cloud.my.domain.example" ""
--   in [ myAuthKey "" (word32 "AUTH") "my.domain.example"
--      , myDiskAuth "" (word32 "DISK") "filename0.txt"
--      , myDiskAuth "" (word32 "DISK") "quarterly-report.pdf"
--      ]
-- @
--
--   In addition to sharing the main key-stretching computation among
--   all three independent output streams, this also shares the computation
--   of the 'G3PKey' among the two calls to @myDiskAuth@.  Although the
--   savings in this latter context is relatively miniscule, it also can be
--   relevant in certain contexts.
--
--   In the case that you want or need to persist or serialize the intermediate
--   intermediate structures, then the plain-old-datatypes 'G3PSpark',
--   'G3PSeed', 'G3PSprout', 'G3PTree','G3PKey', 'PhkdfGen', and their
--   associated functions are more relevant than unbounded streams and
--   implicit closures.

-- Oof, I didn't actually succeed in my claim in the first release of G3Pb1.
-- I now have a deeper appreciation for point-less programming. On the other
-- hand, I feel like there should be a much more idiomatic solution here.
g3pHash :: Foldable f
        => G3PSalt -- ^ All the parameters needed throughout the entire key-stretching computation.
        -> G3PInputs -- ^ All the parameters that can be forgotten as soon as they are hashed once.
        -> G3PSeedInputs -- ^ All the parameters needed for bcrypt-based key stretching
        -> HmacKey -- ^ Sprout Seguid. A good default is to duplicate 'g3pSalt_seguid'.
        -> f ByteString -- ^ Sprout Role, an arbitrary number of bytestring parameters.
        -> ByteString -- ^ Sprout Tag. A good default is to duplicate 'g3pSalt_domainTag'.
        -> ByteString -- ^ echo key right
        -> ByteString -- ^ echo header
        -> Word32 -- ^ echo counter
        -> ByteString -- ^ echo tag. A good default is to duplicate the sprout's tag.
        -> Stream ByteString -- ^ An unbounded stream of 32-byte output blocks.  Use as many or as few as you want. NIST SP 800-108 recommends never looking at more than 137.4 GB of output, though this is an extremely cautious recommendation. On the other hand, if you really want that much CSPRNG data, you are likelyb etter off using this function to generate keys for another, faster CSPRNG.
g3pHash salt inputs =
    let spark = g3pSpark_init salt inputs
     in \seedInputs ->
        let seed = g3pSpark_toSeed seedInputs spark
         in \seguid ->
            let sprout0 = g3pSeed_toSprout seguid seed
             in \role ->
                let sprout' = g3pSprout_addArgs role sprout0
                 in \tag ->
                    let tree = g3pSprout_toTree tag sprout'
                     in \ekey ->
                        let key = g3pTree_toKey ekey tree
                         in \ehdr ectr etag ->
                            g3pKey_toStream ehdr ectr etag key

myDrop' :: Word32 -> Stream a -> Stream a
myDrop' = go
  where
    go 0 s = s
    go n (Cons x s) = x `seq` go (n-1) s

xorBS :: ByteString -> ByteString -> ByteString
xorBS = B.packZipWith xor

data PairBS = PairBS !ByteString !ByteString

xorScan :: Stream ByteString -> Stream PairBS
xorScan = Stream.tail . Stream.scan' f (PairBS blankChunk blankChunk)
  where f (PairBS acc old) new = PairBS (xorBS acc old) new
        blankChunk = B.replicate 32 0

-- | Uses a PBKDF2-like key-stretching computation to prepare keys for
--   the bcrypt key-stretching phase.  

g3pSpark_init :: G3PSalt -> G3PInputs -> G3PSpark
g3pSpark_init salt inputs = spark
  where
    -- Explicitly unpack everything for the unused variable warnings.
    -- i.e. It's relatively easy to check that we've unpacked every
    -- field, then we can rely on unused variable warnings to ensure
    -- we have in fact made use of everything.
    domainTag = g3pSalt_domainTag salt
    seguid = g3pSalt_seguid salt
    longTag = g3pSalt_longTag salt
    contextTags = g3pSalt_contextTags salt
    phkdfRounds = g3pSalt_phkdfRounds salt

    username = g3pInputs_username inputs
    password = g3pInputs_password inputs
    credentials = g3pInputs_credentials inputs

    headerAlfa = [ "G3Pb2 alfa username", username ]

    usernamePadLen = a
      where
        al = encodedVectorByteLength headerAlfa
        a  = add64WhileLt (349 - al) 32

    usernamePadding = B.concat $
      takeBs (fromIntegral (usernamePadLen - 32)) (cycle [longTag, "\x00"]) ++
      takeBs 32 [domainTag, "\x00", "password G3Pb2", nullBuffer]

    headerUsername = headerAlfa ++ [ usernamePadding ]

    -- password will go here

    headerLongTag =
      [ longTag
      , B.concat
          [ bareEncode phkdfRounds, "\x00"
          , "Global Password Prehash Protocol bcrypt(XS) v2 G3Pb2", "\x00"]
      ]

    passwordPadLen = c
      where
        al = encodedVectorByteLength headerLongTag
        a  = add64WhileLt (8605 - al) 4429
        bl = encodedVectorByteLength headerUsername
        b  = add64WhileLt (a - bl) 328
        cl = encodedByteLength password
        c  = add64WhileLt (b - cl) 32

    longPadding =
      takeBs (fromIntegral (passwordPadLen - 32)) (cycle [longTag, "\x00"]) ++
      takeBs 32 [domainTag, "\x00", "creds G3Pb2", nullBuffer]

    credsPadLen = a
      where
        al = encodedVectorByteLength credentials
        a  = add64WhileLt (318 - al) 32

    credsPadding =
      takeBs (fromIntegral (credsPadLen - 29)) (cycle [longTag, "\x00"]) ++
      takeBs 29 [domainTag, "\x00", "tags G3Pb2", nullBuffer]

    (PairBS alfaSum alfaExt) =
        phkdfCtx_init seguid &
        phkdfCtx_addArgs headerUsername &
        phkdfCtx_assertBufferPosition' 32 &
        phkdfCtx_addArg  password &
        phkdfCtx_addArgs headerLongTag &
        phkdfCtx_addArgConcat longPadding &
        phkdfCtx_assertBufferPosition' 32 &
        phkdfCtx_addArgs credentials &
        phkdfCtx_addArgConcat credsPadding &
        phkdfCtx_assertBufferPosition' 29 &
        phkdfCtx_addArgs contextTags &
        phkdfCtx_addArg (bareEncode (V.length contextTags)) &
        phkdfCtx_toStream endPadding
           (word32 "go\x00\x00" + 2024) domainTag &
        xorScan & myDrop' 1 & -- ensure that the sum is not filled with nulls
        myDrop' phkdfRounds & -- do the requested number of additional rounds
        Stream.head

    endPadding = B.concat . flip takeBs (cycle [longTag, "\x00"]) . fromIntegral

    bravo = "G3Pb2 bravo"

    headerBravo =
        [ bravo, alfaExt ] ++ takeBs 53 (cycle [longTag, "\x00"]) ++
        [ alfaSum ]

    -- keyB: key bravo begins bcrypt (and key bullshit baffles brains)
    -- keyB was generated by the call to G3Pb2 bravo, and starts bcrypt
    -- keyB is used to generate a prefixed hmac key to bcrypt,
    --   which is used to generate round keys for bcrypt, as well
    --   to summarize bcrypt's pBox and sBox

    ("",prefixBravo) = hmacKeyPrefixed_init seguid &
                       hmacKeyPrefixed_feeds headerBravo

    bravoKeyPad b = B.concat $
        takeBs 31 [domainTag, "\x00", bravo, nullBuffer] ++ [b]

    keyB = phkdfCtx_initPrefixed (bravoKeyPad "B") prefixBravo &
           phkdfCtx_addArgs contextTags &
           phkdfCtx_finalize endPadding (word32 "KEYB") domainTag

    -- keyC, charlie's continuation control key
    --   It's inclusion (or omission) is a fundamental design tradeoff.

    --   This key allows a low-power device to outsource (part of) the
    --   bcrypt computation without losing control of the continuation
    --   that leads to the seed.

    --   The downside is that keyC has less key stretching than the bcrypt
    --   computation, and cannot be forgotten until after the bcrypt key
    --   stretching is complete, or the computation is abandoned.

    --   Given that this is already at PBKDF2-level key stretching,
    --   and that many password hash functions have historically not
    --   cared about how soon (and often) their computation becomes
    --   unreversable, I think this is a good tradeoff in the
    --   primary intended context of a client-side prehash function.

    keyC = phkdfCtx_initPrefixed (bravoKeyPad "C") prefixBravo &
           phkdfCtx_addArgs contextTags &
           phkdfCtx_finalize endPadding (word32 "KEYC") domainTag

    spark = G3PSpark
       { g3pSpark_beginKey = keyB
       , g3pSpark_contKey  = keyC
       , g3pSpark_contextTags = contextTags
       , g3pSpark_domainTag   = domainTag
       }

g3pSpark_toSeed :: G3PSeedInputs -> G3PSpark -> G3PSeed
g3pSpark_toSeed inputs spark = G3PSeed seed
  where
    beginKey = g3pSpark_beginKey spark
    contKey = g3pSpark_contKey spark
    contextTags = g3pSpark_contextTags spark
    domainTag = g3pSpark_domainTag spark

    bSeguid = g3pSeedInputs_bcryptKey inputs
    bRounds = g3pSeedInputs_bcryptRounds inputs
    bLongTag = g3pSeedInputs_bcryptLongTag inputs
    bDomainTag = g3pSeedInputs_bcryptDomainTag inputs
    bContextTags = g3pSeedInputs_bcryptContextTags inputs

    charlie = "G3Pb2 charlie"

    charlieHeader = charlie : beginKey : takeBs 19 [domainTag, nullBuffer]

    ("", charliePrefix) =
      hmacKeyPrefixed_init bSeguid &
      hmacKeyPrefixed_feeds charlieHeader

    bcryptName = B.concat
      [ "G3Pb2 bcrypt-xs-free"
      , bytestring64 (8 * fromIntegral (B.length bLongTag))
      ]

    (_, charlieCont) =
      bcryptXsFree id bcryptName bLongTag bContextTags bDomainTag
                   bRounds charliePrefix

    contPad = B.concat $ takeBs 32 [domainTag, "\x00", charlie, nullBuffer]

    ("", endCont) = hmacKeyPrefixed_feeds [contPad, contKey] charlieCont

    seed = phkdfCtx_initPrefixed contPad endCont &
           phkdfCtx_addArgs contextTags &
           phkdfCtx_finalize endPadding (word32 "SEED") domainTag

    endPadding = B.concat . flip takeBs (cycle [domainTag, "\x00"]) . fromIntegral

g3pSeed_toSprout :: HmacKey -> G3PSeed -> G3PSprout
g3pSeed_toSprout key (G3PSeed seed) = G3PSprout ctx
  where
    delta = "G3Pb2 delta"
    ctx = phkdfCtx_init key &
          phkdfCtx_addArg (delta <> seed)

g3pSprout_addArg :: ByteString -> G3PSprout -> G3PSprout
g3pSprout_addArg x = G3PSprout . phkdfCtx_addArg x . g3pSprout_phkdfCtx

g3pSprout_addArgs :: Foldable f => f ByteString -> G3PSprout -> G3PSprout
g3pSprout_addArgs xs = G3PSprout . phkdfCtx_addArgs xs . g3pSprout_phkdfCtx

g3pSprout_toTree :: ByteString -> G3PSprout -> G3PTree
g3pSprout_toTree domainTag (G3PSprout ctx) = G3PTree key
  where
    key = phkdfCtx_finalize endPadding (word32 "KEYZ") domainTag ctx
    endPadding = B.concat . flip takeBs (cycle [domainTag, "\x00"]) . fromIntegral

g3pTree_toKey :: ByteString -- ^ This @echo key@ is the right half of the output key.  It is truncated to 32 bytes.
              -> G3PTree -> G3PKey
g3pTree_toKey echoKeyR (G3PTree echoKeyL) = G3PKey (hmacKeyHashed key)
  where
    keyR = takeBs 32 [echoKeyR, "\x00", "G3Pb2 echo key right padding", nullBuffer]
    -- Note that echoKeyL should already be 32 bytes, so this should be id:
    keyL = takeBs 32 [echoKeyL, nullBuffer]
    key = B.concat (keyL ++ keyR)

-- | Variant of 'g3pKey_toStream' that returns plain old data.

g3pKey_toGen
  :: ByteString -- ^ echo header
  -> Word32 -- ^ echo counter
  -> ByteString -- ^ echo tag
  -> G3PKey -> PhkdfGen
g3pKey_toGen echoHeader echoCtr echoTag (G3PKey key) = gen
  where
    hdr = B.concat $
      takeBs 32 [echoHeader, "\x00", "G3Pb2 echo header padding", nullBuffer]
    gen = phkdfGen_initHashed key hdr echoCtr echoTag

-- | Turn a secret, derived 'HmacKeyHashed' into an unbounded
--   stream of 32-byte output blocks.

g3pKey_toStream
  :: ByteString
  -- ^ The @echo header@ is truncated to 32 bytes.
  --
  -- As the initial state of the output stream generator, if more than one
  -- block of the resulting output stream is ever examined, then this
  -- parameter must not include any new secrets. Otherwise the old secrets
  -- are potentially still crackable from the relationship between output
  -- stream blocks.
  --
  -- This problem can be avoided by ensuring at least one of these are true:
  --
  --     1.  sticking to anodyne messages that aren't too specific to
  --         this specific password attempt, like a company name
  --
  --     2.  including data that's already been included elsewhere in the
  --         derivation of the Merkle tree.
  --
  --     3.  duplicating the content of this parameter in the @echo key@
  --         and/or @echo tag@ parameters.
  -> Word32
  -- ^ The @echo counter@, functionally a bonus HKDF info parameter.
  -> ByteString
  -- ^ The @echo tag@, functionally identical to HKDF's info parameter.
  -> G3PKey -> Stream ByteString
g3pKey_toStream hdr ctr tag key =
  phkdfGen_toStream (g3pKey_toGen hdr ctr tag key)

