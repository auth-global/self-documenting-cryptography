{-# LANGUAGE OverloadedStrings, OverloadedLists #-}

{- |

This is intended to be a fairly realistic sketch of what a reasonable-quality
deployment of the G3P might look like for authentication purposes.

TODO: this file may appear to use base16-encoded inputs, but it's literally
base16-encoded inputs, not things decoded to binary and then used as an input.
Fix this.

It starts to sketch how end-to-end encryption might work, but this is intended
more to stimulate the imagination than be a complete sketch.

-}

-- TODO: get the JSON test harness capable of handling partial evaluation
-- TODO: actually set up haddock example testing
-- TODO: include good examples of rehearsals
--           G3Pb2 full dress rehearsal on password change
--           G3Pb2 login tech rehearsal on login page load
-- TODO: G3Pb2 suggested approaches to handling second secrets

module MyCorpExample where

import Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as B
import Data.Text(Text)
import Data.Vector()
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.G3P.V2
import Crypto.G3P.V2.Foxtrot
import Crypto.PHKDF(phkdfGen_head)
import Crypto.PHKDF.HMAC(hmacKey)
import Crypto.Argon2

tests :: [TestTree]
tests =
  [ testCase "My Corporation" $ map B.encodeBase16 results @?= auResults
  ]

results :: [ByteString]
results =
  let myDomain = "my.domain.example"
      myLoginDomain = "login.my.domain.example"
      myStorageDomain = "cloud.my.domain.example"
      myLongTag = "My Corporation, Inc. https://my.domain.example/.well-known/security.txt" :: ByteString
      mySeguid = hmacKey "9c08053b7e507a78b571b5b93e1326674540d7106da6408fcafeddcfcdf1ed76"

      userPublicSalt = "60473b8010e16d46"

      -- If your deployment uses a public salt server, I recommend keeping
      -- random userPublicSalts directly in a database. More specifically, I
      -- do not recommend deriving public salts from non-public information, as
      -- an eavesdropper could steal this non-public information and use it as
      -- evidence that they have actually compromised your stuff.

      -- Or, your deployment could apply key-stretching, perhaps via the G3P,
      -- to a login name to derive the userPublicSalt in a transparent way,
      -- avoiding the pitfalls of running a public salt server.

      -- Either approach seems preferable using a login name as the username
      -- parameter: the G3P always allow the plaintext of the username to be
      -- completely hidden via partial evaluation, but this applies no key
      -- stretching and therefore would be relatively easy to crack. An
      -- attacker who cracks both the username and password might then be able
      -- to log in, and these can be cracked one at a time in this scenario.

      userSecondSecretHash = "0c06f683f093cb899b4a1e9836fc7281"
      userSalt =
        G3PSalt {
          g3pSalt_seguid = mySeguid,
          g3pSalt_longTag = myLongTag,
          g3pSalt_contextTags = [userPublicSalt],
          g3pSalt_domainTag = myDomain,
          g3pSalt_phkdfRounds = 20240
        }
      userInputs =
        G3PInputs {
          g3pInputs_username = userPublicSalt,
          g3pInputs_password = "correct horse battery staple",
          g3pInputs_credentials = [userSecondSecretHash]
        }
      mySeedInputs =
        G3PSeedInputs {
          g3pSeedInputs_bcryptSeguid = mySeguid,
          g3pSeedInputs_bcryptCredentials = [],
          g3pSeedInputs_bcryptLongTag = myLongTag,
          g3pSeedInputs_bcryptContextTags = [],
          g3pSeedInputs_bcryptDomainTag = myDomain,
          g3pSeedInputs_bcryptRounds = 4202
        }
      userSprout = g3pHash userSalt userInputs mySeedInputs mySeguid
      userHeader = userPublicSalt <> myDomain
      userAuthPrehash =
        mySprout ["auth",userPublicSalt] myLoginDomain
                 userHeader userHeader (word32 "AUTH") myLongTag

      -- Now, everything above would ideally happen on the client device, not
      -- the server. However, the server needs to hash the result further before
      -- storage. To deter precomputation attacks on an account, this sketch
      -- of a hypothetical deployment combines two somewhat crude (relative to
      -- PAKE) but effective strategies:
      --
      -- 1. The auth servers perform by far the most expensive key-stretching
      --    computation, and
      --
      -- 2. The auth servers perform this computation behind a secret HMAC key

      -- In my estimation, in many contexts argon2 is likely to be the most
      -- easily accepted hash function for key-stretching. However without
      -- modification argon2 doesn't have much cryptoacoustic potential,
      -- unlike yescrypt and Catena which appear to have some (probably
      -- largely "accidental") cryptoacoustic potential.

      -- I'd love to build a new hash function based closely on argon2, but
      -- this is delicate, time-consuming, and unpredictable work. For the
      -- time being, combining argon2 and g3pFoxtrot is almost certainly an
      -- excellent choice for server-side hashing.

      -- If the overall authentication flow is based on sending a plaintext
      -- prehash to the server which is then hashed further, I recommend using
      -- a secret, server-side salt per account. As this salt is never intended
      -- to be publicly acknowledged, one could derive this salt from
      -- non-public information without directly providing an eavedropper the
      -- ability to prove to others they've been in your infrastructure.

      -- However, I would still recommend always storing a random secret per
      -- account so that an eavesdropper cannot steal your entire secret salt
      -- database, possibly including secret salts that aren't yet in use,
      -- by stealing a few keys.

      -- On the other hand, deriving the salt using secrets both inside
      -- and outside the database means that if somebody steals one set alone,
      -- they won't have access to your secret salts.

      mySecretSeguid = hmacKey "7db250698fe555f6832f33189f97e14ef3c1c2dcada5807119aa7676c24f3fac"

      -- mySecretSeguid should be stored outside the database. Because you want
      -- to be able to easily start a migration to a new key at any time, but
      -- typically will not ever be able to guarantee any timeframe after which
      -- you can get rid of the old keys, you'll actually need a (relatively)
      -- small number of keys stored outside of the database, and a way of
      -- identifying which key is to be used with a given userPrivateSeed

      userPrivateSeed = "4314a11c2620a8ad"
      
      -- userPrivateSeed would normally be stored in the password database,
      -- alongside the password hash and other account information.
      
      userPrivatePreSalt = g3pTango mySecretSeguid [userPrivateSeed, userPublicSalt, "user private presalt", myLongTag] (word32 "SALT") myLoginDomain
      userPrivateSalt = g3pTango mySeguid [userPrivatePreSalt, "user private salt", myLongTag] (word32 "SALT") myLoginDomain

      -- This derivation scheme allows My Corp to prove that its secret salts
      -- are in fact its trade secrets even in the face of the most dogged
      -- liars. Moreover this fact can possibly remain plausibly deniable even
      -- after the derivation has been stolen and published, so neither does
      -- this commit My Corp to claiming its secrets as its own.

      -- Deriving a secret HMAC key per account allows My Corp to outsource
      -- offline cracking attacks on individual accounts without revealing an
      -- offline cracking attack on every account.

      -- Moreover, this derivation allows the proof-of-trade-secret to also be
      -- revealed/claimed on a per-account basis.

      foxtrot = g3pFoxtrot (G3PFoxtrotSalt
        { g3pFoxtrotSalt_key = hmacKey (userPrivateSalt <> B.take 32 myDomain)
        , g3pFoxtrotSalt_longTag = myLongTag
        , g3pFoxtrotSalt_contextTags = [userPublicSalt]
        , g3pFoxtrotSalt_domainTag = myLoginDomain
        , g3pFoxtrotSalt_bcryptRounds = 383
        })

      argon2 = hash $ HashOptions
        { hashIterations = 3
        , hashMemory = 384 * 1024 -- 384 MiB
        , hashParallelism = 1
        , hashVariant = Argon2id
        , hashVersion = Argon2Version13
        , hashLength = 32
        }

      userPrestoreHash = foxtrot ["P" <> userAuthPrehash] (word32 "PASS")
  
      (Right userArgon2Hash) = argon2 (userPrivateSalt <> userPrestoreHash) myLongTag
      
      -- Argon2 hashes (Password, Salt, Secret Key, Associated Data) in that
      -- order. Thus we prefix the "password" with our secret salt, and
      -- use the argon2's "salt" parameter as a self-documenting tag.

      foxtrot' = foxtrot ("A" <> userArgon2Hash)
      userStoredHash = foxtrot' [] (word32 "HASH")

      -- userStoredHash is suitable to be stored in an auth database, and
      -- subsequent authentication attempts can compare this hash against the
      -- database. If this authentication is successful, we can efficiently
      -- compute a key for E2EE storage that includes all of the key-stretching
      -- work performed thus far, and return it to the client:

      userStoragePrekey = foxtrot' [myStorageDomain, "storage-prekey"] (word32 "KEY\x00")

      -- Note that the userStoragePrekey needs to be re-combined with the
      -- original client-side seed before end-to-end encrypted files can be
      -- unlocked. This makes the prekey useless on its own, and therefore the
      -- auth server never gains the information needed to unlock the files
      -- without first guessing "correct horse battery staple".

      -- An attacker who has access to the user's encrypted files but does not
      -- have that user's secret server-side salt would not be able to confirm
      -- or deny that the user's password is "correct horse battery staple",
      -- without talking to the auth server, unless the user has a backup
      -- method to unlock that particular file that bypasses the auth server,
      -- and that backup method reused the user's password. Being required to
      -- talk to an auth server implies that two-factor authentication can be
      -- used to protect encrypted files.

      userStorageKey = mySprout
                      ["disk",myStorageDomain,myLongTag,
                      "key",userStoragePrekey]
                     myStorageDomain userHeader userHeader (word32 "DISK")

      -- myLongTag is included above because it is sufficiently long to be able
      -- to commit to the "disk" and @myStorageDomain@ values by partially
      -- evaluating the sprout and then forgetting the seed. Thus the seed
      -- does not need to be retained while the client is waiting on the
      -- @userStoragePrekey@ from the authentication server.

   in [ userAuthPrehash
      , userStoredHash
      , userStorageKey "filename0.txt"
      , userStorageKey "quarterly-report.pdf"
      ]

-- FIXME: these are currently wrong, change these once this part of the test
-- suite is working again.
auResults :: [Text]
auResults =
  [ "3759cc63959878c79e9077f7c8dc401cad1700e03bab7ca52ef2982553c37197"
  , "e8c26138add0f16e49ad1e2b55ff333eda42fa7330969146f55ac48a49f7166e"
  , "d0a3b6c432b6b612fb82a60554fa3fa906e8a4cc324c6f1de38e52d8eec254cf"
  , "c2fb84c71dbe52280bd0d481c770e4e476a5e0daeeddc3e9eee00423bef9a7e4"
  ]

{-
There are many moving parts that go into a password hash implementation. When
the G3P is deployed as a client-side prehash, My Corp often won't have full
control of the stack its running on. Thus a dynamically-generated dry-run test,
akin to a theatrical full dress rehearsal, is highly recommended whenever
setting or changing a password.

If something goes wrong with the hash computation when a password is set, this
can lead to a major inconvenience or even data loss. This may lead to the need
to reset the password in the case of a traditional website, or lead to the
inability to decrypt an end-to-end encrypted file.

Dynamic testing can greatly reduce the probability of this happening. Moreover,
failed tests builds operational awareness of relevant implementation issues
affecting your deployment.

Here, every parameter should be as close as possible to what it will look like
in the actual password hash computation. In most cases, this means every
parameter other than the password and second secret parameters should be
exactly as it will be for the actual computation.

The server should generate a random nonce, possibly encoded as a passphrase, to
use as the password input. This nonce should have at least 128 bits of entropy.
The server then sends the password and say, the first 16 bytes of the hash
resulting from the tests.

The client should then run the G3P on the password with the full number of
rounds, and then use the outputs as further inputs to the G3P and its key
derivation function. Key-stretching can be run with a reduced number of rounds
after the first computation. Typical deployments should include a test with a
password input that is exactly 31 bytes long, a password that is exactly 32
bytes long, tests with and without a second secret if your deployment officially
supports 2SKD, and further tests of the final, fast key derivation function as
suits your deployment.

Once a final hash has been computed, the client application can compare the
first 16 bytes to verify that it has passed this full dress rehearsal, and
sends the last 16 bytes of the resulting hash in response to the server as
part of the password change process. The server can then verify that the client
has performed and passed its rehearsal.

Furthermore, password change interfaces should have a cryptographically secure
passphrase generator built into them. Sending a random nonce from the server
to the client can be used to protect weaknesses in the client's CSPRNG.

The client should sample from whatever cryptographically secure random sources
are on the device, of course. Ideally a client would sample both /dev/urandom
(or comparable on Windows) *and* employ RdRand or comparable CPU instructions
if available. On browsers, you'd be limited to WebCrypto's getRandomValues.
Then hash those results together with the key-stretched nonce.

The result can then be used to seed a CSPRNG to generate passphrases from
the user's choice of wordlist: ideally the user could pick from a few popular
wordlists, or supply their own. Personally I think the EFF Short Wordlist #1
is a good default, with a default passphrase length of five or six words.
-}