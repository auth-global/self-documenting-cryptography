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
      -- If your deployment uses a public salt server, I recommend keeping
      -- random salts directly in a database. More specifically, I do not
      -- recommend deriving public salts from non-public information, as an
      -- evesdropper could use this as evidence that they have actually
      -- compromised your stuff. Or, your deployment could apply key-stretching
      -- to a login name to derive a salt in a transparent way, avoiding the
      -- pitfalls of running a public salt server.

      userPublicSalt = "60473b8010e16d46"
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
      -- of a hypothetical deployment combines two somewhat crude but effective
      -- strategies:
      --
      --   1. The auth servers perform the main key-stretching computation, and
      --
      --   2. The auth servers perform this computation behind a secret HMAC key

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
      -- non-public information without directly providing an evedropper the
      -- ability to prove to others they've been in your infrastructure.

      -- However, I would still recommend always storing a random secret per
      -- account so that an evesdropper cannot steal your entire secret salt
      -- database, possibly including secret salts that aren't yet in use,
      -- by stealing a single key. On the other hand, deriving the secret salt
      -- using a relatively small number of keys stored outside the database
      -- means that even if somebody steals your auth database, they won't
      -- necessarily have access to your secret salts.

      mySecretSeguid = hmacKey "7db250698fe555f6832f33189f97e14ef3c1c2dcada5807119aa7676c24f3fac"

      userPrivateSeed = "4314a11c2620a8ad"
      userPrivatePreSalt = g3pTango mySecretSeguid [userPrivateSeed,userPublicSalt, "user private presalt"] (word32 "SALT") myLoginDomain
      userPrivateSalt = g3pTango mySeguid [userPrivatePreSalt, "user private salt"] (word32 "SALT") myLoginDomain

      -- This derivation scheme allows My Corp to prove that its secret
      -- salts are in fact its trade secrets even in the face of the most dogged
      -- liars. Moreover this fact can possibly remain plausibly deniable even
      -- after the derivation has been stolen and published, so neither does
      -- this necessarily commit My Corp to claiming its secrets.

      -- Deriving a secret HMAC key per account allows My Corp to outsource
      -- offline cracking attacks on individual accounts without revealing an
      -- offline cracking attack on every account.

      -- Moreover, this derivation allows the proof-of-trade-secret to also be
      -- revealed/claimed on a per-account basis.

      foxtrot = g3pFoxtrot (G3PFoxtrotSalt
        { g3pFoxtrotSalt_key = hmacKey (userPrivateSalt <> B.take 32 userHeader)
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

      userPrestoreHash = foxtrot ("P" <> userAuthPrehash) [] (word32 "PASS")
      (Right userArgon2Hash) = argon2 userRandomSalt (userPrestoreHash <> myLongTag)
      foxtrot' = foxtrot ("A" <> userArgon2Hash)
      userStoredHash = foxtrot' [] (word32 "HASH")

      -- userStoredHash is suitable to be stored in an auth database, and
      -- subsequent authentication attempts can compare this hash against the
      -- database. If this authentication is successful, we can efficiently
      -- compute a storage key that includes all of the key-stretching work
      -- performed thus far:

      userStorageKey = foxtrot' ["storage-key"] (word32 "KEY\x00")

      -- Note that this storage key will be re-combined with the original
      -- client-side seed before end-to-end encrypted files can be unlocked.
      -- The storage key is useless on its own, and therefore the auth server
      -- never gains the information needed to unlock the files without first
      -- guessing "correct horse battery staple".

      -- An attacker who has access to the user's encrypted files but does not
      -- have that user's secret server-side salt would not be able to confirm
      -- or deny that the user's password is "correct horse battery staple",
      -- unless the user has a backup method to unlock that particular file
      -- without talking to the auth server, and that backup method is the
      -- user's reused password.

      userDiskKey = mySprout
                      ["disk",myStorageDomain,myLongTag,
                      "key",userStorageKey]
                     myStorageDomain userHeader userHeader (word32 "DISK")

      -- myLongTag is included above because it is sufficiently long to be able
      -- to commit to the "disk" and myStorageDomain values by partially
      -- evalating the sprout and then forgetting the seed.

   in [ userAuthPrehash
      , userStoredHash
      , userDiskKey "filename0.txt"
      , userDiskKey "quarterly-report.pdf"
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
