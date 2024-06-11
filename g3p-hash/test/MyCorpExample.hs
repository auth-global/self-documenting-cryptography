{-# LANGUAGE OverloadedStrings #-}

-- TODO: get the JSON test harness capable of handling partial evaluation
-- TODO: actually set up haddock example testing

module MyCorpExample where

import Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as B
import Data.Text(Text)
import Data.Vector()
import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.Vector as V

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
      userRandomSalt = "60473b8010e16d46"
      userSecondSecretHash = "0c06f683f093cb899b4a1e9836fc7281"
      mySalt =
        G3PSalt {
          g3pSalt_seguid = mySeguid,
          g3pSalt_longTag = myLongTag,
          g3pSalt_contextTags = V.singleton userRandomSalt,
          g3pSalt_domainTag = myDomain,
          g3pSalt_phkdfRounds = 20240
        }
      myInputs =
        G3PInputs {
          g3pInputs_username = userRandomSalt,
          g3pInputs_password = "correct horse battery staple",
          g3pInputs_credentials = V.singleton userSecondSecretHash
        }
      mySeedInputs =
        G3PSeedInputs {
          g3pSeedInputs_bcryptSeguid = mySeguid,
          g3pSeedInputs_bcryptCredentials = V.empty,
          g3pSeedInputs_bcryptLongTag = myLongTag,
          g3pSeedInputs_bcryptContextTags = V.empty,
          g3pSeedInputs_bcryptDomainTag = myDomain,
          g3pSeedInputs_bcryptRounds = 4202
        }
      mySprout = g3pHash mySalt myInputs mySeedInputs mySeguid
      myHeader = userRandomSalt <> myDomain
      myAuthPrehash =
        mySprout ["auth",userRandomSalt] myLoginDomain
                 myHeader myHeader (word32 "AUTH") myLongTag

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

      mySecretSeguid = hmacKey "7db250698fe555f6832f33189f97e14ef3c1c2dcada5807119aa7676c24f3fac"

      -- The use of secret seguids allows My Corp to prove that its secret
      -- keys are in fact its trade secrets even in the face of the most dogged
      -- liars. Moreover this fact can possibly remain plausibly deniable even
      -- after the secret seguid's derivation has been stolen and published, so
      -- neither does this necessarily commit My Corp to claiming its secrets.

      -- Deriving a secret HMAC key per account allows My Corp to outsource
      -- offline cracking attacks on individual accounts without revealing an
      -- offline cracking attack on every account.

      -- Moreover g3pTangoSalt allows the proof-of-trade-secret to also be
      -- revealed/claimed on a per-account basis, without publicly tying the
      -- proof-of-trade-secret to a specific userRandomSalt. This latter
      -- proof-of-trade-secret is of course implicitly tied to a specific
      -- userRandomSalt, but it need not be tied in an explicit, public way.

      mySecretSalt = g3pTangoSalt mySecretSeguid [userRandomSalt] myLoginDomain myLoginDomain

      myFoxtrot input ctr = phkdfGen_head $ g3pFoxtrot (G3PFoxtrotSalt
        { g3pFoxtrotSalt_secretSalt = hmacKey (mySecretSalt <> B.take 32 myHeader)      , g3pFoxtrotSalt_longTag = myLongTag
        , g3pFoxtrotSalt_contextTags = V.singleton userRandomSalt
        , g3pFoxtrotSalt_domainTag = myLoginDomain
        , g3pFoxtrotSalt_bcryptRounds = 383
        }) input [userRandomSalt] [] ctr

      myArgon2 = hash $ HashOptions
        { hashIterations = 3
        , hashMemory = 384 * 1024 -- 384 MiB
        , hashParallelism = 1
        , hashVariant = Argon2id
        , hashVersion = Argon2Version13
        , hashLength = 32
        }

      myPrestoreHash = myFoxtrot ("P" <> myAuthPrehash) (word32 "PASS")
      (Right myArgon2Hash) = myArgon2 userRandomSalt (myPrestoreHash <> myLongTag)
      myStorageHash = myFoxtrot ("A" <> myArgon2Hash) (word32 "HASH")

      -- Then, if this server-side authentication flow is successful, the auth
      -- server returns a storage key for the account, allowing end-to-end
      -- encrypted files to be unlocked.  Note that the closure of @mySprout@
      -- contains the prehash seed, so this storage key is useless on it's own,
      -- and the authentication server never gains the information needed to
      -- unlock the files without first guessing "correct horse battery staple".

      -- For contrast, an attacker who has only has access to the user's
      -- encrypted files would not necessarily be able to confirm or deny that
      -- the user's password is "correct horse battery staple", unless the user
      -- has a backup method to unlock that particular file without talking to
      -- the auth server, and that backup method is the user's reused password.

      myDiskKey = mySprout
                     ["disk",myStorageDomain,myLongTag,
                      "key","7014dad47f0e7f7157d99b39a06553ce"]
                     myStorageDomain myHeader myHeader (word32 "DISK")
   in [ myAuthPrehash
      , myStorageHash
      , myDiskKey "filename0.txt"
      , myDiskKey "quarterly-report.pdf"
      ]

auResults :: [Text]
auResults =
  [ "3759cc63959878c79e9077f7c8dc401cad1700e03bab7ca52ef2982553c37197"
  , "daae3f4695cf91a4a75aa9389eda00ff10396db5790fa1d4a724801773fd6d5a"
  , "d0a3b6c432b6b612fb82a60554fa3fa906e8a4cc324c6f1de38e52d8eec254cf"
  , "c2fb84c71dbe52280bd0d481c770e4e476a5e0daeeddc3e9eee00423bef9a7e4"
  ]
