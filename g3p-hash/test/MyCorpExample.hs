{-# LANGUAGE OverloadedStrings, OverloadedLists #-}

-- TODO: get the JSON test harness capable of handling partial evaluation
-- TODO: actually set up haddock example testing

module MyCorpExample where

import Data.ByteString(ByteString)
import Data.Text(Text)
import Data.Vector()
import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString.Base16 as B

import Crypto.G3P.V2
import Crypto.PHKDF.HMAC(hmacKey)

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
          g3pSalt_contextTags = [userRandomSalt],
          g3pSalt_domainTag = myDomain,
          g3pSalt_phkdfRounds = 20240
        }
      myInputs =
        G3PInputs {
          g3pInputs_username = userRandomSalt,
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
      mySprout = g3pHash mySalt myInputs mySeedInputs mySeguid
      myHeader = userRandomSalt <> myDomain
      myAuthKey = mySprout ["auth",userRandomSalt]
                      myLoginDomain myHeader myHeader (word32 "AUTH")
      myDiskKey = mySprout (["disk",myStorageDomain,myLongTag,"key","7014dad47f0e7f7157d99b39a06553ce"] :: [ByteString])
                     myStorageDomain myHeader myHeader (word32 "DISK")
   in [ myAuthKey myLongTag
      , myDiskKey "filename0.txt"
      , myDiskKey "quarterly-report.pdf"
      ]

auResults :: [Text]
auResults =
  [ "3759cc63959878c79e9077f7c8dc401cad1700e03bab7ca52ef2982553c37197"
  , "d0a3b6c432b6b612fb82a60554fa3fa906e8a4cc324c6f1de38e52d8eec254cf"
  , "c2fb84c71dbe52280bd0d481c770e4e476a5e0daeeddc3e9eee00423bef9a7e4"
  ]
