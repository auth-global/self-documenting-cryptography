{-# LANGUAGE OverloadedStrings, OverloadedLists, PackageImports #-}

import Crypto.G3P
import qualified Data.Stream as S
import qualified "base16" Data.ByteString.Base16 as B

yb1 = G3PInputBlock
  { g3pInputBlock_domainTag = "1-800-CALL-SPY"
  , g3pInputBlock_seguid = ""
  , g3pInputBlock_longTag = "Please leave the location of America's nuclear wessels after the beep."
  , g3pInputBlock_tags = []
  , g3pInputBlock_phkdfRounds = 20240
  , g3pInputBlock_bcryptRounds = 4095
  , g3pInputBlock_bcryptTag = "1-800-CALL-SPY"
  , g3pInputBlock_bcryptSaltTag = "1-800-CALL-SPY"
  }

ya1 = G3PInputArgs
  { g3pInputArgs_username = "Yuri"
  , g3pInputArgs_password = "default remote access code"
  , g3pInputArgs_credentials = []
  }

yt1 = G3PInputTweak
  { g3pInputTweak_role = []
  , g3pInputTweak_tags = []
  }

nb1 = G3PInputBlock
  { g3pInputBlock_domainTag = ""
  , g3pInputBlock_seguid = ""
  , g3pInputBlock_longTag = ""
  , g3pInputBlock_tags = []
  , g3pInputBlock_phkdfRounds = 0
  , g3pInputBlock_bcryptRounds = 0
  , g3pInputBlock_bcryptTag = ""
  , g3pInputBlock_bcryptSaltTag = ""
  }

na1 = G3PInputArgs
  { g3pInputArgs_username = ""
  , g3pInputArgs_password = ""
  , g3pInputArgs_credentials = []
  }

nt1 = G3PInputTweak
  { g3pInputTweak_role = []
  , g3pInputTweak_tags = []
  }
