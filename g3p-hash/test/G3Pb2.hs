{-# LANGUAGE OverloadedStrings, LambdaCase, RecordWildCards, ViewPatterns, ScopedTypeVariables #-}

module G3Pb2 where

import Control.Exception(try)
import Control.Applicative
import Data.Aeson(Object, Value(..), parseJSON, (.:), (.:?), withObject)
import Data.Aeson.Types(Parser)
import qualified Data.Aeson as Aeson
import Data.Aeson.Key(Key)
import qualified Data.Aeson.Key as K
import Data.Aeson.KeyMap(KeyMap)
import qualified Data.Aeson.KeyMap as KM
import Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as B
import Data.Function(fix)
import Data.Int
import Data.Map(Map)
import qualified Data.Map as Map
import Data.Maybe(fromMaybe)
import Data.Text(Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.Encoding.Base16 as T
import Data.Stream(Stream(..))
import qualified Data.Stream as S
import Data.Vector(Vector, (!))
import qualified Data.Vector as V
import Data.Word

import Network.ByteOrder(word32)

import Crypto.G3P.V2
import Crypto.G3P.V2.Subtle(G3PSpark(..), G3PSeed(..))
import Crypto.PHKDF.HMAC(HmacKey, hmacKey)
import Crypto.Encoding.PHKDF(takeBs, nullBuffer)
import Test.Tasty
import Test.Tasty.HUnit

type Args = KeyMap Val

data Val
   = Int !Int64
   | Str !ByteString
   | Vec !(Vector ByteString)
   | Nul
   | Ref !TestId !Int
     deriving (Show)

data G3PArgs = G3PArgs
  { g3pArgs_salt :: !G3PSalt
  , g3pArgs_inputs :: !G3PInputs
  , g3pArgs_seedInputs :: !G3PSeedInputs
  , g3pArgs_delta :: !G3PDelta
  }

data G3PDelta = G3PDelta
  { g3pDelta_sproutSeguid :: !HmacKey
  , g3pDelta_sproutRole :: !(Vector ByteString)
  , g3pDelta_sproutTag :: !ByteString
  , g3pDelta_echoKey :: !ByteString
  , g3pDelta_echoHeader :: !ByteString
  , g3pDelta_echoCounter :: !Word32
  , g3pDelta_echoTag :: !ByteString
  }


data Result = Result
   { result_args :: !Args
   , result_hashes :: !(KeyMap ByteString)
   }

data TestVector = TestVector
   { testVector_name :: !Text
   , testVector_arguments :: !Args
   , testVector_results :: !(Vector Result)
   }

data TestId = TestId
  { testId_name :: !Text
  , testId_index :: !Int
  , testId_algorithm :: !Text
  } deriving (Eq, Ord, Show)

data SimpleTestVector = SimpleTestVector
   { simpleTestVector_id        :: !TestId
   , simpleTestVector_arguments :: !Args
   , simpleTestVector_result    :: !ByteString
   }

type TestVectors = Vector TestVector

type SimpleTestVectors = Vector SimpleTestVector

type ResultEnv = Map TestId (Either String [ByteString])

blankResult :: Result
blankResult = Result
  { result_args   = KM.empty
  , result_hashes = KM.fromList [ ("G3Pb2","") ]
  }

flattenTestVectors :: TestVectors -> SimpleTestVectors
flattenTestVectors tvs =
  V.fromList $
    [ SimpleTestVector
        { simpleTestVector_id =
            TestId { testId_name = testVector_name tv
                   , testId_index = i
                   , testId_algorithm = alg
                   }
        , simpleTestVector_arguments = args
        , simpleTestVector_result = outHash
        }
    | tv <- V.toList tvs
    , (i, res) <- zip [0..]  (seedEmpty (V.toList (testVector_results tv)))
    , let args = KM.union (result_args res) (testVector_arguments tv)
    , (K.toText -> alg, outHash) <- KM.toAscList (result_hashes res)
    ]
  where
    seedEmpty xs
      | null xs = [blankResult]
      | otherwise = map addBlankResult xs
    addBlankResult x
      | null (result_hashes x) = x { result_hashes = result_hashes blankResult }
      | otherwise = x

genResultEnv :: SimpleTestVectors -> ResultEnv
genResultEnv tvs =
  -- FIXME? The resulting scoping rules in the test vector file is analogous
  -- to Haskell or scheme's letrec, whereas I really want let* here
  fix $ \resultEnv ->
    Map.fromList $
      [ (simpleTestVector_id tv, interpret tv resultEnv)
      | tv <- V.toList tvs
      ]
  where
    interpret tv resultEnv
      | alg == "G3Pb2" =
          case getG3PArgs resultEnv args of
            Just inputs -> Right (doG3P inputs)
            Nothing -> Left "arguments not parsed"
      | alg == "G3PSpark" =
          case getG3PArgs resultEnv args of
            Just inputs -> Right (doG3PSpark inputs)
            Nothing -> Left "arguments not parsed"
      | alg == "G3PSeed" =
          case getG3PArgs resultEnv args of
            Just inputs -> Right (doG3PSeed inputs)
            Nothing -> Left "arguments not parsed"
      | otherwise = Left "algorithm name not recognized"
      where
        alg  = testId_algorithm $ simpleTestVector_id tv
        args = simpleTestVector_arguments tv

doG3P :: G3PArgs -> [ByteString]
doG3P args = S.toList (g3pStream salt inputs seedInputs sproutKey role sproutTag echoKey echoHeader echoCounter echoTag)
  where
    salt = g3pArgs_salt args
    inputs = g3pArgs_inputs args
    seedInputs = g3pArgs_seedInputs args
    delta = g3pArgs_delta args
    sproutKey = g3pDelta_sproutSeguid delta
    role = g3pDelta_sproutRole delta
    sproutTag = g3pDelta_sproutTag delta
    echoKey = g3pDelta_echoKey delta
    echoHeader = g3pDelta_echoHeader delta
    echoCounter = g3pDelta_echoCounter delta
    echoTag = g3pDelta_echoTag delta

doG3PSpark :: G3PArgs -> [ByteString]
doG3PSpark args = [g3pSpark_beginKey spark, g3pSpark_contKey spark]
  where
    salt = g3pArgs_salt args
    inputs = g3pArgs_inputs args
    spark = g3pSpark salt inputs

doG3PSeed :: G3PArgs -> [ByteString]
doG3PSeed args = [g3pSeed_seedKey seed]
  where
    salt = g3pArgs_salt args
    inputs = g3pArgs_inputs args
    seedInputs = g3pArgs_seedInputs args
    seed = g3pSeed salt inputs seedInputs

genSimpleTestCases :: SimpleTestVectors -> ResultEnv -> [ TestTree ]
genSimpleTestCases tvs resultEnv =
   [ testCase testName $ runTest tv resultEnv
   | tv <- V.toList tvs
   , let testId = simpleTestVector_id tv
         name = T.unpack (testId_name testId)
         idx = show (testId_index testId)
         alg = T.unpack (testId_algorithm testId)
         testName = name ++ " | " ++ idx ++ " " ++ alg
   ]

genTestCases :: TestVectors -> [ TestTree ]
genTestCases tvs = genSimpleTestCases stvs (genResultEnv stvs)
  where
    stvs = flattenTestVectors tvs

uncurry4 :: (a -> b -> c -> d -> e) -> (a,b,c,d) -> e
uncurry4 f (a,b,c,d) = f a b c d

instance Aeson.FromJSON Val where
    parseJSON val =
        (Int <$> parseJSON val) <|>
        (Str <$> parseJSONByteString val) <|>
        (Vec <$> parseJSONVectorByteString val) <|>
        (parseRef val) <|>
        (parseNul val)

instance Aeson.FromJSON Result where
    parseJSON = \case
        Object obj -> do
            mArgs <- obj .:? "args"
            args <- maybe (pure KM.empty) parseJSON mArgs
            hashes <- KM.traverse parseJSONHash (KM.delete "args" obj)
            pure (Result args hashes)
        _ -> empty

instance Aeson.FromJSON TestVector where
    parseJSON = withObject "TestVector" $ \v -> TestVector
        <$> v .: "name"
        <*> v .: "args"
        <*> parseResults v

takeBytes :: Int -> [ByteString] -> ByteString
takeBytes n stream = B.concat (go n stream)
  where
    go n _ | n <= 0 = []
    go _ [] = []
    go n (out : outStream')
      | n <= B.length out = [B.take n out]
      | otherwise = out : go (n - B.length out) outStream'

parseRef :: Value -> Parser Val
parseRef = \case
  Object obj -> do
    ref <- obj .: "ref"
    len <- obj .: "len"
    mAlg <- obj .:? "algorithm"
    mIdx <- obj .:? "index"
    let alg = fromMaybe "G3Pb2" mAlg
        idx = fromMaybe 0 mIdx
        testId = TestId ref idx alg
    return $ Ref testId len
  _ -> empty

parseNul :: Value -> Parser Val
parseNul = \case
  Null -> return Nul
  _ -> empty

parseJSONByteString :: Value -> Parser ByteString
parseJSONByteString = \case
    String txt -> pure (T.encodeUtf8 txt)
    Object obj | KM.size obj == 1 -> do
        txt <- obj .: "hex"
        case B.decodeBase16 (T.encodeUtf8 txt) of
          Left _ -> empty
          Right x -> pure x
    _ -> empty

parseJSONVectorByteString :: Value -> Parser (Vector ByteString)
parseJSONVectorByteString val =
    (V.singleton <$> parseJSONByteString val) <|>
    case val of
      Array bs -> V.generateM (V.length bs) (\i -> parseJSONByteString (bs ! i))
      _ -> empty

parseJSONHash :: Value -> Parser ByteString
parseJSONHash = \case
    String txt ->
        case B.decodeBase16 (T.encodeUtf8 txt) of
            Left _ -> empty
            Right x -> pure x
    _ -> empty

parseResults :: Object -> Parser (Vector Result)
parseResults v =
    case KM.lookup "results" v of
        Nothing -> pure V.empty
        Just v@(Object _) ->
            V.singleton <$> parseJSON v
        Just (Array v) ->
            V.generateM (V.length v) (\i -> parseJSON (v ! i))
        _ -> empty

readTestVectorsFromFile :: String -> IO (String, Either String TestVectors)
readTestVectorsFromFile fileName =
    try (Aeson.eitherDecodeFileStrict' fileName) >>= \case
        Left (err :: IOError) -> return (fileName, Left (show err))
        Right result -> return (fileName, result)

testVectorDefaultFileName :: String
testVectorDefaultFileName = "g3p-test-vectors.json"

testFile :: (String, Either String TestVectors) -> TestTree
testFile (fileName, mTestVectors) =
    case mTestVectors of
      Left err -> testCase testName $ assertFailure err
      Right tvs -> testGroup testName $ genTestCases tvs
  where
    testName = "testfile: " ++ fileName

runTest :: SimpleTestVector -> ResultEnv -> Assertion
runTest tv resultEnv =
  case Map.lookup (simpleTestVector_id tv) resultEnv of
    Nothing -> assertFailure "test result not found (this shouldn't be possible)"
    Just (Left err) -> assertFailure err
    Just (Right result) -> compareAu alg goldenOutput result
  where
    alg = T.unpack . testId_algorithm $ simpleTestVector_id tv
    goldenOutput = simpleTestVector_result tv

compareAu :: String -> ByteString -> [ByteString] -> Assertion
compareAu name bs outStream
  | B.null bs = assertFailure ("\"" ++ name ++ "\":\"" ++ concatMap toHex (take 4 outStream) ++ "\"")
  | otherwise = B.encodeBase16 (takeBytes (B.length bs) outStream) @?= B.encodeBase16 bs
  where
    toHex = T.unpack . B.encodeBase16

-- FIXME? Allow computation of tweaks without recomputing seed

getG3PArgs :: ResultEnv -> KeyMap Val -> Maybe G3PArgs
getG3PArgs env = \case
  (getG3PSalt env -> Just (salt,
   getG3PInputs env -> Just (inputs,
   getG3PSeedInputs env -> Just (seedInputs,
   getG3PDelta env -> Just (delta,
   args'))))) | KM.null args'
    -> Just (G3PArgs salt inputs seedInputs delta)
  _ -> Nothing

getG3PSalt :: ResultEnv -> KeyMap Val -> Maybe (G3PSalt, KeyMap Val)
getG3PSalt env = \case
  (matchKey' env "domain-tag" -> (Just (Str g3pSalt_domainTag),
   matchKey' env "seguid" -> (getByteString_defaultEmpty -> Just (hmacKey -> g3pSalt_seguid),
   matchKey' env "long-tag" -> (getMaybeByteString -> Just mLongTag,
   matchKey' env "tags" -> (getMaybeByteStringVector -> Just mTags,
   matchKey env "context-tags" -> (getMaybeByteStringVector -> Just mCtxTags,
   matchKey env "phkdf-rounds" -> (Just (Int (fromIntegral -> g3pSalt_phkdfRounds)),
   args')))))))
   -> let g3pSalt_contextTags = fromMaybe (fromMaybe V.empty mTags) mCtxTags
          g3pSalt_longTag = fromMaybe g3pSalt_domainTag mLongTag
       in Just (G3PSalt {..}, args')
  _ -> Nothing

getG3PInputs :: ResultEnv -> KeyMap Val -> Maybe (G3PInputs, KeyMap Val)
getG3PInputs env = \case
  (matchKey env "username" -> (Just (Str g3pInputs_username),
   matchKey env "password" -> (Just (Str g3pInputs_password),
   matchKey env "credentials" -> (
     getByteStringVector_defaultEmpty -> Just g3pInputs_credentials,
   args'))))
    -> Just (G3PInputs {..}, args')
  _ -> Nothing

getG3PSeedInputs :: ResultEnv -> KeyMap Val -> Maybe (G3PSeedInputs, KeyMap Val)
getG3PSeedInputs env = \case
  (matchKey' env "domain-tag" -> (getMaybeByteString -> Just mDomainTag,
   matchKey' env "bcrypt-domain-tag" -> (getMaybeByteString -> Just mBcryptDomainTag,
   matchKey' env "seguid" -> (getMaybeByteString -> Just mSeguid,
   matchKey' env "bcrypt-seguid" -> (getMaybeByteString -> Just mBcryptSeguid,
   matchKey  env "long-tag" -> (getMaybeByteString -> Just mLongTag,
   matchKey  env "bcrypt-long-tag" -> (getMaybeByteString -> Just mBcryptLongTag,
   matchKey' env "tags" -> (getMaybeByteStringVector -> Just mTags,
   matchKey env "bcrypt-context-tags" -> (getMaybeByteStringVector -> Just mCtxTags,
   matchKey env "bcrypt-rounds" -> (Just (Int (fromIntegral -> g3pSeedInputs_bcryptRounds)),
   args'))))))))))
   -> let g3pSeedInputs_bcryptKey = hmacKey (fromMaybe (fromMaybe B.empty mSeguid) mBcryptSeguid)
          g3pSeedInputs_bcryptContextTags = fromMaybe (fromMaybe V.empty mTags) mCtxTags
          g3pSeedInputs_bcryptDomainTag = fromMaybe (fromMaybe B.empty mDomainTag) mBcryptDomainTag
          g3pSeedInputs_bcryptLongTag = fromMaybe (fromMaybe B.empty mLongTag) mBcryptLongTag
       in Just (G3PSeedInputs {..}, args')
  _ -> Nothing

getG3PDelta :: ResultEnv -> KeyMap Val -> Maybe (G3PDelta, KeyMap Val)
getG3PDelta env = \case
  (matchKey env "seguid" -> (getMaybeByteString -> Just mSeguid,
   matchKey env "bcrypt-seguid" -> (getMaybeByteString -> Just mBcryptSeguid,
   matchKey env "sprout-seguid" -> (getMaybeByteString -> Just mSproutSeguid,
   matchKey env "tags" -> (getMaybeByteStringVector -> Just mTags,
   matchKey env "role" -> (getMaybeByteStringVector -> Just mRole,
   matchKey env "domain-tag" -> (getMaybeByteString -> Just mDomainTag,
   matchKey env "bcrypt-domain-tag" -> (getMaybeByteString -> Just mBcryptDomainTag,
   matchKey env "sprout-tag" -> (getMaybeByteString -> Just mSproutTag,
   matchKey env "echo-key" -> (getMaybeByteString -> Just mEchoKey,
   matchKey env "echo-header" -> (getMaybeByteString -> Just mEchoHeader,
   matchKey env "echo-counter" -> (getEchoCounter -> Just g3pDelta_echoCounter,
   matchKey env "echo-tag" -> (getMaybeByteString -> Just mEchoTag,
   args')))))))))))))
   -> let g3pDelta_sproutSeguid = hmacKey (fromMaybe (fromMaybe (fromMaybe B.empty mSeguid) mBcryptSeguid) mSproutSeguid)
          g3pDelta_sproutRole = fromMaybe (fromMaybe V.empty mTags) mRole
          g3pDelta_sproutTag = fromMaybe (fromMaybe (fromMaybe B.empty mDomainTag) mBcryptDomainTag) mSproutTag
          g3pDelta_echoKey = fromMaybe g3pDelta_echoHeader mEchoKey
          g3pDelta_echoHeader = fromMaybe g3pDelta_sproutTag mEchoHeader
          g3pDelta_echoTag = fromMaybe g3pDelta_sproutTag mEchoTag
       in Just (G3PDelta {..}, args')
  _ -> Nothing

defaultEchoCounter :: Word32
defaultEchoCounter = word32 "OUT\x00"

getEchoCounter :: Maybe Val -> Maybe Word32
getEchoCounter = \case
  Nothing -> Just defaultEchoCounter
  Just Nul -> Just defaultEchoCounter
  Just (Int ctr)
      | 0 <= ctr && ctr <= fromIntegral (maxBound :: Word32)
        -> Just (fromIntegral ctr)
      | otherwise -> Nothing
  Just (Str str) ->
      if B.length str <= 4
      then Just (word32 (B.concat (takeBs 4 [str, nullBuffer])))
      else Nothing
  _ -> Nothing




getByteStringVector_defaultEmpty :: Maybe Val -> Maybe (Vector ByteString)
getByteStringVector_defaultEmpty = \case
  Nothing -> Just V.empty
  Just Nul -> Just V.empty
  Just (Str str) -> Just (V.singleton str)
  Just (Vec vec) -> Just vec
  _ -> Nothing

getMaybeByteStringVector :: Maybe Val -> Maybe (Maybe (Vector ByteString))
getMaybeByteStringVector = \case
  Nothing -> Just Nothing
  Just Nul -> Just Nothing
  Just (Str str) -> Just (Just (V.singleton str))
  Just (Vec vec) -> Just (Just vec)
  _ -> Nothing

getByteString_defaultEmpty :: Maybe Val -> Maybe ByteString
getByteString_defaultEmpty
  = fmap (fromMaybe B.empty) . getMaybeByteString

getByteString :: Maybe Val -> Maybe ByteString
getByteString = \case
  Just (Str str) -> Just str
  _ -> Nothing

getMaybeByteString :: Maybe Val -> Maybe (Maybe ByteString)
getMaybeByteString = \case
  Just (Str str) -> Just (Just str)
  Just Nul -> Just Nothing
  Nothing -> Just Nothing
  _ -> Nothing

matchKey, matchKey' :: ResultEnv -> Key -> KeyMap Val -> (Maybe Val, KeyMap Val)
matchKey env key map = (interpRefs env (KM.lookup key map), KM.delete key map)
matchKey' env key map = (interpRefs env (KM.lookup key map), map)

interpRefs :: ResultEnv -> Maybe Val -> Maybe Val
interpRefs env (Just ref@(Ref testId bytes)) =
  case Map.lookup testId env of
    Nothing -> Just ref
    Just (Left _) -> Just ref
    Just (Right echo) -> Just (Str (takeBytes bytes echo))
interpRefs _   val = val
