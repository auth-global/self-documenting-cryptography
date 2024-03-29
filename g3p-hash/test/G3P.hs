{-# LANGUAGE OverloadedStrings, LambdaCase, RecordWildCards, ViewPatterns, ScopedTypeVariables #-}

module G3P where

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

import Crypto.G3P
import Test.Tasty
import Test.Tasty.HUnit

type Args = KeyMap Val

data Val
   = Int !Int
   | Str !ByteString
   | Vec !(Vector ByteString)
   | Nul
   | Ref !TestId !Int
     deriving (Show)

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

type ResultEnv = Map TestId (Either String (Stream ByteString))

blankResult :: Result
blankResult = Result
  { result_args   = KM.empty
  , result_hashes = KM.fromList [ ("G3Pb1","") ]
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
      | alg == "G3Pb1" =
          case getG3PInputs resultEnv args of
            Just inputs -> Right (uncurry4 g3pHash inputs)
            Nothing -> Left "arguments not parsed"
      | otherwise = Left "algorithm name not recognized"
      where
        alg  = testId_algorithm $ simpleTestVector_id tv
        args = simpleTestVector_arguments tv

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

takeBytes :: Int -> Stream ByteString -> ByteString
takeBytes n stream = B.concat (go n stream)
  where
    go n ~(Cons out outStream')
      | n <= 0 = []
      | n <= B.length out = [B.take n out]
      | otherwise = out : go (n - B.length out) outStream'

parseRef :: Value -> Parser Val
parseRef = \case
  Object obj -> do
    ref <- obj .: "ref"
    len <- obj .: "len"
    mAlg <- obj .:? "algorithm"
    mIdx <- obj .:? "index"
    let alg = fromMaybe "G3Pb1" mAlg
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

compareAu :: String -> ByteString -> Stream ByteString -> Assertion
compareAu name bs outStream
  | B.null bs = assertFailure ("\"" ++ name ++ "\":\"" ++ concatMap toHex (S.take 4 outStream) ++ "\"")
  | otherwise = B.encodeBase16 (takeBytes (B.length bs) outStream) @?= B.encodeBase16 bs
  where
    toHex = T.unpack . B.encodeBase16

-- FIXME? Allow computation of tweaks without recomputing seed

getG3PInputs :: ResultEnv -> KeyMap Val -> Maybe (G3PInputBlock, G3PInputArgs, G3PInputRole, G3PInputEcho)
getG3PInputs env = \case
  (getG3PBlock env -> Just (block,
   getG3PArgs env -> Just (args,
   getG3PRole env -> Just (role,
   getG3PEcho env -> Just (echo,
   args'))))) | KM.null args'
    -> Just (block, args, role, echo)
  _ -> Nothing

getG3PArgs :: ResultEnv -> KeyMap Val -> Maybe (G3PInputArgs, KeyMap Val)
getG3PArgs env = \case
  (matchKey env "username" -> (Just (Str g3pInputArgs_username),
   matchKey env "password" -> (Just (Str g3pInputArgs_password),
   matchKey env "credentials" -> (
     getByteStringVector_defaultEmpty -> Just g3pInputArgs_credentials,
   args'))))
    -> Just (G3PInputArgs {..}, args')
  _ -> Nothing

getByteStringVector_defaultEmpty :: Maybe Val -> Maybe (Vector ByteString)
getByteStringVector_defaultEmpty = \case
  Nothing -> Just V.empty
  Just Nul -> Just V.empty
  Just (Str str) -> Just (V.singleton str)
  Just (Vec vec) -> Just vec
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

getG3PBlock :: ResultEnv -> KeyMap Val -> Maybe (G3PInputBlock, KeyMap Val)
getG3PBlock env = \case
  (matchKey' env "domain-tag" -> (Just (Str g3pInputBlock_domainTag),
   matchKey env "seguid" -> (getByteString_defaultEmpty -> Just g3pInputBlock_seguid,
   matchKey env "long-tag" -> (getMaybeByteString -> Just mLongTag,
   matchKey env "tags" -> (getByteStringVector_defaultEmpty -> Just tags,
   matchKey env "seed-tags" -> (getByteStringVector_defaultEmpty -> Just seedTags,
   matchKey env "phkdf-rounds" -> (Just (Int (fromIntegral -> g3pInputBlock_phkdfRounds)),
   matchKey env "bcrypt-rounds" -> (Just (Int (fromIntegral -> g3pInputBlock_bcryptRounds)),
   matchKey env "bcrypt-tag" -> (getMaybeByteString -> Just mBcryptTag,
   matchKey env "bcrypt-salt-tag" -> (getMaybeByteString -> Just mBcryptSaltTag,
   args'))))))))))
   -> let g3pInputBlock_tags = tags <> seedTags
          g3pInputBlock_longTag = fromMaybe g3pInputBlock_domainTag mLongTag
          g3pInputBlock_bcryptTag = fromMaybe g3pInputBlock_domainTag mBcryptTag
          g3pInputBlock_bcryptSaltTag = fromMaybe g3pInputBlock_bcryptTag mBcryptSaltTag
       in Just (G3PInputBlock {..}, args')
  _ -> Nothing

getG3PRole :: ResultEnv -> KeyMap Val -> Maybe (G3PInputRole, KeyMap Val)
getG3PRole env = \case
  (matchKey env "role" -> (getByteStringVector_defaultEmpty -> Just roleTags,
   args'))
   -> Just (G3PInputRole roleTags, args')
  _ -> Nothing

getG3PEcho :: ResultEnv -> KeyMap Val -> Maybe (G3PInputEcho, KeyMap Val)
getG3PEcho env = \case
  (matchKey env "echo-tag" -> (getMaybeByteString -> Just mEchoTag,
   matchKey env "domain-tag" -> (getByteString -> Just domainTag,
   args')))
   -> let echoTag = fromMaybe domainTag mEchoTag
       in Just (G3PInputEcho echoTag, args')
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
