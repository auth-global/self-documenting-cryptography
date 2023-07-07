{-# LANGUAGE OverloadedStrings, LambdaCase, RecordWildCards, ViewPatterns, ScopedTypeVariables #-}

module PHKDF where

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

import Debug.Trace

import Crypto.PHKDF
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
  , result_hashes = KM.fromList [ ("phkdf-pass",""),("phkdf-simple","") ]
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
      | alg == "phkdf-pass" =
          case getPhkdfPassInputs resultEnv args of
            Just inputs -> Right (uncurry3 phkdfPass inputs)
            Nothing -> Left "arguments not parsed"
      | alg == "phkdf-simple" =
          case getPhkdfSimpleInputs resultEnv args of
            Just inputs -> Right (uncurry phkdfSimple inputs)
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

uncurry3 :: (a -> b -> c -> d) -> (a,b,c) -> d
uncurry3 f (a,b,c) = f a b c

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

parseRef :: Value -> Parser Val
parseRef = \case
  Object obj -> do
    ref <- obj .: "ref"
    len <- obj .: "len"
    mAlg <- obj .:? "algorithm"
    mIdx <- obj .:? "index"
    let alg = fromMaybe "phkdf-pass" mAlg
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
testVectorDefaultFileName = "phkdf-test-vectors.json"

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
  | B.null bs = assertFailure ("\"" ++ name ++ "\":\"" ++ concatMap toHex (S.take 2 outStream) ++ "\"")
  | otherwise = B.encodeBase16 (takeBytes (B.length bs) outStream) @?= B.encodeBase16 bs
  where
    toHex = T.unpack . B.encodeBase16

takeBytes :: Int -> Stream ByteString -> ByteString
takeBytes n stream = B.concat (go n stream)
  where
    go n ~(Cons out outStream')
      | n <= 0 = []
      | n <= B.length out = [B.take n out]
      | otherwise = out : go (n - B.length out) outStream'

-- FIXME? Allow computation of tweaks without recomputing seed

-- I initially liked this ViewPattern approach to high-level parsing, but now
-- I don't, because of error messages and ResultEnv handling

-- TODO: Rewrite getPhkdf*Inputs and their helpers

getPhkdfPassInputs :: ResultEnv -> KeyMap Val -> Maybe (PhkdfInputBlock, PhkdfInputArgs, PhkdfInputTweak)
getPhkdfPassInputs env = \case
  (getPhkdfPassBlock env -> Just (block,
   getPhkdfPassArgs env -> Just (args,
   getPhkdfPassTweak env -> Just (tweak,
   args')))) | KM.null args'
    -> Just (block, args, tweak)
  _ -> Nothing

getPhkdfSimpleInputs :: ResultEnv -> KeyMap Val -> Maybe (PhkdfInputBlock, PhkdfInputArgs)
getPhkdfSimpleInputs env = \case
  (getPhkdfSimpleBlock env -> Just (block,
   getPhkdfSimpleArgs env -> Just (args,
   args'))) | KM.null args'
    -> Just (block, args)
  _ -> Nothing

getPhkdfPassArgs :: ResultEnv -> KeyMap Val -> Maybe (PhkdfInputArgs, KeyMap Val)
getPhkdfPassArgs env = \case
  (matchKey env "username" -> (Just (Str phkdfInputArgs_username),
   matchKey env "password" -> (Just (Str phkdfInputArgs_password),
   matchKey env "credentials" -> (
     getByteStringVector_defaultEmpty -> Just phkdfInputArgs_credentials,
   args'))))
    -> Just (PhkdfInputArgs {..}, args')
  _ -> Nothing

getPhkdfSimpleArgs :: ResultEnv -> KeyMap Val -> Maybe (PhkdfInputArgs, KeyMap Val)
getPhkdfSimpleArgs env = \case
  (getPhkdfPassArgs env -> Just (inputArgs,
   matchKey env "role" -> (getByteStringVector_defaultEmpty -> Just role,
   args')))
    -> let creds = phkdfInputArgs_credentials inputArgs
           inputArgs' = inputArgs {
               phkdfInputArgs_credentials = creds <> role
             }
        in Just (inputArgs' , args')
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

getPhkdfPassBlock :: ResultEnv -> KeyMap Val -> Maybe (PhkdfInputBlock, KeyMap Val)
getPhkdfPassBlock env = \case
  (matchKey env "domain-tag" -> (Just (Str phkdfInputBlock_domainTag),
   matchKey env "seguid" -> (getByteString_defaultEmpty -> Just phkdfInputBlock_seguid,
   matchKey env "long-tag" -> (getMaybeByteString -> Just mLongTag,
   -- use matchKey' to leave the "tags" argument behind for getPhkdfPassTweak
   matchKey' env "tags" -> (getByteStringVector_defaultEmpty -> Just tags,
   matchKey env "seed-tags" -> (getByteStringVector_defaultEmpty -> Just seedTags,
   matchKey env "rounds" -> (Just (Int (fromIntegral -> phkdfInputBlock_rounds)),
   args')))))))
    -> let phkdfInputBlock_tags = tags <> seedTags
           phkdfInputBlock_longTag = fromMaybe phkdfInputBlock_domainTag mLongTag
        in Just (PhkdfInputBlock {..}, args')
  _ -> Nothing

getPhkdfSimpleBlock :: ResultEnv -> KeyMap Val -> Maybe (PhkdfInputBlock, KeyMap Val)
getPhkdfSimpleBlock env = \case
  (getPhkdfPassBlock env -> Just (block,
   matchKey env "echo-tags" -> (getByteStringVector_defaultEmpty -> Just echoTags,
    args')))
    -> let block' = block {
               phkdfInputBlock_tags = phkdfInputBlock_tags block <> echoTags
             }
        in Just (block', KM.delete "tags" args')
  _ -> Nothing

getPhkdfPassTweak :: ResultEnv -> KeyMap Val -> Maybe (PhkdfInputTweak, KeyMap Val)
getPhkdfPassTweak env = \case
  (matchKey env "role" -> (getByteStringVector_defaultEmpty -> Just phkdfInputTweak_role,
   matchKey env "tags" -> (getByteStringVector_defaultEmpty -> Just tags,
   matchKey env "echo-tags" -> (getByteStringVector_defaultEmpty -> Just echoTags,
   args'))))
    -> let phkdfInputTweak_tags = tags <> echoTags
        in Just (PhkdfInputTweak{..}, args')
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
