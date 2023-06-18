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
import Data.Maybe(fromMaybe)
import Data.Text(Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.Encoding.Base16 as T
import Data.Stream(Stream(..))
import qualified Data.Stream as S
import Data.Vector(Vector, (!))
import qualified Data.Vector as V

import Crypto.PHKDF
import Test.Tasty
import Test.Tasty.HUnit

type Args = KeyMap Val

data Val
   = Int !Int
   | Str !ByteString
   | Vec !(Vector ByteString)
   | Nul

data Result = Result
   { result_args :: !Args
   , result_hashes :: !(KeyMap ByteString)
   }

data TestVector = TestVector
   { testVector_name :: !Text
   , testVector_args :: !Args
   , testVector_results :: !(Vector Result)
   }

type TestVectors = Vector TestVector

blankResult :: Result
blankResult = Result
  { result_args   = KM.empty
  , result_hashes = KM.fromList [ ("phkdf-pass",""),("phkdf-simple","") ]
  }

genTestCases :: TestVectors -> [ TestTree ]
genTestCases tvs =
    [ testCase testName $ runTest alg args outHash
    | tv <- V.toList tvs
    , (i, res) <- zip [0..]  (seedEmpty (V.toList (testVector_results tv)))
    , let args = KM.union (result_args res) (testVector_args tv)
    , (alg, outHash) <- KM.toAscList (result_hashes res)
    , let testName = T.unpack (testVector_name tv) ++ " | " ++ K.toString alg ++ " " ++ show i
    ]
  where
    seedEmpty xs = if null xs then [blankResult] else xs

uncurry3 :: (a -> b -> c -> d) -> (a,b,c) -> d
uncurry3 f (a,b,c) = f a b c

instance Aeson.FromJSON Val where
    parseJSON val =
        (Int <$> parseJSON val) <|>
        (Str <$> parseJSONByteString val) <|>
        (Vec <$> parseJSONVectorByteString val) <|>
        (Nul <$ (parseJSON val :: Parser ()))

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

runTest :: Key -> KeyMap Val -> ByteString -> Assertion
runTest key map goldenOutput
  | key == "phkdf-pass"
  = case getPhkdfPassInputs map of
      Just inputs -> compareAu "phkdf-pass" goldenOutput (uncurry3 phkdfPass inputs)
      Nothing -> assertFailure "arguments not parsed"
  | key == "phkdf-simple"
  = case getPhkdfSimpleInputs map of
      Just inputs -> compareAu "phkdf-simple" goldenOutput (uncurry phkdfSimple inputs)
      Nothing -> assertFailure "arguments not parsed"
  | otherwise = assertFailure "algorithm name not recognized"

compareAu :: String -> ByteString -> Stream ByteString -> Assertion
compareAu name bs outStream
  | B.null bs = assertFailure ("\"" ++ name ++ "\":\"" ++ concatMap toHex (S.take 4 outStream) ++ "\"")
  | otherwise = B.encodeBase16 (takeBytes (B.length bs) outStream) @?= B.encodeBase16 bs
  where
    toHex = T.unpack . B.encodeBase16

    takeBytes n stream = B.concat (go n stream)
      where
        go n ~(Cons out outStream')
          | n <= 0 = []
          | n <= B.length out = [B.take n out]
          | otherwise = out : go (n - B.length out) outStream'

-- FIXME? Allow computation of tweaks without recomputing seed

getPhkdfPassInputs :: KeyMap Val -> Maybe (PhkdfInputBlock, PhkdfInputArgs, PhkdfInputTweak)
getPhkdfPassInputs
  (getPhkdfPassBlock -> Just (block,
   getPhkdfPassArgs -> Just (args,
   getPhkdfPassTweak -> Just (tweak,
   args')))) | KM.null args'
  = Just (block, args, tweak)
getPhkdfPassInputs _ = Nothing

getPhkdfSimpleInputs :: KeyMap Val -> Maybe (PhkdfInputBlock, PhkdfInputArgs)
getPhkdfSimpleInputs
  (getPhkdfSimpleBlock -> Just (block,
   getPhkdfSimpleArgs -> Just (args,
   args'))) | KM.null args'
  = Just (block, args)
getPhkdfSimpleInputs _ = Nothing

getPhkdfPassArgs :: KeyMap Val -> Maybe (PhkdfInputArgs, KeyMap Val)
getPhkdfPassArgs
  (matchKey "username" -> (Just (Str phkdfInputArgs_username),
   matchKey "password" -> (Just (Str phkdfInputArgs_password),
   matchKey "credentials" -> (
     getByteStringVector_defaultEmpty -> Just phkdfInputArgs_credentials,
   args'))))
  = Just (PhkdfInputArgs {..}, args')
getPhkdfPassArgs _ = Nothing

getPhkdfSimpleArgs :: KeyMap Val -> Maybe (PhkdfInputArgs, KeyMap Val)
getPhkdfSimpleArgs
  (getPhkdfPassArgs -> Just (inputArgs,
   matchKey "role" -> (getByteStringVector_defaultEmpty -> Just role,
   args')))
  = Just (inputArgs' , args')
  where
    inputArgs' = inputArgs {
      phkdfInputArgs_credentials = phkdfInputArgs_credentials inputArgs <> role
    }
getPhkdfSimpleArgs _ = Nothing

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

getPhkdfPassBlock :: KeyMap Val -> Maybe (PhkdfInputBlock, KeyMap Val)
getPhkdfPassBlock
  (matchKey "domain-tag" -> (Just (Str phkdfInputBlock_domainTag),
   matchKey "seguid" -> (getByteString_defaultEmpty -> Just phkdfInputBlock_seguid,
   matchKey "long-tag" -> (getMaybeByteString -> Just mLongTag,
   matchKey' "tags" -> (getByteStringVector_defaultEmpty -> Just tags,
   matchKey "seed-tags" -> (getByteStringVector_defaultEmpty -> Just seedTags,
   matchKey "rounds" -> (Just (Int (fromIntegral -> phkdfInputBlock_rounds)),
   args')))))))
  = let phkdfInputBlock_tags = tags <> seedTags
        phkdfInputBlock_longTag = fromMaybe phkdfInputBlock_domainTag mLongTag
     in Just (PhkdfInputBlock {..}, args')
getPhkdfPassBlock _ = Nothing

getPhkdfSimpleBlock :: KeyMap Val -> Maybe (PhkdfInputBlock, KeyMap Val)
getPhkdfSimpleBlock
  (getPhkdfPassBlock -> Just (block,
   matchKey "echo-tags" -> (getByteStringVector_defaultEmpty -> Just echoTags,
   args')))
  = Just (block', KM.delete "tags" args')
  where
    block' = block {
      phkdfInputBlock_tags = phkdfInputBlock_tags block <> echoTags
    }
getPhkdfSimpleBlock _ = Nothing

getPhkdfPassTweak :: KeyMap Val -> Maybe (PhkdfInputTweak, KeyMap Val)
getPhkdfPassTweak
  (matchKey "role" -> (getByteStringVector_defaultEmpty -> Just phkdfInputTweak_role,
   matchKey "tags" -> (getByteStringVector_defaultEmpty -> Just tags,
   matchKey "echo-tags" -> (getByteStringVector_defaultEmpty -> Just echoTags,
   args'))))
  = let phkdfInputTweak_tags = tags <> echoTags
     in Just (PhkdfInputTweak{..}, args')
getPhkdfPassTweak _ = Nothing

matchKey, matchKey' :: Key -> KeyMap a -> (Maybe a, KeyMap a)
matchKey key map = (KM.lookup key map, KM.delete key map)
matchKey' key map = (KM.lookup key map, map)
