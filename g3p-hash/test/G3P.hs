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
     deriving (Show)

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
  , result_hashes = KM.fromList [ ("G3Pb1","") ]
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
testVectorDefaultFileName = "g3p-test-vectors.json"

testFile :: (String, Either String TestVectors) -> TestTree
testFile (fileName, mTestVectors) =
    case mTestVectors of
      Left err -> testCase testName $ assertFailure err
      Right tvs -> testGroup testName $ genTestCases tvs
  where
    testName = "testfile: " ++ fileName

runTest :: Key -> KeyMap Val -> ByteString -> Assertion
runTest key map goldenOutput
  | key == "G3Pb1"
  = case getG3PInputs map of
      Just inputs -> compareAu "G3Pb1" goldenOutput (uncurry3 g3pHash inputs)
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

getG3PInputs :: KeyMap Val -> Maybe (G3PInputBlock, G3PInputArgs, G3PInputTweak)
getG3PInputs
  (getG3PBlock -> Just (block,
   getG3PArgs -> Just (args,
   getG3PTweak -> Just (tweak,
   args')))) | KM.null args'
  = Just (block, args, tweak)
getG3PInputs _ = Nothing

getG3PArgs :: KeyMap Val -> Maybe (G3PInputArgs, KeyMap Val)
getG3PArgs
  (matchKey "username" -> (Just (Str g3pInputArgs_username),
   matchKey "password" -> (Just (Str g3pInputArgs_password),
   matchKey "credentials" -> (
     getByteStringVector_defaultEmpty -> Just g3pInputArgs_credentials,
   args'))))
  = Just (G3PInputArgs {..}, args')
getG3PArgs _ = Nothing

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

getG3PBlock :: KeyMap Val -> Maybe (G3PInputBlock, KeyMap Val)
getG3PBlock
  (matchKey "domain-tag" -> (Just (Str g3pInputBlock_domainTag),
   matchKey "seguid" -> (getByteString_defaultEmpty -> Just g3pInputBlock_seguid,
   matchKey "long-tag" -> (getMaybeByteString -> Just mLongTag,
   -- use matchKey' to leave the "tags" argument behind for getG3PTweak
   matchKey' "tags" -> (getByteStringVector_defaultEmpty -> Just tags,
   matchKey "seed-tags" -> (getByteStringVector_defaultEmpty -> Just seedTags,
   matchKey "phkdf-rounds" -> (Just (Int (fromIntegral -> g3pInputBlock_phkdfRounds)),
   matchKey "bcrypt-rounds" -> (Just (Int (fromIntegral -> g3pInputBlock_bcryptRounds)),
   matchKey "bcrypt-tag" -> (getMaybeByteString -> Just mBcryptTag,
   matchKey "bcrypt-salt-tag" -> (getMaybeByteString -> Just mBcryptSaltTag,
   args'))))))))))
  = let g3pInputBlock_tags = tags <> seedTags
        g3pInputBlock_longTag = fromMaybe g3pInputBlock_domainTag mLongTag
        g3pInputBlock_bcryptTag = fromMaybe g3pInputBlock_domainTag mBcryptTag
        g3pInputBlock_bcryptSaltTag = fromMaybe g3pInputBlock_bcryptTag mBcryptSaltTag
     in Just (G3PInputBlock {..}, args')
getG3PBlock _ = Nothing

getG3PTweak :: KeyMap Val -> Maybe (G3PInputTweak, KeyMap Val)
getG3PTweak
  (matchKey "role" -> (getByteStringVector_defaultEmpty -> Just g3pInputTweak_role,
   matchKey "tags" -> (getByteStringVector_defaultEmpty -> Just tags,
   matchKey "echo-tags" -> (getByteStringVector_defaultEmpty -> Just echoTags,
   args'))))
  = let g3pInputTweak_tags = tags <> echoTags
     in Just (G3PInputTweak{..}, args')
getG3PTweak _ = Nothing

matchKey, matchKey' :: Key -> KeyMap a -> (Maybe a, KeyMap a)
matchKey key map = (KM.lookup key map, KM.delete key map)
matchKey' key map = (KM.lookup key map, map)
