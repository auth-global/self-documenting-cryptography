{-# LANGUAGE ScopedTypeVariables, BangPatterns, ViewPatterns, LambdaCase, OverloadedStrings #-}

module Main where

import           Data.ByteString (ByteString,breakSubstring)
import           Data.ByteString.Internal (c2w)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import           System.Environment (getArgs)

main :: IO ()
main = do
  (filename : _) <- getArgs
  test_cases <- B.readFile filename
  test_output <- BL.getContents
  BL.putStr test_output
  let rewrites = getRewrites (BL.toStrict test_output)
  B.writeFile filename (findAndReplaceAll rewrites test_cases)

removeSubstring :: ByteString -> ByteString -> Maybe (ByteString, ByteString)
removeSubstring target =
    let findSub = breakSubstring target
        n = B.length target
     in \source -> case findSub source of
                     (_,"") -> Nothing
                     (a,z) -> Just (a, B.drop n z)

data Replaced a = Original !a | Replaced !a

forget :: Replaced a -> a
forget = \case
    Original a -> a
    Replaced a -> a

findAndReplace :: (ByteString, ByteString) -> (Replaced ByteString) -> [Replaced ByteString]
findAndReplace ~(target, replacement) = go
  where
    findSub = removeSubstring target
    len = B.length target

    go :: Replaced ByteString -> [Replaced ByteString]
    go x =
      case x of
        (Replaced _) -> [x]
        (Original source) ->
          case findSub source of
            Nothing -> [x]
            Just (a,z) -> Original a : Replaced replacement : go (Original z)

findAndReplaceAll :: [(ByteString,ByteString)] -> ByteString -> ByteString
findAndReplaceAll = \rewrites str -> go rewrites [Original str]
  where
    go [] strs = B.concat (map forget strs)
    go (rewrite:rewrites) strs
      = go rewrites (concatMap (findAndReplace rewrite) strs)

splitChar :: Char -> ByteString -> Maybe (ByteString, ByteString)
splitChar c str = flip B.splitAt str <$> B.elemIndex (c2w c) str

getRewrites :: ByteString -> [(ByteString, ByteString)]
getRewrites = go []
  where
    findExpected = removeSubstring "expected: \""
    findActual   = removeSubstring "but got: \""
    go reps str =
      case findExpected str of
        Nothing -> reps
        Just (_,str) ->
          case splitChar '"' str of
            Nothing -> []
            Just (expected,str) ->
              case findActual str of
                Nothing -> []
                Just (_,str) ->
                  case splitChar '"' str of
                    Nothing -> []
                    Just (got,str) -> go ((expected,got) : reps) str
