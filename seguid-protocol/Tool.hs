module Tool where

import Data.Bits
import Data.ByteString(ByteString)
import qualified Data.ByteString as B
import Data.ByteString.Internal(c2w,w2c)
import qualified Data.List as List
import Data.Word

chopAt :: Int -> ByteString -> [ByteString]
chopAt n = List.unfoldr f
  where f bs | B.null bs = Nothing
             | otherwise = Just (B.splitAt n bs)

showHexString :: ByteString -> String
showHexString bs =  "  \"" ++ List.intercalate lineBreak bss ++ "\"\n"
  where
    lineBreak  = "\\\n  \\"

    bss :: [String]
    bss = map (concatMap toHex . B.unpack) (chopAt 16 bs)

    toHex :: Word8 -> String
    toHex n = "\\x" ++ map toHexDigit [ shiftR n 4 .&. 0x0F, n .&. 0x0F ]

    toHexDigit :: Word8 -> Char
    toHexDigit x | x < 10    = w2c (c2w '0' + x)
                 | otherwise = w2c (c2w 'A' + x - 10)
