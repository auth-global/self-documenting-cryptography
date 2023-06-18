module PreinitSalt where

import Data.ByteString(ByteString)
import qualified Data.ByteString as B
import qualified Data.List as List
import Data.Int
import Data.Word
import Network.ByteOrder

genPrimes :: Int -> [Int]
genPrimes lim = 2:filter isPrime [3,5..lim]
  where isPrime n = all (\d -> n `mod` d /= 0) [3,5..n `div` 2]

chopAt :: Int -> ByteString -> [ByteString]
chopAt n = List.unfoldr f
  where f bs | B.null bs = Nothing
             | otherwise = Just (B.splitAt n bs)

compute_seguid_v0_salt :: ByteString
compute_seguid_v0_salt = B.concat (map f primes)
  where
    primes = genPrimes 131

    f p = bytestring32 result
      where
        x = fromIntegral p ** 0.75 :: Double
        frac = x - fromIntegral (floor x :: Int64)
        result = floor (frac * (2 ^ 32)) :: Word32

verify_seguid_v0_salt :: ByteString -> Bool
verify_seguid_v0_salt bs =
    B.length bs == 128
    && length primes == 32
    && all checkPair (zip primes (chopAt 4 bs))
  where
    primes = genPrimes 131

    checkPair (p, frac) =
        checkInteger n && not (checkInteger (n+1))
      where
        -- Note the floating point arithmetic is much more
        -- incidental to this algorithm.  It is also fail-safe
        -- in the sense that computing the wrong floats can only
        -- cause the correct salt to be rejected.
        n = floor (fromIntegral p ** 0.75 :: Double) * (2 ^ 32) +
            fromIntegral (word32 frac) :: Integer
        p3 = (fromIntegral p ^ 3) * (2 ^ 128) :: Integer
        checkInteger n = (n ^ 4) < p3

