# Revision history for hash-string

## 0.1.0.2 (2025-06-02)

* The input parameters to xor were declared `restrict`, so the pointer
  comparison was actually necessary to avoid undefined C behavior.

* Enabled autovectorization, and added `restrict` annotations to the base16
  conversions

## 0.1.0.1 (2025-05-31)

* Removed a mildly problematic non-constant-time branch when xor'ing the same
  physical string with itself.
     
* Improved support for GHC versions < 9.4

## 0.1.0.0 (2025-01-20)
