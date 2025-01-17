* Performance tweaking

   * The encoding functions in particular are written rather naively, it should
     be possible to optimize these routines to a significant degree. (On the
     other hand, it might not be particularly important. The encoded data still
     needs to be processed by a cryptographic state machine, which is very slow
     relative to unoptimized encoding routines.

* Test Suite

   * The property-based test ensures that the output exactly equals the unique
     expected output, however there's still the possibility that we don't test
     the problematic input. I'm particularly skeptical that the current input
     generator is effectively exercising the input space in this case.

   * There are still a handful of functions that aren't covered by the test
     suite, although most/all of the functions with complicated implementations
     are covered.