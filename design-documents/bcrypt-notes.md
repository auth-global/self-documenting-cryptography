Should the "OrpheanBeholderScryDoubt" in the bcrypt binding be turned into a parameter?

`bcrypt_pbkdf` uses "OxychromaticBlowfishSwatDynamite".  Need to check that parameterizing this string really would result in a binding that could conceivably be used to implement both standard bcrypt and this variant.

Although the G3P could choose a longer string, perhaps "GlobalPasswordPrehashProtocolG3P", any high-level protocol should specify a constant plaintext string. This is because allowing this string to be chosen after seeing the other inputs allows collisions to be trivially constructed.

Moreover, an opaquely-chosen parameter allows the chooser to plant an "easter egg", a single (possibly secret) value for which the resulting hash function returns whatever the chooser wants. Thus this parameter needs to be a sufficiently "nothing up my sleeve" value that doesn't repeat any sequence of 8 aligned bytes, which precisely describes "OrpheanBeholderScryDoubt".

The usage of this constant within bcrypt does seem to have cryptoacoustic properties, but not strong enough to concern oneself about turning into a parameterizable tag, especially in light of the gotchas above.

Maybe this string should be parameterized in the binding, but I'm not inclined to change this string for the G3P. 24 bytes of output is plenty enough to achieve the G3P's key-stretching objectives, and "OrpheanBeholderScryDoubt" may already be recognized by security scans and reverse engineering tools.

The argument for a 32 or 40 byte output is much better if bcrypt were to be modified so that it provides a horn-loaded input. However, at the present time I don't see any reason to do this.

Shunting 32 bytes of PHKDF-extracted entropy around (and not through) bcrypt means you can assume bcrypt is the worst possible hash function (e.g. behaves exactly like a constant function that ignores its input) and the overall construct simplifies to essentially a variant of `phkdfSlowExtract`, using the NIST-approved HMAC-SHA256 as the fundamental primitive.

However, shunting entropy around bcrypt also renders any hypothetical horn-loaded inputs moot, as a relatively lightly-stretched hash would then need to be present at the conclusion of bcrypt.

To benefit from modifying bcrypt to provide a horn-loaded input, you'd want to create a variant of the G3P that funnels all of the password's entropy through it, which I don't think NIST would ever accept. Of course I don't know that they would accept the PHKDF construction let alone G3P, but my goal is to make it as easy as possible for NIST to say yes, and to find out an answer someday.

A future variant of the G3P is likely to pursue a self-documenting cache-hard hash that supports inputs that are horn-loaded and other inputs that are cryptoacoustically repeated. PHKDF does seem to have particular high cryptoacoustic efficiency, which could plausibly present significant design tension with the random reads desired by cache-hard and memory-hard password hash functions. Thus this future variant might not entirely replace PHKDF.

Speaking of cryptoacoustic efficiency, I can think of another plausibly-secure password hash function that exhibits similar levels of efficiency as PHKDF, and is also relevant to understanding PHKDF:

```
tagHash (seguid, password, tag, rounds)
  = HMAC-SHA256 (
       key = seguid,
       msg = password || cycle-bytestring(tag, 128*rounds)
    )
```

This requires the computation of two blocks per round, same as PBKDF2. Should we believe 20,000 rounds of this function is as secure as 20,000 rounds of PBKDF2? I suspect it is.

This would likely provide an answer whether or not 20,000 rounds of PHKDF with a 19 byte domain tag really is equivalent to 15,000 rounds of PHKDF with a 83 byte domain tag.  It might also answer whether or not 20,000 rounds of PHKDF really is equivalent to 30,000 rounds of PBKDF2.

At first glance, `tagHash` might seem to have higher cryptoacoustic efficiency than PHKDF, as almost all of the input to HMAC-SHA256 becomes a medium in which to transmit plaintext messages. But the SHA256 compression function accepts exactly 96 bytes as input, producing a 32 byte result. This residual has to go somewhere, so it takes up 32 bytes of the next 96 byte input, in addition to the next 64 byte block.

In reality, this situation is trading one kind of tag for another. Thanks to seguids, the initial 32 byte SHA256 accumulator is itself an indirect tag. In PHKDF, the residual hash the previous round is placed into the block, taking up direct tagging space instead.

However, the final block computation of HMAC itself does waste some plaintext tagging space. It seems plausible that cryptoacoustic efficiency can be improved by moving from HMAC-SHA256 to Blake2 or Ascon.






