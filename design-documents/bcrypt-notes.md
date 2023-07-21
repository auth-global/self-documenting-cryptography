Should the "OrpheanBeholderScryDoubt" in the bcrypt binding be turned into a parameter?

`bcrypt_pbkdf` uses "OxychromaticBlowfishSwatDynamite".  Need to check that parameterizing this string really would result in a binding that could conceivably be used to implement both standard bcrypt and this variant.

Although the G3P could choose a longer string, perhaps "GlobalPasswordPrehashProtocolG3P", any high-level protocol should specify a constant plaintext string. This is because allowing this string to be chosen after seeing the other inputs allows collisions to be trivially constructed.

Moreover, an opaquely-chosen parameter allows the chooser to plant an "easter egg", a single (possibly secret) value for which the resulting hash function returns whatever the chooser wants. Thus this parameter needs to be a sufficiently "nothing up my sleeve" value that doesn't repeat any sequence of 8 aligned bytes, which precisely describes "OrpheanBeholderScryDoubt".

The usage of this constant within bcrypt does seem to have cryptoacoustic properties, but not strong enough to concern oneself about turning into a parameterizable tag, especially in light of the gotchas above.

Maybe this string should be parameterized in the binding, but I'm not inclined to change this string for the G3P. 24 bytes of output is plenty enough to achieve the G3P's key-stretching objectives, and "OrpheanBeholderScryDoubt" may already be recognized by security scans and reverse engineering tools.

The argument for a 32 or 40 byte output is much better if bcrypt were to be modified so that it provides a horn-loaded input. One could plausibly do this by hashing the horn-loaded input into the blowfish key for a small (likely fixed) number of rounds, thereafter only rekeying blowfish via less-secret (and non-horn-loaded) salt parameters.  However, at the present time I don't see any reason to do this.

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

This requires the computation of two blocks per round, same as PBKDF2. Should we believe 20,000 rounds of this function is as secure as 20,000 rounds of PBKDF2, at least in terms of preimage and shortcut resistance? I suspect it is.

This would likely provide an answer whether or not 20,000 rounds of PHKDF with a 19 byte domain tag really is equivalent to 15,000 rounds of PHKDF with a 83 byte domain tag.  It might also answer whether or not 20,000 rounds of PHKDF really is equivalent to 30,000 rounds of PBKDF2.

At first glance, `tagHash` might seem to have higher cryptoacoustic efficiency than PHKDF, as almost all of the input to HMAC-SHA256 becomes a medium in which to transmit plaintext messages. But the SHA256 compression function accepts exactly 96 bytes as input, producing a 32 byte result. This residual has to go somewhere, so it takes up 32 bytes of the next 96 byte input, in addition to the next 64 byte block.

In reality, this situation is trading one kind of tag for another. Thanks to seguids, the initial 32 byte SHA256 accumulator is itself an indirect tag. In PHKDF, the residual hash the previous round is placed into the block, taking up direct tagging space instead.

However, the final block computation of HMAC itself does waste some plaintext tagging space. It seems plausible that cryptoacoustic efficiency can be improved by moving from HMAC-SHA256 to Blake2 or Ascon.

Here _cryptoacoustic efficiency_ refers to the metaphorical power transfer function from senders to receivers. More concretely, higher cryptoacoustic efficiency means higher cost overheads imposed on virtual black-box tag obscuration attacks. Thus any non-conjectural comparison would necessarily developing or finding a more rigorous and formal security model for cryptoacoustics. This lack of a model is part of the reason why G3Pb1 hedges its cryptoacoustic bets between PHKDF-HMAC-SHA256 and bcrypt.

## cryptoacoustic notes

bscrypt and argon2, though they seem like they should be supremely logical choices for future versions of the G3P, both appear to be fairly dead in the cryptoacoustical sense. All their input parameters are horn-loaded, which means no input is capable of providing cryptoacoustic repetition.  For example, a hypothetical G3Pa2 could say, stuff plaintext tags into the parameters of argon2, which certainly has plausible cryptoacoustic properties thanks to blake2, but there are no messages that can be cryptoacoustically conveyed during the key-stretching phase itself.

I briefly examined the other hash password hash functions that were specifically acknowledged by the PHC.  Of those, lyra2 and makwa also appear to have a similar issue. Along with bscrypt and argon2, any of these four functions would seem to require significant (and often rather delicate) reconstruction to be highly interesting in the cryptoacoustical sense.

Catena, yescrypt, and Balloon Hash seem worth deeper investigation. These may well have interesting cryptoacoustic properties that are either already directly usable via their public interfaces, and/or can be made more useful via relatively safe and simple modifications/instantiations. Yescrypt seems like a prime candidate for cryptoacoustic reconstruction, because yescrypt already depends upon PBKDF2 and PHKDF seems like a rather cautious upgrade.

I'm curious to dig into the cryptoacoustic properties of Blake3. It sounds like a fascinating design, but the internal tree structure would also seem to impose often-undesirable complications in cryptoacoustically sensitive designs, so... maybe Blake3 needs a mode of operation that provides a traditional fully-serialized input processing?  Does Blake3 provide a key or counter that forces a complete rehash from plaintext inputs?  How cryptoacoustically viable would such a construct be?

If the number of rounds of blake2 can safely be reduced, that might possibly be of interest to PHKDF. Let's compare 14k rounds of PHKDF using a full 10 rounds of blake2s to 20k rounds of PHKDF using a reduced 7 rounds of blake2s. Both constructions involve 140k rounds of blake2s's lower-level compression function, so the overall level of key stretching should be very comparable between these two constructions.

However, I would expect that the larger number of plaintext repetitions is reasonably likely to demonstrate higher cryptoacoustic efficiency, or at least not be substantially worse. Of course, this is all highly conjectural without developing a more formal security model for cryptoacoustics, and experimenting with practical construction of tag obscuration attacks: maybe for whatever reasons the full 10 rounds of blake2s makes it more than 1.4x times more expensive to obscure each individual cryptoacoustic repetition relative to the reduced 7 round version. (But then why would this non-linear cryptoacoustic advantage not apply to the feedback mode employed by PHKDF?)

The block size of ascon seems a little shorter than I'd prefer, but I still think PHKDF-ascon is worth further consideration. Keeping the very first hash function employed relatively friendly to embedded systems seems decidedly advantageous; the fact that microcontrollers now regularly come with SHA256 hardware support is a major reason why I went with HMAC-SHA256 as the fundamental primitive for the outer shell of the G3Pb1.

A technique I considered but didn't adopt for the G3Pb1 (beyond a particularly simple variant in PHKDF's slow extraction function) involves interleaving M bytes of tagging space with N bytes of direct inputs, residual inputs, etc, where M+N is a smallish power of two such as 16 or 64 or 1024 informed by the internal structure of the underlying hash function. This approach might offer a solution to work around the block-size limitations of ascon or the internal tree-structure of blake3.

However this seemed potentially more difficult to reverse-engineer than the G3Pb1's approach, which may be the first-ever attempt at a cryptoacoustic design. Considering that the techniques of cryptoacoustic self-narration and self-documenting cryptography are fairly new and not yet widely appreciated, let alone deeply understood, ease of understanding seems a particularly important design goal for the time being

Starting from an insecurely-obfuscated blob of machine code hiding a deployment of the G3Pb1, it is a design goal that a reasonably good reverse engineer who has never encountered cryptoacoustics should be able to find that deployment's official documentation with relative ease. Suffixing a message to a hash function's input seems a reasonable Schelling point for bootstrapping the cryptoacoustic method of communication. Once these techniques are more commonly deployed, understood, and expected, then it's more reasonable to introduce more sophisticated cryptoacoustic encoding techniques such as interleaving.

The issue with interleaving is that it provides insecure obfuscation techniques a more room to work, and that might trip up a reverse engineer who hasn't encountered cryptoacoustics before.  These engineers might be less expectant of messages explicitly intended for them to be baked into the deployment of the cryptographic protocol they wish to understand and contextualize.