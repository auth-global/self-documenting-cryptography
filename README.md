## The Cryptoacoustic Enigma Machine

![Property of YOUR COMPANY INC.](design-documents/media/property-tag.png)

The [Global Password Prehash Protocol (G3P)](g3p-hash/lib/Crypto/G3P.hs) is [designed](design-documents/g3p.md) to be a password hash and key derivation function, based on PHKDF and bcrypt. The algorithm behind the G3P is a bit like an [Enigma rotary cipher machine](https://en.wikipedia.org/wiki/Enigma_machine) with an integrated [tape deck](https://en.wikipedia.org/wiki/Digital_Audio_Tape) and [loudspeaker](https://en.wikipedia.org/wiki/Loudspeaker) which provides a form of _digital watermarking_.[^steampunk]

The position of the G3P's rotors are initialized by a _seguid_. Then the user types their username and password on the keyboard, which causes the position of the rotors to change.

The G3P has no internal state beyond the position of the rotors. After the data entry process is complete, the username and password are no longer needed for the key-stretching phase. This is why the G3P design document describes these parameters as _horn-loaded_.

Finally, the user plays a prerecorded message on the tape deck. This message is typically provided by the deployment to the user, and is typically not a secret. A reasonable choice of message might be something like "this password hash function is for employees of Your Company, Inc, to log into the website https://employees.your-company.example. If you run across any stolen password hashes, please call 555-YOUR-SPY and report them."[^tipline]

This message should narrate the precise purpose of this particular password, thus serving as a digital variant of a physical _property tag_ that you can affix to tangible property.

As this message is played back on the loudspeaker, the watermarking process causes the position of the rotors to change accordingly. After the song-and-dance routine is complete, the final position of the rotors provides the derived key, which is also suitable as a traditional password hash.

In one sense, this message becomes part of the password itself, providing an [embedded attribution](https://joeyh.name/blog/entry/attribution_armored_code/) that hopefully cannot be removed without losing the ability to compute the correct password hash function. In the terminology of Joey Hess's blog post, the G3P is an attempt at an attribution-armored password hash function. The G3P sets up a series of chokepoints in the password hashing algorithm so that each chokepoint itself signals a specific embedded attribution.

The G3P's primary security goal is traditional: it must be impossible to directly decrypt a password hash, the algorithm must provide key stretching, and it should also be perfectly suitable for use as a key derivation function. Any failure of the sound system integrated into the G3P must not impact this primary mission.

Thus G3P's secondary security goal is that password hashes should be _traceable_ or _useless_ after they have been _stolen_. If you know how to crack a password hash, you should know where to report it as stolen. If you don't know where to report a password hash as stolen, you shouldn't be able to crack it.[^replaying_hashes]

The mechanisms behind this embedded attribution process is what I call _cryptoacoustics_. The use cases I suggest adopting result in an example of what I call _[self-documenting](https://www.cut-the-knot.org/Curriculum/Algebra/SelfDescriptive.shtml) cryptography_.

Self-documenting cryptography is the use of self-narration and self-reference in cryptographic constructions in order to communicate certain indelible facts to legitimate users and other observers. It depends upon cryptoacoustics to deliver those messages.

It's important to play the tape _after_ the user inputs the username and password. If one were to initialize the rotors and then play the tape, then the overall construction wouldn't be a secure embedded attribution. Somebody could simply initialize the machine, play the tape, and then use the resulting rotor position to initialize multiple other machines to compute the correct hash function without listening to the tape at all.

This is my intuition behind the design patterns that the G3P employs. Our `seguid` corresponds to HMAC's `key` parameter, and any `tag` is part of the embedded attribution and appended _after_ a user-supplied message. These parameters are what G3P uses as salt, in addition to the username.

Indeed, HMAC-SHA256 is already it's own Cryptoacoustic Enigma Machine, one that the G3P builds up into a larger machine. In fact, it would seem that most or all existing cryptographic hash functions already are their own Cryptoacoustic Enigma Machine in some form or another. For example, affixing a tag after user-supplied input is plausibly a cryptoacoustically-secure construction for most any common hash function other than Blake3, which still has it's own cryptoacoustic possibilities.[^blake3]

From a point of view that is particularly cautious, this tagging process is nothing more than a novel justification for the `FixedInfo` parameters mentioned in [NIST SP 800-56C](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final), or alternatively the `Label` and `Context` parameters mentioned in [NIST SP 800-108](https://csrc.nist.gov/pubs/sp/800/108/r1/final), which this document refers to as _contextual parameters_, or synonymously, _tags_, which serve as an embedded attribution.

From the point of view of the G3P's primary security model, this tagging process results in domain-specific hash functions that are particularly low-risk substitutes for the underlying, untagged hash function.  The secondary security model is the topic of the next section.

## Attacking and Defending Cryptoacoustics

> A language design should *at least* provide facilities which allow the comprehensible expression of algorithms: *at best* a language suggests better forms of expression. But language is *not* a panacea. A language cannot, for example, prevent the creation of obscure programs: the ingenious programmer can always find an infinite number of paths to obfuscation.
>
> - William Wulf (1977), via "Programming Language Concepts, 2/E" by Ghezzi and Jazayeri
>
> (See also the [International Obfuscated C Code Contest](https://www.ioccc.org/))

Cryptography more typically depends on the property that if you know a key, then you can compute a cryptographic function. Cryptoacoustics depends upon the converse: if you can compute some cryptographic function, then you know (part of) its key. When this proposition holds, that part of the key can be used to convey a message, or _tag_.

In the cryptoacoustic security model, attackers obfuscate programs in order to hide these tags, and defenders use reverse engineering to reveal these tags. This inverts the roles of Fully Homomorphic Encryption (FHE), where defenders obfuscate programs and attackers reverse engineer them. In this sense, cryptoacoustics is an anti-problem associated with FHE.

Let's say you deploy the G3P for a company, club, or other organization. Now one of your password hashes gets stolen. The thief decides to use a [botnet](https://arstechnica.com/security/2024/03/attack-wrangles-thousands-of-web-users-into-a-password-cracking-botnet/) or [other stolen computing resources](https://www.reddit.com/r/aws/comments/x03vay/hacked_aws_account_is_facing_200000_in_charges/) to try to crack that password.

A security analyst investigating this incident uncovers the thief's executable payload. Perhaps their company has already tapped into the command and control network of the botnet. Perhaps the fraudulent cloud server instance was suspended and terminated, and snapshot of the machine was given to the analyst to decipher.

Neither this analyst nor your organization have any knowledge of the other's existence, but now they have an implementation of your deployment of the G3P, which includes an invitation to call 555-YOUR-SPY.

If this implementation is written in a relatively straightforward way, all the security analyst would have to do is dump the strings contained in the payload, after which they should have zero difficulty disclosing their observations back to your company's counterintelligence tip line.

Of course the thief might anticipate this scenario, and try to prevent it happening. Many simple obfuscation techniques can keep your tags out of a simple scan for string constants. If they do that, the thief becomes a (less-than-trivial) attacker of the G3P's secondary cryptoacoustic security model, in furtherance of an attack on the G3P's primary goal of being a password hash function.

For the attacker to definitively win your cryptoacoustic security game, they must provide a _securely obfuscated_ implementation of your deployed password hash function. This means that the invitation to call 555-YOUR-SPY _must_ remain out of reach of the best reverse engineers on their best days, thus preventing a win by the defense.

In order for the defenders to definitively win your cryptoacoustic security game, a defender must find one of your stolen hashes and report it back to your counterintelligence tip line. This is why the G3P is designed to be reverse engineered.

In a secondary yet very fundamental sense, the #1 VIP stakeholders in the G3P are the unknown reverse engineers toiling away on some obfuscated implementation of your deployment. Thus the design is driven a desire to simplify reverse engineering as much as possible, across all possible implementations of the G3P.

Many of the techniques evoked by William Wulf's quote are relatively simple and often impose highly manageable runtime costs. Some of these techniques are very clever and devious, as studying IOCCC contest entries can attest. They certainly can slow down many good reverse engineers for days.

However, these sorts of techniques will eventually yield to competent, persistent reverse engineering, and thus they tend to be examples of _insecure_ tag obfuscation attacks. Insecure obfuscation attacks means that the defenders are capable of winning, at least in principle.

The G3P has a built-in backstop against insecure obfuscation attacks. Once a reverse engineering team understands the correspondence between an implementation and SHA256, they can watch a memory replay and read off the strings being fed into that function. This in turn reveals all the tags hidden inside the implementation.

This works because most every hash function exclusive-or's its input into a cryptographic state machine.[^group_operation] These perturbations of the state machine are intolerant to noise, which hopefully serves as a bulwark against obfuscation.

This is in fact my intuition for thinking about the cryptoacoustic properties of a hash function: I get to specify the password, I don't get to directly observe any of the other inputs, but do I get to watch a memory replay of the computation associated with my password input.

My goal as a observer is to decode those other parameters from the memory replay. My goal as a designer is to ensure that decoding process is as simple and straightforward as possible.

In the metaphor of the Cryptoacoustic Enigma Machine, I assume that an attacker's implementation muted the speaker. However, I've arranged it so that reverse engineers have the ability to deduce what the loudspeaker would have said by carefully observing the exact motions that the rotors make. Thus if the attacker is to definitively win your cryptoacoustic security game, they must also obscure the rotors themselves.

The G3P's rotors correspond to the internal state of SHA256, and blowfish's expensive key setup function. The need to hide this internal state suggests that any truly secure tag obscuration attack must incorporate encryption that is homomorphic on these state machines.

Surprisingly, Fully Homomorphic Encryption (FHE) exists. Thus it would seem that the necessary components can be built, at least in principle. Fortunately, the run-time overhead of even state-of-the-art FHE is much too high to be deployed in a practical tag obscuration attack, at least for the time being. Although a truly secure tag obscuration attack need not depend on any particular FHE implementation, it still seems plausible that such an attack would still impose significant run-time overhead.

The G3P tries to maximize this presumed run-time overhead. In doing so, it is trying to deter attackers from deploying secure tag obfuscation attacks, or at least offering the defenders a meaningful consolation prize if this does happen.

This deterrence is a [pure, unmitigated opportunity cost](https://arxiv.org/abs/2211.16626). Few nefarious password crackers would accept a 99% reduction in guessing throughput, or a 100x cost multiplier, in exchange for "winning" the cryptoacoustic security game. If an attacker accepts, the defenders gain a significant advantage in keeping their plaintext passwords secret.

If it would cost $100 for an attacker to crack some mildly weak password, then a securely obfuscated attack would cost $10,000. That's 9900 incentives to either in-source the attack or disclose the target of the attack to the cracker. This disclosure need not be forthright, the attacker might decide to take a chance and deploy an insecurely obfuscated cracker, thus providing the defenders an opportunity to win.

Of course, a 99.9% reduction in guessing throughput, or 1000x cost multiplier, would be even better. It turns out to be convenient to discuss this cost multiplier in terms of _decibels_. Thus a 100x cost multiplier corresponds to 20 dB advantage, and a 1000x cost multiplier corresponds to a 30 dB advantage.

In the context of slow password hashing, I estimate that 20 dB is roughly the minimum _cryptoacoustic advantage_[^cryptoacoustic_efficiency] in order for a cryptoacoustic construction to be sort of minimally viable. Cryptoacoustic advantage corresponds to the _minimum obfuscation overhead_ imposed by the most efficient tag obfuscation attack that is secure against the best reverse engineers.

Even if the cracker is running on stolen resources, a 99% reduction in password guessing throughput is a significant opportunity cost. A cryptoacoustic advantage of +10 dB would correspond to cost multiplier of 10x, or a 90% reduction in guessing throughput. At this point you might see a few nefarious entities deploy secure tag obscuration attacks, but I would expect this to be extremely niche and sporadic.

Therefore, a cryptoacoustic construction with a +10 dB advantage would likely still be reasonably effective at spreading the tags of a slow password hash function on average, even if the viability of the construction might be dubious in specific cases, and would be dubious going forward.

My guess is that at +6 dB advantage, or a 4x cost multiplier representing a 75% reduction in guessing throughput, is about where you'd start to see limited but steady deployments of secure tag obscuration attacks against password hashes. As the advantage drops to 0 dB, the cost multiplier approaches 1x. The opportunity cost of deploying a proper attack becomes negligible. This in turn could lead to the widespread adoption of secure tag obscuration attacks by nefarious password crackers.

This would represent a total failure of the secondary security goal of cryptoacoustics. However it would also represent a significant insight into the research program for cryptoacoustics.

Slow password hashing is something of a best case for cryptoacoustics. Other applications of cryptoacoustics may need +60 dB or +90 dB advantage or more to be viable, making a securely obfuscated attack a million or billion times more expensive.

Though there's a couple different interpretations of what a negative cryptoacoustic advantage might represent, none of them are terribly plausible. In particular, a securely-obfuscated implementation is almost certainly not going to be _faster_ than a native implementation. And because the G3P's tags are _contextual parameters_, a failure of the cryptoacoustic security model doesn't imply a failure of the classical security model.

The purpose of _cryptoacoustic repetition_ as employed by PHKDF and the G3P is that it reduces the advantage that a smaller construction must exhibit in order for a larger construction to be viable. This is especially important because we don't know what the actual cryptoacoustic advantage of SHA256 or blowfish might be, but we want to maximize the advantage of the G3P anyway.

## The Cryptoacoustic Medium

Cryptoacoustics is the art of transmitting [signals](https://en.wikipedia.org/wiki/Signal) in the [medium](https://en.wikipedia.org/wiki/Transmission_medium) of cryptographic state changes so that our tags are easily decoded and understood by observers, and that maximize the advantage to run-time efficiency of being either forthright or insecurely obfuscated.  This medium hopefully serves as a bulwark against obfuscation because it is _intolerant to noise_.

Conveying a message requires the use of a transmission medium. In our scenario, cryptographic state changes serve as a virtual transmission medium. This medium is purely mathematical and has no physical basis. Rather, algorithmic chokepoints ride upon the context of past communications that occurred via physical transmission media. In the case of the G3P, this context is that somebody hashed a password, and then somebody else stole that hash.

This tagging process is not unlike a digital watermark, however, the G3P provides no means of authenticating whether or not any purported password hash is genuine or not, so there's _plausible deniability_ baked into this process.

Rather, the tag is only readable during the password hashing process. Thus, this kind of watermark represents a belief about where a password hash came from, a belief that must be correct before offline attacks on truly genuine hashes can be achieved.

This is not an interactive communication protocol, yet non-interactive communication protocols can be extremely useful. Consider for example broadcast television, broadcast radio, [WSPR](https://en.wikipedia.org/wiki/WSPR_\(amateur_radio_software\)) and other radio beacon protocols, or a physical property tag.

This project follows various philosophies of documentation-driven design. Not only does this nicely complement the design for reverse engineering, I find it to be an indispensable way to find bugs and produce higher quality software.

I think there's likely to be a number of intriguing opportunities for applying the ideas behind self-documenting cryptography to other contexts, especially self-narration and blockchain applications.

## Why call it "Cryptoacoustics"?

[![German sound location, 1917. The photograph shows a junior officer and a soldier from an unidentified Feldartillerie regiment wearing combined acoustic/optical locating apparatus. The small-aperture goggles were apparently set so that when the sound was located by turning the head, the aircraft would be visible.](design-documents/media/acoustic_locator_13.jpg)](https://rarehistoricalphotos.com/aircraft-detection-radar-1917-1940/)

The above picture is of a German officer and soldier from 1917 wearing a combined acoustic/optical apparatus used for locating aircraft and gunfire in WWI. These are strictly passive devices, but they would certainly improve both the sensitivity and the directionality of human hearing, combined with some degree of telescopic magnification of human vision.

Some might take umbrage at the fanciful name I've chosen for this technique, but I'm pretty sure it's an important enough technique to deserve a memorable name, and I suspect that reactive resistance to the name tends to be more a symptom of the relatively small intersection between people with a less-than-naive background in cryptography and people with a similar background in signals and systems.

The analogy between cryptography and signals is not completely clarified in my mind. However, I am confident that this analogy is reasonably deep and fertile, at least if you assume that some cryptographic construction exhibits high enough cryptoacoustic advantage for the topic to be viable in the long term. On that count, I am cautiously optimistic, but we need theory before answering that question is really possible.

[![Aircraft engines produced unprecedented sound, so in order to hear them at a distance, the war efforts developed listening devices. A two-horn system at Bolling Field, USA, 1921.](design-documents/media/acoustic_locator_11.jpg)](https://rarehistoricalphotos.com/aircraft-detection-radar-1917-1940/)

The above picture is of a American officer from 1921 using an entirely passive, but extremely large two-horn acoustic aircraft locator at Bolling Field, USA.

There's no technical reason to go with acoustics as the name for the metaphor versus say, something that suggests a different physical transmission medium such as radio waves, visible light, electronic circuitry, or perhaps just a generic "cryptosignaling". However I don't feel cryptosignaling is nearly as memorable or descriptive, and sound is the primary means of communication for most humans in face-to-face physical interactions.

I also went with cryptoacoustics because I am interested in hi-fi audio and professional sound reinforcement systems, and was thinking a fair bit about those topics while I was developing cryptoacoustics. I also thought of my friend Duncan Lowne, who was interested in acoustics, computer engineering, and electronic music under his moniker [Rathumos](https://www.youtube.com/watch?v=dzBHtZ3wxow). Now that I see the metaphor, I'm sure he would understand it, and I'm sure he would be delighted to have his memory tied to the cryptoacoustic transmission medium.

I am sure I would have found cryptoacoustics to be a rather surprising concept as recently as July 2022. That reminded me of the pleasantly surprising acoustics of [Chicago's Field Museum of Natural History](https://www.fieldmuseum.org/), which I remember my [swing choir](https://en.wikipedia.org/wiki/Glee_\(TV_series\)) exploring on a performance-adjacent field trip. While that kind of effect is better experienced in person, Malinda provides a reasonable YouTube demonstration of the kinds of acoustic effects that are possible in [Singing in Church](https://www.youtube.com/watch?v=H6zswBOzxig).

Other classic examples of surprising acoustic effects include [whispering galleries](https://en.wikipedia.org/wiki/Whispering_gallery) and pairs of [acoustic mirrors](https://en.wikipedia.org/wiki/Acoustic_mirror).

I was also amused to first read Niels Provos' retrospective on [Bcrypt at 25](https://www.usenix.org/publications/loginonline/bcrypt-25-retrospective-password-security) sometime in late August or early September of 2023, in a context where I had already compared the cryptoacoustics of bcrypt in the G3P to a subwoofer. I found out that Niels has a cybersecurity-themed EDM (Electronic Dance Music) project under his moniker [activ8te](https://activ8te.bandcamp.com/). EDM music is certainly known for it's relatively heavy use of synth bass, which makes those subs woof.

[![Three Japanese acoustic locators, colloquially known as “war tubas”, mounted on four-wheel carriages, being inspected by Emperor Hirohito.](design-documents/media/acoustic_locator_8.jpg)](https://rarehistoricalphotos.com/aircraft-detection-radar-1917-1940/)

Above is a historical photograph from the 1930s of the Japanese Emperor Hirohito inspecting three military acoustic locators on carts, colloquially known as "war tubas". Each locator has four horns, and each horn is a key part of a highly sensitive directional microphone, which were electrically amplified. They could be turned into potent bass horns if one were to replace the microphones with loudspeaker drivers.

The primary intended use is for pointing the anti-aircraft guns also seen in this picture. Acoustic location soon lost out to radar, but continued to play niche roles for locating aircraft throughout World War II, and for locating artillery fire even after WWII.

Acoustic location for all kinds of purposes, including aircraft, has seen a renaissance during Putin's invasion of the Ukraine. Listening for sound has the distinct tactical advantage of being an entirely passive endeavor, unlike radar. Furthermore, high-quality sound reception equipment has become far more affordable. Finally and most importantly, listening for particular sounds at scale has become possible thanks to integrated circuits and artificial intelligence.

## The Goals of the G3P

Our recurring example of a botnet-based password cracker is really just one of the more surprising and illuminating examples. The cryptoacoustic medium doesn't care about the physical mechanisms that gave rise to a password cracking attack. It abstracts over that entirely. Rather it summarizes over the context of past communications, no matter how these communications occurred.

For example, if the hash thief were to post a crackable version of your password database on an underground forum, then it will be either trivial or at least possible for any individual on that forum to get in contact with you and sell out the thief.

Of course this requires your organization to do three things. First, you must operate a tip line for gathering counterintelligence information. Second, you must rise above the [utterly worn-out IT cliché of metaphorically shooting the messenger who reports any cybersecurity issue](https://soatok.blog/2022/06/14/when-soatok-used-bugcrowd/). If you don't treat your informants with respect, they won't come back. Furthermore you run the risk of developing a bad reputation so that another potential informant declines to engage with your tipline. Third, you must learn to adopt [antifragile](https://en.wikipedia.org/wiki/Antifragile_\(book\)) [attitudes](https://kellyshortridge.com/blog/posts/what-does-the-word-security-mean/) and [practices](https://www.securitychaoseng.com/), and learn to take the information being given to you on your tipline cautiously but seriously.[^inductive_attitude]

In doing so, I hope that it will become increasingly untenable to post password databases where they can be seen by others without drawing the attention of the relevant security departments. In effect, this is an attempt to move towards a closer approximation of [closed-loop](https://en.wikipedia.org/wiki/Closed-loop_controller) detection of leaked password hashes. In the longer run, I hope that will disrupt the activities of the cybercriminal scene. That said, I expect the more profound change in behavior will ultimately be on the part of security departments.

The major design goals for the G3P are that:

1. All HMAC calls and the overwhelming majority of SHA256 blocks should be tagged with at least one self-documenting constant.

2. Follow the guidance of [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) and [NIST Special Publication 800-108r1](https://csrc.nist.gov/publications/detail/sp/800-108/rev-1/final) as closely as possible

3. Offer the strongest API guarantees that are reasonably possible, without introducing extravagant complexity to do so.  Any implementation complexity must result in meaningful payoffs.

## PHKDF

The Password Hash and Key Derivation Function (PHKDF) is a unification and synthesis of PBKDF2, HKDF, and TupleHash.  The name was chosen because the construction it suggests is quite literally a portmanteau of the PBKDF2 algorithm and the HKDF algorithm.

For example, it's not a great idea to use literal PBKDF2 to generate more than one output block worth of data. It would make much more sense to take HKDF apart into it's constituent `HKDF-Extract` and `HKDF-Expand`, and then replace the extraction function with a call to PBKDF2, and feed exactly one output block from PBKDF2 as the pseudorandom key to `HKDF-Expand`.

This is more or less exactly what the [`phkdfVerySimple`](phkdf/lib/Crypto/PHKDF/Primitives.hs) function does. This is included in API documentation as a conceptual simplification of [`phkdfSimple`](phkdf/lib/Crypto/PHKDF.hs), which is a more fully worked example with a reference implementation.

The difference between these examples and the sketch above is that they actually use [`phkdfStream`](phkdf/lib/Crypto/PHKDF/Primitives.hs) instead of literal PBKDF2 and HKDF. This low-level primitive is a mildly dangerous modification of `HKDF-Expand` which is specified in [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869).

The reason `phkdfStream` is mildly dangerous is because it intentionally violates the letter of HKDF's design philosophy of maintaining a clean separation between extraction and expansion. Therefore, naive use of `phkdfStream` can result in some nasty security gotchas. However, it's relatively straightforward to bundle up multiple calls to produce a hash function that is a much safer construction, one that doesn't come with esoteric low-level side-conditions.

Taking that higher-level view, PHKDF affirms the spirit of the HKDF's design principle. It is highly recommended that any complete application of `phkdfStream` itself express a clear distinction between extraction and expansion, even if the lower level building block does not.

A minimal example of a complete high-level application of PHKDF is included in API documentation as [`hkdfSimple`](phkdf/lib/Crypto/PHKDF/Primitives.hs). This demonstrates using two calls to `phkdfStream` in order to taking initial keying material and turning those secrets into an unbounded pseudorandom stream. Any two non-overlapping portions of this pseudorandom stream may be safely revealed or otherwise used independently of each other.

Taking a step up in complexity, [`phkdfVerySimple`](phkdf/lib/Crypto/PHKDF/Primitives.hs) adds key stretching via a single call to the similarly dangerous and low-level `phkdfSlowExtract` function, which itself is two calls `phkdfStream`. Adding in one more call for safe final output expansion, this high-level protocol involves three calls to `phkdfStream` in total. This example is the simplest demonstration of the actual portmanteau that PHKDF recommends using.

The next step is [`phkdfSimple`](phkdf/lib/Crypto/PHKDF.hs), which is the simplest worked example that is provided an actual reference implementation instead of being relegated to API documentation. All the additional features are various niceties. For example, generous length padding is added so that even multi-kilobyte passwords are processed in constant number of cryptographic operations.

This length padding creates another tagging opportunity which is exposed as the `long-tag` parameter which is ideal for conveying longer messages. Another addition is the `echo-tags` vector of bitstrings. The plaintext of each individual bitstring gets hashed exactly three times, providing another great option for longer messages. Finally, the `credentials` vector is added with the intention of supporting Two-Secret Key Derivation (2SKD) schemes not unlike 1Password.

Finally [`phkdfPass`](phkdf/lib/Crypto/PHKDF.hs) adds the ability to safely add additional tweaks and secrets to the final output stream after the expensive key-stretching computation has been completed. While it is essentially a design study for the G3P, it might possibly be of interest for deployment. This function is the G3P minus bcrypt, as the G3P provides a full wrap-around integration of bcrypt inside PHKDF.

## Seguid Protocol

[![THE TORONTO RECURSIVE HISTORY PROJECT
OF TORONTO'S RECURSIVE HISTORY
This plaque was commemorated on October 10, 2018,
commemorate its own commemoration. Plaques like this
one are an integral part of the campaign to support more
plaques like this one. By reading this plaque, you have made
a valuable addition to the number of people who have read
this plaque. To this day and up to the end of this sentence,
this plaque continues to be read by people like yourself
Heritage Toronto 2018](design-documents/media/toronto-recursive-history.jpg)](https://readtheplaque.com/plaque/the-toronto-recursive-history-project)

The [Seguid Protocol](design-documents/seguid.md) is a domain-specific hash function that produces Self-Documenting Globally Unique Identifiers, or _seguids_. Seguids are self-documenting in the sense that they cryptographically attest to their own provenance and their own official documentation for y'all to follow.

The self-referential sign above isn't quite a proper seguid, but there is certainly a meaningful connection. The supply-chain attack alluded to in Ken Thompson's famous 1983 lecture "Reflections on Trusting Trust" is an example of a [offensive Quine](https://research.swtch.com/nih) used to deliver a self-replicating exploit. By contrast, a seguid is an example of a defensive [Quine](https://en.wikipedia.org/wiki/Quine_\(computing\)) used to deliver self-replicating documentation.

The Seguid Protocol turns HMAC's key parameter into a cryptoacoustic tagging location subject to a few mild limitations. The ability to compute an HMAC function does not imply direct knowledge of the HMAC key, and so therefore the key does not have any plaintext cryptoacoustic properties. However, the ability to compute an HMAC function does imply knowledge of a cryptographic hash of the HMAC key, so HMAC keys do have indirect cryptoacoustic properties.

Seguids improve coverage of the G3P by self-documenting tags, thus advancing its first design goal. It also plausibly advances the G3P's second design goal as well, as the seguid protocol is intended to produce outputs that qualify as a [_key derivation key_ (KDK)](https://csrc.nist.gov/glossary/term/key_derivation_key) in NIST parlance.

The Seguid Protocol aspires to be a meta-KDK that can produce the highest quality KDKs on demand, thus providing answers for "what salt should I use for HKDF?" among other questions.

One of the practical advantages of using a strongly-randomized seguid as part of the salt for a deployment of the G3P is that any precomputation of a password hash dictionary is out of the question until after the seguid is created.

Technically, the Seguid Protocol is `HKDF-SHA512` specified with constant salt and info parameters. Since these parameters of HKDF exhibit plausibly-secure cryptoacoustic properties, the Seguid Protocol applies the ideas of self-documenting cryptography to itself and narrates what it is doing. This is to help reverse engineers who are looking at code that implements the Seguid Protocol contextualize what they are looking at. This is a relatively incidental, secondary design feature of the Seguid Protocol.

## Why Adopt Cryptoacoustics?

From a point of view that is particular cautious, my argument for cryptoacoustics is a novel justification for _contextual parameters_. Furthermore, the G3P applies these insights to make specific suggestions about what kind of data to include when contextual parameters are applied to password hashing.[^contextual_parameters_and_password_hashing] This suggested application of cryptoacoustics results in an example of self-documenting cryptography.

I know of no theoretical basis for believing the cryptoacoustic constructions deployed by the G3P are workably secure in the way I conjecture they are. Clearly this situation is not ideal, and should not be tolerated in the long run.

However, in the short run, I'm unconcerned about this state of affairs. Successfully attacking the G3P's cryptoacoustic properties requires a non-trivial response by somebody who cares enough. This scenario would be a secondary cybersecurity concern anyway, as this very concern has been largely or entirely neglected until now.

I often agree with Imre Lakatos's philosophy of science, especially his notion of a _research program_, and suggest treating the idea of cryptoacoustics as a research program.

A total failure of the cryptoacoustic research program, which is relatively unlikely, would only represent a return to today's status quo. A total failure of any specific cryptoacoustic construction, which is well within the realm of plausibility, would not even be recognized as a vulnerability at all by today's standards.

Thus it seems smart to take some of the oldest password hash functions that have continued to be viable for new, well-informed, high-security deployments, and deploy them in a new way that provides incentives to more deeply understand our existing tools from a new point of view.

Whether or not the particular cryptoacoustic constructions employed by the G3P stand up to scrutiny in the long term, deeper study of these issues might someday pave the way for new cryptographic hash functions that have enhanced cryptoacoustic potential by maximizing the _minimum obscuration overhead_ for contextual parameters.

## Cryptoacoustics as Watermarking

Cryptoacoustics is an alternative form of _digital watermarking_. However, I don't expect the existing literature in this subfield to be of much direct benefit to developing a proper theoretical basis for cryptoacoustics, as there seems to always be differences in assumptions that often seem irreconcilable.

For example, Wikipedia describes [digital watermarking](https://en.wikipedia.org/wiki/Digital_watermarking) as "a kind of marker covertly embedded in a noise-tolerant signal such as audio, video or image data." By contrast, cryptoacoustics attempts to _overtly_ embed a tag into a noise-_intolerant_ signal, namely the inputs to a cryptographic function.  This intolerance for noise hopefully serves as a bulwark against obfuscation.

The literature usually requires that a watermarked signal be nearly identical to the original signal. By contrast, a tagged hash should be statistically independent from any untagged hash without access to the underlying cryptographic secrets. This property helps provide the plausible deniability of any given tag.

The tagged hash and untagged hash should be completely different hashes, yet these two hashes should also be indistinguishable in the sense of determining which hash is associated with which tag. For this reason, cryptoacoustics should prove to be much more robust than more traditional forms of digital watermarking, as it's starting from much stronger assumptions.

## Cryptoacoustics and Obfuscation

The existing literature on [program obfuscation](https://blog.cryptographyengineering.com/2014/02/21/cryptographic-obfuscation-and/) is much more likely to be relevant to building a proper theoretical foundation for cryptoacoustics. Most famous is the paper "[On the (Im)possibility of Obfuscating Programs](https://www.iacr.org/archive/crypto2001/21390001.pdf)" by Barak et al.

While a cursory reading of this paper might suggest that it supports the plausibility of cryptoacoustics, I'm unconvinced that a more careful reading of this paper either supports or detracts in any significant way.

In particular, the unobfuscatable property demonstrated in the aforementioned paper is not directly useful for creating a general-purpose plaintext tagging construction. Furthermore, it seems far from obvious that this particular construction (or something like it) can be used for any practical purpose.

At the time the paper was written, whether or not full homomorphic encryption was even possible was still an open question. Surprisingly, FHE does exist, which seems to rule out many or most practical use cases for a truly unobfuscatable program property in the sense of Barak et al.

Cracking a password hash is a rather costly endeavor that is particularly sensitive to inefficiency. For this reason, cryptoacoustics need not rely a notion of "unobfuscatable" that is as stringent as found in Barak et al.

What is crucial is _cryptoacoustic advantage_, which seems to be (nearly) synonymous with _cryptoacoustic efficiency_ and _minimum obfuscation overhead_.

As mentioned before, +20 dB would probably be enough to make slow password hashing cryptoacoustically viable, but other applications may need more like +60 dB or more.

For example, the Seguid Protocol is HKDF-SHA512 that specifies constant salt and info parameters. Correspondingly, the Seguid Protocol uses these parameters as cryptoacoustic tags, narrating itself in an attempt to help out any reverse engineer who is examining such implementations contextualize what they are looking at.

Since the Seguid Protocol applies no key stretching, millions of hashes can be computed per second. Thus the most efficient tag obscuration attack may need to impose 1,000,000x overhead or more in order to be truly effective in this scenario. For this reason, slow password hashing seems to be a best-case scenario for the application of cryptoacoustics.

Thus the point of _cryptoacoustic repetition_ as employed by PHKDF and the G3P is to reduce the minimum obfuscation overhead that is required of a "small" cryptoacoustic construction in order for a larger protocol that depends on it to be viable.

For this reason, it is much easier to deploy practical tag obscuration attacks against the Seguid Protocol than PHKDF or the G3P. On the other hand, it's also far less clear what practical benefits this might confer to an attacker.

At my own current level of understanding of my own design, incorporating cryptoacoustics into the Seguid Protocol itself is mostly an issue of design consistency, though there may well be advantages and benefits I don't currently appreciate.

On the other hand, this is a problem for password hash functions such as argon2. While appending a tag after the password has cryptoacoustic properties, that input is a horn-loaded parameter into the internal argon2 algorithm. This means we can discard the password _and tag_ during the key-stretching computation.

In our metaphor of the cryptoacoustic Enigma machine applied to argon2, it's a bit like as if the prerecorded tape played one little thing quietly, and then went completely silent for the rest of the song-and-dance routine. Unfortunately, this arrangement is inherent to argon2 because there simply no way to include cryptoacoustic repetitions of the tag during the key-stretching phase.

As a result, the cryptoacoustic security of this argon2-based construction is relatively dependent on blake2 exhibiting high minimum obfuscation overhead, in much the same way that the Seguid Protocol is similarly dependent on the cryptoacoustic efficiency of SHA512.

I don't believe it would be particularly difficult to tweak argon2 in some way to enable cryptoacoustic repetition throughout the key-stretching phase, but then it wouldn't be argon2.

## Cryptoacoustic Safety

Many programmers and some mathematicians would unthinkingly react with the following argument: there's no theoretical basis for cryptoacoustics, which is all based on informal inductive guesswork anyway, and therefore cryptoacoustics has no business being in anybody's password hash function.

I openly admit that the propositions of this argument are true. There is currently no theoretical basis for cryptoacoustics that I am aware of. I also admit that I'm taking an educated shot into the dark on cryptoacoustics, hoping to hit my target. I will even admit that at the present time I have little to no intention to develop a proper theoretical basis for cryptoacoustics myself, but I certainly encourage any and all who are so interested to work on that.

However, I don't believe the conclusion follows from these acknowledgments. In fact, I think everybody should incorporate cryptoacoustics into password hash functions and their deployments. You only have to do a cost/benefit risk analysis to understand why.

In a worst-case scenario, a total failure of cryptoacoustics would only mean that an attacker managed to obscure our tags without incurring substantial overhead. This wrecks the G3P's secondary security goal that output hashes should be _traceable-or-useless_, but leaves untouched the primary security goal of being slow to compute and not directly reversible. On this count, the G3P is almost certainly at least as good as PBKDF2 and also at least as good as Bcrypt.

This type of hedging is a major design theme in the G3P. Yes, my conjectures are shooting into the dark, but the point is that I'm not hunting grues, and my target might actually be quite large. In stark contrast to the Sagan Standard of probability and statistics, exotic design properties can sometimes be implemented using only the most mundane techniques. In this way, the G3P is placing design bets on tweaks that have little to no downside risk, and are reasonably likely to pay off big.

Moreover, I'm not shooting into the dark once, but twice, hedging the cryptoacoustic properties of the G3P between PHKDF and bcrypt. If the _cryptoacoustic advantage_ of either SHA256 or blowfish's expensive key expansion functions turns out to be impractically low, the G3P still has the other function family to pin its cryptoacoustic hopes on. The ultimate success of these two attempts at a secure cryptoacoustic construction are not likely entirely independent of each other, but the G3P is certainly not repeating the exact same attempt twice.

Though qualitatively describing the similarities and differences between the cryptoacoustic properties of PHKDF and bcrypt can be a useful exercise, a quantitative comparison would almost certainly require a theoretical basis for cryptoacoustics.  At that point we definitely need a light to keep the grues away.

Maybe someday humanity will even see low-level cryptographic hash functions designed to maximize the minimum obfuscation overhead, thus maximizing the cryptoacoustic potential of that specific hash function.

[^steampunk]:
    If this metaphor is taken a bit too literally, it does have a subtle but undeniably steampunk vibe. Analog audio introduces noise, but inputs to a cryptographic hash function are noise-intolerant. This kind of fundamental incompatibility is rarely a problem in a steampunk story line.

    On the other hand, digital audio requires electronics that can operate much faster than electromechanical switches, so why would the Cryptoacoustic Enigma Machine still be using rotors?

    On the other hand, a non-aural mechanical "cryptoacoustic" enigma machine based off of teletype terminals or punched tape might be sort-of viable, at least by the standards of decades gone by. But that's not as memorable a metaphor.

[^tipline]:
    Of course, I would recommend your [security.txt](https://securitytxt.org/) consist of a website and/or email address, not (just) a telephone answering machine. Also, you might not want to advertise a literal address directly in a G3P deployment itself, because that deployment can be very difficult to change. Thus it may be sensible to to use your G3P deployment to advertise a URI to your security.txt instead.

[^replaying_hashes]: Depending upon how a hash is intended to be used, it may or may not be possible to replay it as an authentication credential. I assume that if one knows where to replay the hash, one knows where to report it stolen, which doesn't really pose a problem for our slogan of _traceable-or-useless_.

[^blake3]: Blake3's embedded Merkle tree enables parallel processing on long inputs, but it also presents challenges to cryptoacoustic applications. If one were to simply append a tag after user-supplied inputs, then (parts of) a tag might be replaceable by some other value. From this naive point of view, blake3 replaces it's tape deck with something a bit more esoteric.

[^contextual_parameters_and_password_hashing]:
    The application of contextual parameters to password hashing is an idea I originated independently. Though I don't have any references at hand, it also feels like an idea that probably isn't exactly entirely novel. In any case, the use of contextual parameters during password hashing is not widely practiced or advocated for.

    On the other hand, the interrelated ideas of cryptoacoustics and self-documenting cryptography feels rather novel to me. I still find parts of the idea surprising. To me, the trick feels vaguely reminiscent of the [100 prisoners problem](https://en.wikipedia.org/wiki/100_prisoners_problem).

[^group_operation]: This also works when any kind of easily invertible group operation is used to perturb the state machine.

[^cryptoacoustic_efficiency]:
    Cryptoacoustic advantage, which suggests vocabulary commonly used cryptography, would seem to be synonymous with _cryptoacoustic efficiency_ in an analogy to the efficiency of a loudspeaker. For example, the sound pressure level produced by a pair of bookshelf speakers at 1 watt is typically around 85 dB or so.


[^inductive_attitude]:
    In our personal life we often cling to illusions. That is, we do not dare to examine certain beliefs which could be easily contradicted by experience, because we are afraid of upsetting our emotional balance. There may be circumstances in which it is not unwise to cling to illusions, but in science we need a very different attitude, the _inductive attitude_. This attitude aims at adapting our beliefs to our experience as efficiently as possible. It requires a certain preference for what is matter of fact. It requires a ready ascent from observations to generalizations, and a ready descent from the highest generalizations to the most concrete observations. It requires saying "maybe" and "perhaps" in thousand different shades. It requires many other things, especially the following three.

    First, we should be ready to revise any one of our beliefs.

    Second, we should change a belief when there is a compelling reason to change it.

    Third, we should not change a belief wantonly, without some good reason.

    These points sound pretty trivial. Yet one needs rather unusual qualities to live up to them.

    The first point needs "intellectual courage." You need courage to revise your beliefs. Galileo, challenging the prejudice of his contemporaries and the authority of Aristotle, is a great example of intellectual courage.

    The second point needs "intellectual honesty." To stick to my conjecture that has been clearly contradicted by experience just because it is _my_ conjecture would be dishonest.

    The third point needs "wise restraint." To change a belief without serious examination, just for the sake of fashion, for example, would be foolish. Yet we have neither the time nor the strength to examine seriously all of our beliefs. Therefore it is wise to reserve the day's work, our questions, and our active doubts for such beliefs we can reasonably expect to amend. "Do not believe anything, but question only what is worth questioning."

    Intellectual courage, intellectual honesty, and wise restraint are the moral qualities of the scientist.

    - G. Pólya, "Mathematics and Plausible Reasoning, Vol I: Induction and Analogy in Mathematics", Chapter 1, Section 4. See also the [Tools of Math Construction](https://github.com/constructive-symmetry/constructive-symmetry), a study guide regarding math, logic, and reason.
