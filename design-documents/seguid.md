# The Seguid Protocol for Self-Documenting Globally Unique Identifiers

(by Leon P Smith, Auth Global)

This work is licensed under a Creative Commons Attribution-ShareAlike 4.0 International License.

## Abstract

A seguid is an identifier that can be followed back to its origin with the help of a search engine. The origin can then be validated against the seguid itself. The first intended use case for seguids are as constant identifiers used to delineate a specific deployment of a cryptographic protocol. Follow the seguid, y'all!

Short for Self-Documenting Globally Unique Identifier, seguids are designed for reverse engineering. It's not uncommon that an software engineer or security analyst struggles to find relevant documentation when reading or reviewing cryptographic code. Sometimes they aren't even directly aware this is a problem. These problem is especially acute when the code is a payload observed on a botnet.  Such payloads are often of unknown origin and may have an unclear purpose. Seguids are an attempt to improve these stories in the case of publicly-disclosed identifiers.

The preferred way to generate seguids is to use the _Seguid Protocol_, which is a domain-specific cryptographic hash function that comes tightly bundled with strong opinions about how that hash function is intended to be applied and its results interpreted. Specifically, the inputs are intended to be Uniform Resource Identifiers (URIs) that point to relevant documentation and other artifacts. This hash function then outputs an identifier which is _transparently derived_, _self-documenting_, and _globally unique_ in cryptographically strong senses of these phrases.

A seguid is _transparently derived_ in the sense that the inputs to the hash function are not intended to be secret, and are in fact intended to be published for the whole world to see. A seguid is _self-documenting_ in that these input parameters immutably attest to it's own official sources of documentation and other relevant artifacts via URIs.

Because the Seguid Protocol expects the use of a Uniform Resource Locator (URL) that points to a webpage where a creator will be publishing documentation relevant to their Seguid, the Internet's Domain Name System (DNS) as administered by ICANN is included in the cryptographic domain separation provided by the Seguid Protocol.

A seguid is _globally unique_ thanks to the preimage and collision resistance of the HKDF-SHA512 cryptographic hash function working in conjuction with the domain separation provided by the usage guidelines. Moreover, global uniqueness can be optionally be reinforced with additional strong randomization.

Seguids are _indirectly_ self-documenting in the sense that if you are starting from nothing more than a literal bitstring, you will require a search engine to find the corresponding derivation of the seguid. By contrast, a _directly_ self-documenting constant cannot rely on external means to deliver its message.

An example of a directly self-documenting constant used in this paper is the info parameter to HKDF-SHA512. Here we place URLs to the official documentation for the Seguid Protocol, so that anybody who is capable of computing the seguid hash function themselves must necessarily know the official documentation URL.

This complementary notion is more usefully applied and more throughly explored in the companion document, "The Global Password Prehash Protocol G3P, a Case Study in Self-Documenting Cryptography". That proposal uses directly self-documenting constants to achieve domain separation between authentication services, thereby enhancing the traceability of stolen password hashes.  The G3P Protocol also serves as a case study in applying the Seguid Protocol.

Though the Seguid Protocol is likely to prove useful in other contexts, this document has a specific emphasis on choosing constant, publicly-known salts for derivation protocols based off of keyed cryptographic hash functions.  This is useful not only for deploying the G3P, but also most key derivation protocols based on HKDF, many protocols based on HMAC, and all protocols that are compliant with NIST Special Publication 800-108.

## Introduction to the Seguid Protocol

The Seguid hash function accepts a list of arbitrary bitstrings as inputs.  The encoding used by this function ensures that one cannot trivially find collisions by say, moving bits between strings, by permuting the order in which the strings appear in the list, or even by deleting, adding, or moving empty bitstrings.  Moreover, varying the output length parameter completely changes the result as well, so there are no easy collisions there either.

```
SEGUID-V1 : (
    args : Vector<BitString>,
    bits : Integer{ 0 <= bits <= 130560 } = 512
  ) -> BitString
```

To derive your first Self-documenting Globally Unique Identifier, first choose a URL at which you will be publishing documentation regarding your seguid. Then hash your chosen URL with the seguid protocol's hash function:

```
your-self-documenting-guid = SEGUID-V1 (
    [ "https://your-domain.example/link/to/docs/for/your/seguid" ],
  )
```

At this URL you need to publish a hexadecimal encoding of your literal seguid, along with the parameters to the seguid hash function that you used to derive it.   So that observers can follow your seguid back to its source, you need to ensure that this webpage is allowed to be indexed according to your website's `robots.txt`, and that several major search engines find it. This webpage should document how your seguid is intended to be used and in what contexts.

If your seguid is intended to be used as a constant key to an `HMAC` function, such as `HKDF-Extract`'s `salt` parameter, or `HKDF-Expand`'s pseudorandom key (`prk`), or the G3P, then that seguid's documentation webpage also needs to publish two additional cryptographic hashes derived from the seguid itself.  This is because these precomputed hashes can be shared in leiu of the HMAC key.  When code found in the wild includes only precomputed keys, we want to ensure that software developers, security engineers, and reverse engineers still have an easy time following the seguid back to its verifiable source.

You may include additional URIs in the bitstrings that follow the first parameter.  For example, maybe you want to include links to an arxiv paper, github, or other well-known sites for supplemental documentation and relevant useful artifacts.  That's allowed too, and these additional sources need not contain the derived seguid that is required to be published at the first URL:

```
your-alternate-seguid = SEGUID-V1 (
    [ "https://docs.your-domain.example/your-alternate-seguid",
      "https://tools.ietf.org/html/rfc3986",   // RFC for URIs
      "https://tools.ietf.org/html/rfc5869"    // RFC for HKDF
    ]
  )
```

These first two examples are _weakly_ self-documenting. Even though the derivations of these seguids specify one or more URLs at which official documentation can be found, the documentation behind these URLs can change over time.  By contrast, a _strongly_ self-documenting seguid attests to some unchangable, immutable version of its own documentation.

Yet it is important to be weak!  Weak self-documentation via mutable references seems to play an essential role in the Seguid Protocol that strong self-documentation via immutable references does not.  We need search engines to index our literal seguids, so that so that people who are starting from a literal seguid can easily find its official documentation.

The strong documentation cannot itself publish the resulting seguid as a literal constant.  Because this documentation is used to derive the seguid, changing the documentation changes the seguid itself. Thus the strong documentation cannot publish what we need to publish.

The InterPlanetary Name System (IPNS) is a mutable reference that is much more secure than an HTTPS URL, and provides with additional benefits. An IPNS Uniform Resource Identifier (URI) encodes a self-certified public key in the URI itself. The URI provides cryptographic evidence that somebody had the corresponding private key, at least once upon a time.

An IPNS address that is under your control sets up a strongly authenticated channel for publishing information and updates about your seguid. Including such a URI also has the very nice benefit of strongly randomizing the resulting seguid, because the public key encoded in the address represents a level of entropy equal to the private key, which itself is supposed to be a high-entropy secret.

```
your-strongly-randomized-seguid = SEGUID-V1 (
    [ "https://docs.your-domain.example/your-strongly-randomized-seguid",
      "ipns://your-public-key-address-here"
    ]
  )
```

One could even consider forgoing the URL altogether in favor of relying solely on IPNS, but for the time being this seems quite an adventurous choice with unclear benefits.  If you don't have a domain name and don't want one, consider whether using a link to a public source-code repository under your control as the canonical source of documentation is a reasonable fit for your needs.

A weakly self-documenting seguid doesn't require documentation up-front, which means it can be an expedient choice during development. Once documentation of sufficient quality has been prepared, you should consider deriving a new strongly self-documenting seguid at some point, especially if the weakly-documented seguid hasn't been publicly revealed yet, or you have an otherwise opportune occasion to migrate seguids.

Some URLs include cryptographic hashes of (some of) the content behind URL.  Examples include the github permalink in the example below. If strong documentation is implemented in this way, there's no systematic way of enforcing the relationship between the URL and the content it attests to.  The content behind these URLs can still change, and typical visitors to the URL won't ever verify the hash against the documentation.

I highly recommend the use of InterPlanetary FileSystem (IPFS) Content Identifier (CID) Uniform Resource Identifiers (URIs) for creating, publishing, and managing strongly self-documenting seguids. A content identifier does not specify a location where the file is stored, but instead specifies the content of the file itself.  The content identifier does not enable one to directly figure out what the content of the file is, but it does allow anything that purports to be the desired content to be verified against the CID.

```
your-strongly-documented-seguid = SEGUID-V1 (
    [ "https://docs.your-domain.example/your-strongly-documented-seguid",
      "ipfs:// TODO: prepare an actual content identifier to include here",
      "TODO: prepare a github permalink here that leads to a discussion of such permalinks"
    ]
  )
```

Thus the IPFS network serves a bit like a distributed search engine for discovering the location of the files that correspond to content identifers, much like seguids require search engines to go from the literal seguid to its documentation.  This way, IPFS also makes it easier for potential seguid archivists to systematically locate, index, replicate, and redistribute documentation and other relevant artifacts.

For this reason, the Seguid Protocol asks creators to take care regarding copyright, licensing, and other intellectual property issues surrounding documentation and other artifacts they publish on IPFS. If a copyrightable asset is not allowed to be freely redistributed to the general public, and you are unwilling or unable to grant that permission, then you must not publish that content on IPFS.

In the common case where the creator of a seguid holds any copyright interests in the documents referenced by a seguid's IPFS content identifer, the Seguid Protocol asks that the creator to openly license all such copyright interests to the general public under terms that allow for free redistribution.

The Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License is one of the most restrictive licenses currently available that satisfies this requirement.  At the other extreme, a public-domain dedication, renouncing all copyright interests to the maximum extent allowed by law, is another alternative.  In between, there number of appropriate licensing options available, including a range of other Creative Commons licenses, the GNU Free Documentation license, and many standard licenses used by open-source software projects.

Similarly, creators must take care that they respect the copyrights and licensing of third parties in any documentation or other artifacts they publish to IPFS. If you have doubt that you have the ability to grant free redistribution of a copyrightable asset to the general public, you should refer to the third-party asset by name, by URL, by URI, by ISBN, by DOI, and/or other appropriate indirect identifiers. If you wish to ensure that you are referencing a specific version of an asset, you could additionally include a cryptographic hash of it.

Of course, one can combine both IPFS and IPNS URIs to get the all benefits of strong documentation, strong randomization, and setting up an authenticated channel for future publication. In fact, this is exactly what Version 2 of the Seguid Protocol's _global salt_, `seguid-v2-salt` will do.

```
seguid-v2-salt = SEGUID-V1 (
    [
      "https://docs.auth.global/seguid-v2",
      "ipfs://${self-cidv1}/docs.auth.global/seguid-v2/${self-hash}.md",
      "ipns:// TODO: fill this in before the release of Version 2"
    ], bits = 1024
  )

SEGUID-V2 (args, bits = 512) =
  SEGUID-PROTOCOL-V0 (
    salt = seguid-v2-salt,
    msgs = args,
    info = "https://docs.auth.global/seguid-v2",
    bits = bits
  )
```

Version 1 of the global salt include both HTTPS and IPNS URIs, to get a strongly randomized global salt with a strongly authenticated channel for publishing official documentation.  It will be strongly self-documented, though not necessarily with a final official specification for the Seguid Protocol V1.  Thus the strong attestation would document what the Seguid Protocol is intended to be, though the strongly-attested documentation wouldn't necessarily be 100% authoritative for V1 of the Seguid Protocol.


```
seguid-v1-salt = SEGUID-V0 (
    [
      "https://docs.auth.global/seguid-v1",
      "ipns:// TODO: fill this in before any release at all",
      "git:/ TODO: fill this in after it's been generated"
    ], bits = 1024
  )

SEGUID-V1 (args, bits = 512) =
  SEGUID-PROTOCOL-V0 (
    salt = seg
    msgs = args,
    info = "https://docs.auth.global/seguid-v1",
    bits = bits
  )
```

Version 0 of the global salt, the _preinitialization salt_, is a _nothing-up-my-sleeve_ constant 128 bytes long, inspired from the initialization vectors of the SHA-2 family of functions.

```
seguid-v0-salt = f(1) || ... || f(32)

f(n) = the fractional part of the n^th prime integer to the 3/4 power, truncated to 32 bits

SEGUID-V0 (args, bits = 512) =
  SEGUID-PROTOCOL-V0 (
    salt = seguid-v0-salt,
    msgs = args,
    info = "https://docs.auth.global/seguid-v0",
    bits = bits
  )
```

Finally, the underlying cryptographic protocol is implemented on top of HKDF-SHA512 using TupleHash's `encode_string` padding function borrowed from NIST Special Publication 800-185.  Note that while all the deployments of the seguid protocol defined above require the output bitlength to be less than or equal to 130,560 bits, the underlying protocol doesn't care if `bits` is greater than that.  However, do realize this is technically an extension/violation of HKDF's official specification.

Alternatively, you could implement an HKDF-like construct by stringing together two calls to PHKDF-STREAM, which doesn't itself impose this limitation.  However this would be an odd choice, as the stream generator used by HKDF and PHKDF is rather slow.  If you need a large amount of pseudorandom data, it may make much more sense to use one or more of these functions to seed a faster (CS)PRNG.

```
SEGUID-PROTOCOL-V0 (
    salt :: BitString,
    args :: Vector<BitString>,
    info :: ByteString,
    bits :: NonnegativeInteger,
  ) -> do

  prk = HKDF-Extract-SHA512 ( salt, ikm = concat-map(encode_string, args) )

  return HKDF-Expand-SHA512-BitLength-Strict ( prk, info, bits )
```

This application of HKDF-Expand simply makes the output length non-colliding by encoding the length into the info field using TupleHash's `left_encode` padding function.  It also allows an arbitrary number of bytes to be output by using plain HKDF-Expand to output the requisite number of bytes, and then truncate the requisite number of bits.

```
HKDF-Expand-BitLength-Strict (prk, info, bits) =
  if bits <= 0:
    return ""
  else:
    return HDKF-Expand-BitLength (prk, left_encode(bits) || info, bits)

HDKF-Expand-BitLength (prk, info, bits) =
  if bits <= 0:
    return ""
  else:
    bytes-to-generate = (bits + 7) div 8  // i.e.  ceil(bits / 8)
    bits-to-truncate  = (- bits) mod 8    // must be in range 0..7
    bytes = HKDF-Expand (prk, info, bytes-to-generate)
    bytes[-1] &= (255 << bits-to-truncate)
    return bytes
```

I generally recommend 256-512 bit output lengths for most seguids. Beyond that recommendation, deriving a seguid that is less than 160 bits long significantly weakens its globally-unique and self-documenting properties. I recommend a minimum length of 224 bits. I also recommend sticking to an output lengths that are multiples of 8 bits so that you get a full bytestring, unless you have a specific reason not to. Also, HKDF-SHA512 technically specifies a maximum output length of 16,320 bytes.  Thus seguids should not be longer than 130,560 bits.

## A Seguid Protocol Description

The goals of the previous section were to informally introduce the Seguid Protocol, to unambiguously define its hash function, and constrain the form that its initialization vector will ultimately take.  The goal of this section is to provide a more comprehensive description of how the hash function is intended to be used.

The first bitstring argument to the Seguid hash function must be an RFC 3986-compliant Uniform Resource Identifier (URI) at which the creator will be posting documentation relevant to the derived seguid.  The content behind this URL should be indexable, and I strongly recommend using the `https://` or at least `ipns://` URI schemes. The webpage linked to by this URL must include the derived seguid literal itself, encoded as hexadecimal, and must include the bitstrings that generated it. This webpage should also include any relevant documentation, and any useful links to other publicly-available artifacts relevant to this seguid.

Subsequent bitstrings must also encode RFC 3986-compliant URIs, up until the occurrence of the first empty bitstring. These URIs should point at documentation and other relevant artifacts as well. In particular, the use of InterPlanetary File System (IPFS) and InterPlanetary Name System (IPNS) URIs is strongly encouraged.

The Seguid Protocol may be extended in the future. Every case where the first empty bitstring is followed by a non-empty bitstring is reserved for these possible future extensions. However, if the first empty bitstring is followed by a second empty bitstring, then the meanings of all subsequent arguments are defined by the initial sequence of URIs, which must be non-empty. This provides a sandbox in which you can experiment with your own local extensions to the Seguid Protocol without running any risk of ever conflicting with official future extensions, or any other initial sequence of URIs.

It's important to remember that one of the primary intended purposes of the Seguid Protocol is for generating your very own domain-specific, globally unique cryptographic hash functions, tightly bundled with a description of how your specific hash function is intended to be used.  Instead of using a local extension of the Seguid protocol, you could derive an seguid, specify that it is to be used as a constant salt to SEGUID-PROTOCOL-V0, and describe what the inputs to your hash function are supposed to mean.

The result is that your seguid specifies its own hash function that behaves just like SEGUID-V1, except now there are absolutely zero constraints on how the arguments of your new hash function are to be interpreted. Therefore, before you embark on an experiment in extending the Seguid Protocol, you might want to have an answer for the question "Why not use the Seguid Protocol to create your very own domain-specific hash function instead?"

TODO?  Discussion of IPNS vs DNS and traditional URLs?

### Design Discussion

The seguid protocol's _global salt_ (`seguid-v2-salt`) will verify the content of the very document you are reading, therefore this document cannot specify this constant without invoking some form of self-reference.  The purpose of this document is to eventually provide a immutable description of how the global salt is intended to be used, thus verifiably associating it with the seguid protocol.

When creating strongly documented seguids, in most (or all?) cases there seems to be no real reason for a document to unambiguously and precisely specify the exact literal seguid constant(s) it will eventually be paired with.

Rather, the document can simply assume the existence of one or more named constants such as `seguid-v2-salt` or `your-strongdoc-seguid`, and then describe how those named constants are intended to be used.  The immutable association is created when one or more literal seguid constants along with their derivation are published in the mutable locations specified by the inputs to the seguid hash function.  This fills in the named constants, and handles the self-reference necessary for strong documentation very naturally, in a way that can be easy to miss.[^letrec-scheme]

Though this specification constrains the form the global salt will eventually take, it does not unambiguously specify the value the global salt will be. Even though this ambiguity is likely acceptable, I also expect it to be useful to constrain the form the derived seguid(s) will eventually take.

In the case of this document, the main ambiguity is the `${self-cidv1}` reference. In order for this document to provide a self-contained specification of a precise final value for the global salt, it would also have to specify the other files provided at that IPFS Content ID address.

The Seguid Global Salt is strongly randomized. The IPNS address included in this document corresponds to a high-entropy private key generated uniformly at random by computers owned by the author and under his control. Strong randomization is particularly beneficial when choosing constant, publicly-known keys for HMAC-SHA256. Technically, the information-theoretic entropy of this document almost certainly dwarfs that of the IPNS address, however the entropy of this document can only be estimated, whereas the entropy of an IPNS address can be directly calculated.

For example, RFC 5869 recommends choosing HKDF's salt uniformly at random if possible, which this proposal takes seriously. If you are using the seguid protocol to derive an constant, publicly known salt as the initialization vector for an HKDF-based key derivation protocol, you automatically benefit from the strong randomization built-in to the seguid protocol via this author's private key.

Even better, you yourself can ensure strong randomization by generating your own IPNS address and including it in the derivation of your seguid.  Moreover, this also sets up an authenticated channel on which you can publish future material regarding your seguid.

Cryptographers also prefer constants that have nothing up their sleeve. This notion is fundamentally incompatible with strong randomization. Seguids have at least one private key up their sleeve. However, seguids are also transparently derived from published inputs to HMAC-SHA256. Transparent derivation allows us to salvage the most salient aspects of the cryptographer's notion of _nothing-up-my-sleeve_ in this context.

In this context, choosing the `seguid-v1-salt` is a relatively low-stakes endeavor, cryptographically speaking. Even if I were a supervillian who directly specified the global salt in a somehow "nefarious" way, the seguid protocol is just one strong randomization away from foiling... whatever plot that was.  Moreover, although the seguid's notion of _transparent derivation_ is relaxed relative to the cryptographer's notion of _nothing-up-my-sleeve_, allowing transparently derived constants enables tangible benefits in return, enhancing domain separation and allowing for self-documentation, strong randomization, and setting up cryptographically authenticated channels for future publication.

In order to be safe, cryptographic encodings such as `encode_args` above need to be one-to-one and well-defined functions. After all, when composing `f . g`, where `f` it doesn't matter if `f` is collision-resistant when `g` is not.  Thus in the common case that `f` is a cryptographic hash function and `g` is a function that encodes some type into bitstrings,  we want `g` to be a one-to-one function, that is, `g(a) == g(b)` implies `a == b`.

Conversely, g is a well-defined function when `a == b` implies `g(a) == g(b)`. This issue conceptually arises in JSON-based encodings. For example, the JSON strings `{"foo":1,"bar":2}` and `{"bar":2,"foo":1}` are considered to be equivalent syntactic representations of the same JSON dictionary, yet these two strings have different cryptographic hashes. While hashing a string (that happens to represent a JSON value) is a perfectly well-defined function of strings, this is not a well-defined function of JSON values,  because a single JSON value can result in different hash outputs depending on how exactly that JSON value is syntactically represented.

InterPlantary FileSystem Content Identifiers (IPFS CIDs) are an example where well-defined encodings are in fact important; IPFS endeavors to ensure that any bit-for-bit identical collection of files and filenames results in the same CID.  Accomplishing this in practice includes unambiguously specifying things such as the order in which filenames and the contents of those files will be included in CIDv1's hashing protocol.

One could deploy a seguid-like construct to a context that is uncontrolled, unexpected, and/or uncommitted.   Alternatively, one can deploy a seguid to a context that is controlled, expected, and committed.  The latter is preferred, as it allows stronger conclusions to be drawn.  For example, there are confidence tricks that exploit this subtle difference.

For example, a confidence trickster could make use of unforgeable timestamps to say, reliably reveal a cryptographic hash to a statement prepared before a major sporting event that contains a reasonably precise and accurate description of what happened at that event. The trick is simply to prepare beforehand enough different predicted outcomes that one of them will be close enough to being correct. Once the result of the sporting event is known, the confidence trickster can then choose which prediction to reveal.

To be a more honest prediction, a speculator needs to reveal a hash before the event that commits them to a single prediction.  However this alone isn't quite sufficient: a variation of our confidence trickster might take this superficially more honest approach, but provides different predictions to different people.  Ultimately a few of the people will see some amazingly good predictions, and thus may become vulnernable to future depredations by the confidence trickster. So an even more honest sports speculator needs to make a commitment to a single prediction that the whole world can see.

A primary goal of the Seguid Protocol itself is to help construct a more completely committed context for deploying seguids, and for easily transferring this onto new domain-specific hash protocols.  One of the oft-overlooked practical aspects of applied cryptography is how various constructions relate contexts to each other.

My go-to example of this phenomenon is that the statement "message X has a valid digital signature, therefore message X is valid".  This might not be wrong, but is certainly extremely misleading. Rather, it's far more useful to emphasize that a valid signature connects the validity of a message X to the validity of the public key that verifies the signature, nothing more and nothing less.  Furthermore, the interpretation of a message with a valid signature depends on context.  Messages with valid signatures will often need to be subjected to further security validations and sanity checking, depending on whatever policies are appropriate for that context.

The previous paragraph is well-known information to a wide variety of professionals who somehow work with cryptography.  Yet it's suprising how often this is received as profound new information, even to an audience of highly technical IT engineers and administrators.

The Seguid Protocol aspires to be a reasonably general-purpose tool for creating and binding together cryptographic contexts in ways that are more finely delineated, and more tightly bound, than many common "best practices" seen today.  In doing so, the Seguid Protocol hopes to improve the security posture of many cryptographic deployments in ways both theoretical and practical.

## History


[![THE TORONTO RECURSIVE HISTORY PROJECT
OF TORONTO'S RECURSIVE HISTORY
This plaque was commemorated on October 10, 2018,
commemorate its own commemoration. Plaques like this
one are an integral part of the campaign to support more
plaques like this one. By reading this plaque, you have made
a valuable addition to the number of people who have read
this plaque. To this day and up to the end of this sentence,
this plaque continues to be read by people like yourself
Heritage Toronto 2018](media/toronto-recursive-history.jpg)](https://readtheplaque.com/plaque/the-toronto-recursive-history-project)

A fine example of a proto-seguid found in its own native habitat.

To invent seguids, break apart the concepts embodied in the self-referential sign of the Toronto Recursive History Project, and distill one of those concepts into a Y-like combinator.  Use the ideas behind "Y in Practical Programs" to weave some Merkle-tree cryptography into this fixpoint.  Add a generous helping of Programming Language Theory and a smidge of the Theory of Computation, and work and rework these basic ingredients until they form a cohesive and unified whole.  Finish with a protective glaze of numerology.

This author has long been interested in exploring the outer limits of self-reference. This author also has a long personal history of dealing with (or rather, largely failing to deal with) some of the most outrageous and obstinate liars imaginable, at least by the contemporary standards of 2023. Developed as a tool for documenting dishonesty, seguids are response to these sorts unfortunate life experiences that are now being experienced by large numbers of people worldwide.

Of course the most outrageous liars are invariably supported by a network of willfully blind enablers and reluctant witnesses. Oftentimes those liars also have one or more enthusaistic accomplices. There is no technological solution for observers who are in denial, fatigued, intimidated, complicit and/or corrupt. Yet seguids can be used to make some truths more directly knowable, hopefully tilting the social landscape ever so slightly away from pathological lies.

To provide grist for Feyerabend's slogan that _anything goes_, seguids drew significant inspiration from numerology. The original idea was to attach numerological significance to the configuration of a computer system, say by using a cryptographic hash as a configuration constant that is absolutely essential to deployment of the system. If somebody then chooses to try to lie about the origin or purpose of that configuration constant as say, part of a criminal scheme to avoid acknowledging liabilities already incurred by the deployment of the system, then the numerological significance of the configuration constant(s) can be appealed to.

This seed of an idea lay dormant for years. The basic notion to "use a cryptographic hash to catch a liar", say by putting extra hashes inside git commit messages that represent commitments to some (possibly sensitive) bit of private information that one suspects one might need to appeal to later, seems like seems like it should be obvious to those reasonably well versed in blockchain technologies and other forms of applied cryptographic hashing. However these vague notions are very incomplete, with a lot of critically important detail left out. Moreover I wasn't specifically aware of a configuration parameter in the systems I worked on or was envisioning that seemed a plausible fit for the slightly more specific notion of a seguid.

Eventually I came around to thinking about how to make stolen password hashes traceable or useless. To set this historical context, I had already come to understand that suffixing a tag to an externally-supplied input of SHA256 was a plausibly-secure plaintext tagging construction. I was now researching how one might be able to best use this observation in a PBKDF2-based password prehashing scheme.

In this context, I was introduced to Soatok's blog post on HKDF, which lead me to read RFC 5869 for the first time.  These two documents really nucleated a burst of creative insight into my research topics. Most interestingly, HKDF's salt parameter also gave me an obvious place to try to germinate the idea of a seguid, which would then turn into a second and complementary indirectly self-documenting cryptographic tag.

Attempting to write my thoughts down clearly turned out to be far more difficult than I imagined.  At first I thought that seguids would be a minor section in the presentation of the G3P, but that section and presentation kept growing in scope.  I could more-or-less accurately describe what I wanted to happen, but had great difficulty justifying why.

Eventually I broke that stubborn section out into it's own writing project, and started writing specifically on the topic of seguids. Once I took that step, it took about three weeks of ceaseless re-writing before the result started to make sense, which turned into the document you are now reading. Those early drafts sounded very much like the self-referential sign above.

Part of the difficulty is that it wasn't at all obvious to me how to organize an introduction that seemed approachable, especially because the concept employs self-reference in unusual ways that were new to me. How do you cut that knot and give yourself and your audience a place to start?

There is almost certainly a better heuristic to finding a reasonable organization for this paper than the one I took. This involved a lot of repetitive trial-and-error writing, with the occasional insights gleaned informing the next draft.

More than once the insight obtained from trying to answer the question "why" dramatically improved my preliminary answer to the question "how", and vice-versa. More than once I thought about lectures on quines by Larry Moss, and conversations about Scheme's `letrec` and scoping rules with Dan Friedman, Amr Sabry and others.

The concept of a seguid suffered for a long time without having a name for it. At first, I focused the discussion around `seguid-v2-salt`, the global salt that I was originally calling the "global pseudorandom key". In the context of what I wanted to acheive, that was certainly the wrong starting point along multiple axes.

Once I shifted my primary focus to seguids as the outputs of the function that produces them, I started using the term "SGUID", suggesting the pronouncation "ESS-gwid". I thought of it like a linguistic variation on "escrow", except with cephalopods instead of corvids. Then I realized that "seguid" can be translated from Spanish to English as the imperative "y'all follow", so I leaned into it. I decided to follow this uncannily appropriate cultural pun wherever it may lead.

## Acknowledgements

To Obsidian Systems and the many wonderful people I've worked with there. Thank you for giving me excellent professional opportunities to hone my skills in applied cryptography.  Also thank you for introducing me to IPFS, which played an unexpectedly large role in this paper.  Maybe that shouldn't have been suprising, as it was obvious to me from the start that there is overlap and deep connections between seguids, content identifers, content-addressable storage, and non-fungible tokens.

To my blackmailer. You are certainly a man of your day, and a notable example of the contemporary cultural zeitgeist here in the United States of America. Your original, deviceful dishonesty and audacious, shameless shenanigans helped cultivate a mindset of much more comprehensively enumerating the ways in which people can lie. Your epochal Gish gallops motivated me to think about how to automatically document dishonesty by default. Your openly criminal conduct directly seeded a notion that select concepts in numerology might in fact be somehow useful and practical in the right context, which eventually grew into the Seguid Protocol.

To Soatok, whose blog posts on HKDF provided a plausible context in which to germinate the idea of a Seguid. To Bruce McAdam for "Y in Practical Programs", one of my all-time favorite papers in computer science, and to many other writers who have influenced me whom I've never met.  To many teachers, fellow students, and colleagues at Case Western Reserve University, Indiana University, and Lambda the Ultimate who have shaped my views on Programming and Languages the Theory of Computation over the years.  All of this very much helped me arrive at Self-Documenting Cryptography in general, and the Seguid Protocol in particular.

# Bibliography

TODO: Format this more properly

NIST Special Publication 800-185

NIST Special Publication 800-108r1

https://tools.ietf.org/html/rfc3986

https://tools.ietf.org/html/rfc5869

https://soatok.blog/2021/11/17/understanding-hkdf/

TODO: add references to IPFS and IPNS documentation

[^letrec-scheme]: Indeed, this description of the necessary self-reference very much reminds me of the literal definition of letrec in various versions of the Scheme programming language, which has lead to such intriguing oddities as Alan Bawden's famous comp.lang.scheme post of March 2, 1989,  "LETREC + CALL/CC = SET! even in a limited setting"
