# Revision history for g3p-hash

## Version 2.0.0.0 "The War Tuba" (2024-04-20)

I was incredibly over the moon happy with Version 1. Then it provided me with
the spark of insight that lead to Version 2, which is 100x better. I am still
amazed by Version 1, although I'm no longer interested in deploying it myself.

At that point in time, I had put on hold a full cryptoacoustic reconstruction
of bcrypt, as I figured it was long past overdue to get Version 1 into this
fight. But then a last minute low-risk, plausibly high-reward guess to hedge
my bets lead to a sequence of revelations that gave me the understanding of
bcrypt that I needed to confidently make the changes I originally wanted.
(See commit a0d89af)

Now I wish I was lofting something bigger than bcrypt, but to paraphrase
Donald Rumsfeld, you go to war with the password hash functions you have,
not the password hash functions you want. And on that count, bcrypt has
become a mighty cryptoacoustic horn indeed! I have great confidence these
modifications will keep those fully homomorphic cancel-culture crackers
away for a long time to come.

(Not actually released on 4-20, but I did start having the mental breakthroughs
a few days earlier, spent 4-20 hacking away, and then spent the next two weeks
slowly making it a reality. It isn't even released yet, but hopefully soon.)

## Version 1.0.0.1 "Fight like a Pacifist" (2024-03-21)

Developing this project has been a long, strange trip. I've taken clues and
inspiration from so many different places, and the history of my in-the-moment
thinking on these topics is not well-preserved. But I do have a few specific
acknowledgments in mind.

First of all, I'd like to thank Lois T Clark for teaching me how to fight like
a pacifist. I'd like to thank Joe Taylor (K1JT) for WSPR and the WSJT suite of
amateur radio protocols. I'd like to thank Troy Hunt for "Have I Been Pwned?".
I'd like to thank the State of Indiana for providing me with a world-class
public education. These lessons directly inspired the goals and methodologies
of this project.

I'd like to thank Mike Dunn and Katalin Bimbo for trying to teach me relevance
logic. While I still have no formal understanding of this topic, thinking about
relevance was absolutely indispensable during this long development cycle.
It helped me see through my own dubious ideas and justifications, it helped me
modulate the goals and methodologies of this project, and it helped me make
real progress on identifying plausibly-desirable design properties. In short,
it took me to a design with which I am so much happier than I could have
imagined at the outset of this project.

I'd like to thank David Doiron for introducing me to signals and the theory of
communication via optics, and Yuri Goldfeld and the Indiana Academy, especially
the classes of 1998 and 1999 for so very inadvertently helping me piece together
some of clues that lead me to this result.

I'd like to thank Guo-Qiang Zhang and George Voutsadakis for teaching me about
automata and the theory of computation, Dan Friedman and Amr Sabry for teaching
me about programming languages, Larry Moss for teaching me about quines, and to
David Singer for introducing me to number theory, RSA cryptography, and digital
identity.

Finally, I'd like to thank the developers of HMAC, SHA256, PBKDF2, HKDF,
blowfish, and bcrypt for paving the way, Steve "sc00bz" Thomas and Soatok for
sharing their valuable insights into cryptography with me, and Obsidian Systems
for giving me opportunities to develop my skills in cryptography.

## Version 1.0.0.0 (2024-03-21)

* Initial release accidentally omitted C header files
