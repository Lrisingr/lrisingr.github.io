---
layout: post
title:  "Breaking a Toy Hash Function"
date:   2016-04-26 04:19:22 +0700
categories: [others]
---
1. [breaking-a-toy-hash-function](http://twistedoakstudios.com/blog/Post4706_breaking-a-toy-hash-function)
<br/>
2. [bug-hunting-1-garbled-audio-from-end-to-end](http://twistedoakstudios.com/blog/Post7052_bug-hunting-1-garbled-audio-from-end-to-end)
<br/>
3. [deadlocks-in-practice-dont-hold-locks-while-notifying](http://twistedoakstudios.com/blog/Post8424_deadlocks-in-practice-dont-hold-locks-while-notifying)
<br/>
4. [impractical-experiments-1-representing-numbers-as-polynomials](http://twistedoakstudios.com/blog/Post6871_impractical-experiments-1-representing-numbers-as-polynomials)
<br/>
5. [searching-a-sorted-matrix-faster](http://twistedoakstudios.com/blog/Post5365_searching-a-sorted-matrix-faster)
<br/>
You probably know that hash functions can be used to protect passwords. The idea is that someone with access to the hash can’t figure out the corresponding password, but can use the hash to recognize that password when it is received. This is really, really useful in cases where attackers have access to your source code and your data.

For example, consider WarCraft 3 maps (essentially little self-contained games). Maps specify terrain, units, code and etc but can’t access the internet, the file system, or even the current time. Anyone who has a map knows every detail of how it works, if they care to look. If you want to make a map that recognizes a password, perhaps to give yourself some sort of unfair admin powers as a joke, you’ll want to protect that password so that people who look inside the map won’t be able to play the joke on you.

In fact, years ago, I happened across exactly that sort of thing: a bit of JASS code that hashes the user’s name and a password in order to recognize the map maker and a couple of their friends. However, the hash function being used was created by a friend of the map maker. It is not a standard cryptographic hash function.

One of the standard refrains in cryptography is “Do not write your own crypto.”. Given that this person wrote their own crypto, I wondered if I could break their hash function. I tried a bit and gave up, but the problem stayed in the back of my mind. Every year or so I’d get the urge to go back and try again, waste a day messing with it, and give up again.

This year, I finally succeeded. I reversed the password, and all three usernames.

Note that I am not a cryptographer. The way I broke this function is probably… naive. I assume that, to a real cryptographer, this function is a toy to be crushed in an hour (“Ha! Just use X!”).

Nevertheless, I broke the hash function and I’m going to explain how.

The Hash Function
Given that most readers won’t know the intricacies of obfuscated JASS, I’ve taken the liberty of translating the hash function to C#:
{% highlight c# %}
static Tuple<Int32, Int32> Hash(string text) {
    var charSet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`~!@#$%^&*()_+-=|[];',.{}:<>? ";
    Int32 a = 0;
    Int32 b = 0;
    foreach (var letter in text) {
        var e = charSet.IndexOf(letter);
        if (e == -1) e = charSet.Length + 1;
        for (var i = 0; i < 17; i++) {
            a = a *-6 + b + 0x74FA - e;
            b = b / 3 + a + 0x81BE - e;
        }
    }
    return Tuple.Create(a, b);
}
{% endhighlight %}

As you can see, the state of the hash function is made up of two 32-bit signed integers (a, b) that both start out as 0. The input is a sequence of characters, drawn from 93 possibilities. Each character from the input is mixed into the state over a progression of 17 rounds and, when the last character has been mixed in, the result is just the final state of (a, b).

Note that addition and multiplication are unchecked (e.g. Int32.MaxValue+1 = Int32.MinValue, Int32.MaxValue*2 = -2) and division rounds towards 0 (e.g. -4/3 = -1, 7/3 = 2).

In addition to the hash function, here is translated code to verify that a username/password combination is valid:
{% highlight c# %}
static bool Verify(string username, string password) {
    var expectedPassHash = Tuple.Create(-0x20741256, -0x4A579222);
    var expectedNameHashes = new[] {
        Tuple.Create(-0x52BEB283, -0x733C9599),
        Tuple.Create(0x605D4A4F, 0x7EDDB1E5),
        Tuple.Create(0x3D10F092, 0x60084719)
    };

    var passHash = Hash(password);
    var nameHash = Hash(username);
    return password.StartsWith("<+")
        && passHash.Equals(expectedPassHash)
        && expectedNameHashes.Contains(nameHash);
}
{% endhighlight %}
As you can see, both the valid usernames and the valid password are protected by hashing them. Also, the first two characters of the password are included in the code.

Side Note: Although it might seem dumb to give away some of the password's characters, it's actually a good idea given the context. The prefix is used as a filter for the chat event that triggers the hashing, to avoid hashing every single chat message said by anyone. The filter also allows the game to avoid secretly sharing all team messages with opponents (They need to know something matching the filter was said in order to run the chat event trigger, and need to know what was said in order to feed the right information into the hash function. Otherwise they can't advance in lockstep.).

Our goal is to find a username and a password that make Verify return true.

Leaking Entropy
The first thing to notice about the above function, that suggests it should be easy to break, is that it leaks entropy. It is using non-reversible operations, which decrease the number of the states the system might be in.

To make it easier to talk about that, here's a spread out version of the internal loop, with the multiplication by -6 factored and the division by 3 split into rounding followed by inverse-multiplying.
{% highlight c# %}
a *= 2;
a *= -3;
a += b;
a += 0x74FA;
a -= e;
b -= b % 3; // round to multiple of 3, towards 0
b *= -1431655765; // multiplicative inverse of 3 (mod 2^32)
b += a;
b += 0x81BE;
b -= e;
{% endhighlight %}
When working in modular arithmetic, some multiplications are reversible (do not leak entropy) but others aren't.

Multiplying a 32-bit integer by 3 does not decrease the amount of entropy because it is reversible. Every input state corresponds to exactly one output state. You can even efficiently run the operation backwards by multiplying by the modular multiplicative inverse of 3. The multiplicative inverse of 3 is 3^{-1} \equiv -1431655765 \pmod{2^{32}} because multiplying them together gives a result equivalent to one: 3 \cdot 3^{-1} = 3 \cdot -1431655765 = -4294967295 = -2^{32}+1 \equiv 1 \pmod{2^{32}}.

Multiplying by 2 is NOT reversible. It does decrease the amount of entropy. This happens because (x+2^{31}) \cdot 2 \equiv x \cdot 2 + 2^{32} \equiv x \cdot 2 \pmod{2^{32}}, meaning both inputs of either x or x+2^{31} are collided into the single output of 2 \cdot x. In the worst case this limits the possible number of output states to be half the number of input states, destroying 1 bit of entropy. Many inputs map to one output, so the operation is not reversible and leaks entropy.

The other non-reversible operation is rounding to the nearest multiple of 3 towards 0. In the worst case this destroys about 1.5 bits of entropy, reducing the number of possible states by about a third.

These leaks occur every single round, and it's possible for their cumulative effects to be very bad. It's a bit like those "mixing tank" problems you solve when learning differential equations, except the input mixture keeps changing color. If the tank is leaking then the contributions of the early colors to the average color decrease exponentially, instead of linearly, as more colors are added.

These leaks make me suspect that earlier values are in danger of 'diluting away'. Every round destroys a couple bits and replaces them with mixtures of the remaining entropy. Later values don't get destroyed and mixed much, but early ones do. Maybe, to find a preimage, I only have to care about the last few characters instead of all the characters. Maybe, to find a collision, I can significantly increase my chances by adding the same long suffix to any two starting strings.

It turns out that these leaks weren't devastating, but they really shouldn't have existed in the first place. Fixing the leak caused by multiplying by -6 is as easy as changing 6 to 7. Fixing the leak caused by rounding to a multiple of 3 is also easy: just remove the rounding.

Wait, no, that last idea is terrible.

Almost Linear
All of the operations in the hash function, except rounding to a multiple of three, are linear. They distribute over addition.

If we removed the rounding operation, the contributions of every input could be separated and reduced to a single multiplicative constant that depended only on the position relative to the end of the string. Each input value would be multiplied by the constant corresponding to its position, you'd sum up the products, and that'd be the result of hashing. Suddenly, finding an input that hashes to a given value would be like solving the subset sum problem and there'd all this structure we might be able to take advantage of to save huge amounts of time.

Fun fact: if you fixed the entropy leak due to the rounding (by removing it), but didn't fix the leak due to the multiplication by -6, you'd have made things far, far worse. The constants corresponding to positions would keep gaining factors of two. Ultimately, only the last four characters would get non-zero corresponding constants and collisions would be somewhat easier to find.

It's interesting that the operation that rounds b to be a multiple of three affects the state very little. It offsets it by at most 2, but that little tweak is the only reason reversing the hash function is difficult. Of course, in a properly designed hash function, the non-linearities are reversible and their effects are not tiny tweaks to state (e.g. they might XOR a into b instead of adding a into b, presumably flipping half of b's bits).

The fact that the non-linearity is so small made me wonder if I could just apply integer programming to the problem. Presumably integer constraint solvers are super fast when there's this sort of regularity. That did not go well.

Integer constraint solvers are not designed with modular arithmetic in mind. Every solver I used failed to reverse even three of the seventeen rounds needed to process a single character, because the solutions required values that exceeded the solvers' valid range. Confusingly, the solvers mostly just claimed "no solution". The only solver that actually told me I was going out of range, instead of pretending there was no solution, was IBM's CPLEX. I hereby award them one competence point.

I also tried extracting the non-linearities by rearranging the code by hand. I took this way, way too far before giving up.

Meet in the Spring
Eventually, I figured maybe I should try the obvious thing and brute-force the answer.

First, I tried just enumerating all inputs. This starts getting pretty slow once you get to five characters, since there's 93 possibilities for each character and 93^5 = 6956883693 \approx 10^{10}. With that many possibilities to check, every additional operation needed to check a single possibility is adding at least a second to your running time (and hashing involves hundreds of operations). At six characters that goes up to a hundred seconds per operation, and you'll be left waiting for days.

Second, I tried to meet in the middle.

Because the entirety of the hash function's state is used as its output, it's possible to run it backwards (this is slower, though). Just do the inverses of each operation. This allows you to explore both forwards and backwards, while trying to find common middle states.

To say that this gives a performance boost is a bit of an understatement. Instead of using almost a trillion hash operations to try all possible six character strings, we're only going to spend a million hash operations and a million reverse-hash operations. The million hash operations are used to try all possible three character prefixes, building a dictionary that takes a reached state and tells you the prefix that reaches it. The million reverse hash operations are used to try all possible three character suffixes, telling you which intermediate states can be reached by exploring backwards from the end state. If there's a path from the start point to the end point, then one of the states reached by traveling backwards will be in the dictionary and you're done.

I used meeting in the middle to go from searching all five character strings to all six character strings. I didn't bother with seven because my machine would go out of memory trying to store all the four-character states.

Third, I decided to use a bloom filter instead of a dictionary to store the middle states. Now, instead of immediately getting a solution when I found a match in the middle, each match was a possible solution that I could verify later on by re-exploring the possible prefixes.

Why is it worth sacrificing the immediate result to go from three 'cached' rounds to four cached rounds? Because every cached round is effectively a 100-fold speedup. I could even have gone to five cached rounds, if my machine had more than 4 gigs of memory (the bloom filters had to be quite large to accommodate the hundreds of millions of items while maintaining low false-positive rates).

Fourth, I tried tracking integer constraints. I knew a lot of constraints that intermediate states had to satisfy, so I checked them constantly and discarded states that didn't fit. When I measured how much this was reducing the search space it was a staggering 50% per reverse-round. I assumed most of this was being burned countering the search space increasing as irreversible operations had multiple possible inputs.

At this point I found my first result, which I could have found earlier if I'd just let things run longer. One of the usernames only had seven characters: "Procyon". However, I was still hitting a massive time investment wall. Checking all those constraints took time.

Then I realized the 50% reduction in search space from the constraints was wrong. It turned out that the constraints were just catching what would have been caught by the very next reverse-multiplication or reverse-division-by-3. The constraints were actually achieving a... 0% reduction. Whoops. Removing them sped things up quite a bit, allowing me to search all 9 character strings.

Finally, I realized that I should switch the direction of caching. Going backwards was more expensive than going forwards, and I was memory-limited to caching fewer rounds than I was exploring from the other direction. Caching the results of going backwards, instead of going forwards, would reduce the amount of reverse hash operations and allow me to search all strings up to ten characters as long as I was willing to wait a couple days while my laptop chugged away.

Collision
We've finally reached the weakness I ultimately used to beat the hash function: the size of its output.

The output size is 64 bits, which allows a bit more than 10^{19} possibilities. I can search through every string up to ten characters (with 93 possibilities per character), which is 93^{10} possibilities. That's about five times 10^{19}.

Right. At this point it doesn't matter how long the real password is. By pure brute luck, I'm going to stumble onto strings that hash to the same thing.

My work is done. I just need to let the computer churn.

Code
This is the code I used to break the hash function:
{% highlight c# %}
/// Returns a given start state and a sequence of values of the given length that reach the given end state.
/// If not such sequence exists, returns null.
public static Tuple<HashState, int[]> Break(HashState end,
                                            int assumedLength,
                                            IEnumerable<HashState> startStates) {
    // generate bloom filter going backwards from end
    var numExpandBackward = (assumedLength - 1).Min((assumedLength * 2) / 3).Max(0).Min(4);
    var filter = HashStateBloomFilter.GenReverseCache(end, numExpandBackward, pFalsePositive: 0.0001);

    // explore forward from starts to filter, discard states that don't match
    var possiblePartialSolutions =
        from start in startStates
        from midStateAndData in start.ExploreTraceVolatile(assumedLength - numExpandBackward)
        where filter.MayContain(midStateAndData.Item1)
        select new { start, data = midStateAndData.Item2.ToArray(), end = midStateAndData.Item1 };

    // base case: not enough length to bother meeting in the middle. Partials are actually complete solutions.
    if (numExpandBackward == 0) {
        return possiblePartialSolutions
            .Select(e => Tuple.Create(e.start, e.data))
            .FirstOrDefault();
    }

    // we don't want to wait for all possible partial solutions before checking. That would take tons of memory.
    // we also don't want to check after every single possible partial solution, because that's expensive.
    // so we partition possible solutions and check whenever there's enough to make it worth the time.
    var partitions = possiblePartialSolutions.PartitionVolatile(10000);

    // complete any partial solutions
    var solutions =
        from partition in partitions
        let partialSolutionMap = partition.ToDictionary(e => e.end, e => e)
        // recursively solve the gap
        let secondHalf = Break(end, numExpandBackward, partialSolutionMap.Keys, true)
        where secondHalf != null
        // Anything reaching here is a solution. Combine it with the first half and return it.
        let partialSolution = partialSolutionMap[secondHalf.Item1]
        let start = partialSolution.start
        let data = partialSolution.data.Concat(secondHalf.Item2).ToArray()
        select Tuple.Create(start, data);

    // actually run the queries
    return solutions.FirstOrDefault();
}
{%endhighlight%}
The above code makes a bloom filter containing states that can reach the end by adding a suffix of some length (up to 4). It then iterates over prefixes of the complementary length, noting any that match the filter. Once it has ten thousand matching prefixes, or runs out, it recursively tries to break the gap from the states reached by matching prefixes to the end state. If it finds a way to break the gap, the correct prefix is paired with the gap solution in order to make a full solution. Otherwise it keeps going until it runs out of prefixes.

Note that the code is not optimized very much. In particular, it's using Linq queries instead of the equivalent imperative code. As far as I know, neither the C# compiler not the .Net jit optimize them particularly well and so the code is paying for tons of virtual function calls when it doesn't have to. On the other hand, the equivalent imperative code is stupidly hard to get right because you end up mixing everything together in a big jumble. (I spent my time doing other things while the computer did the tedious work.)

Solutions
After about two days of computing, and one dead laptop, the code returned a password that matched the password hash. The password is "<+nt1AkgbMht" (or rather, <+nt1AkgbMht is a string that hashes to the same thing as the true password). If you're wondering why the password has 12 characters, when I said I was searching 10, recall that the first two characters of the password were given away in the JASS code. I searched 10 additional characters.

(It's tempting to pretend I didn't know those two characters, because 93^{12} \approx 10^{24}, so I could say I literally searched a trillion trillion possibilities.)

After another three days, I had both remaining usernames. These are clearly collisions, instead of the actual names, but here they are nonetheless: "hRlGz%W3&R" and "b>4FXV'Xf8" match the first and third hashed usernames respectively (the second was "Procyon").

My Reward
With the solutions in hand I can finally download Phase Killer, play it in single player with a profile called "Procyon", say "<+nt1AkgbMht" and see... a red "VALID" message.

Valid

Worth it.

Summary
Things we've learned about writing hash functions:

Don't write your own hash function.
Don't leak entropy. All round operations should be reversible.
Don't use the hash's entire state as its result. Running backwards from the result should be hard. (See also: length extension attack.)
Use non-linear combinations of operations and apply them a lot. The effects of each input should be difficult to separate. (See also: avalanche effect.)
Have a result with lots of bits. Collisions should be hard to find. (See also: birthday attack.)
Don't write your own hash function (except for fun).
