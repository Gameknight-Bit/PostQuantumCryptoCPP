# Post Quantum Cryptoschemes

This small project is/was geared to my own learning of *Post Quantum Cryptography Algorithms*. Thus, as I learn more about these very cool algorithms I intend to add more implementations :)

I also will be trying to optimize them as much as I can as practice so I'll try to add performance stats.

I have a bunch of notes on each algorithm including my intuition on why they work/are secure against current quantum algorithms.

## Importance of PQCs

While Quantum Computation is not currently at large in society (and it isn't clear that it ever will) as engineers focused on data security, we should take care to focus on the worst case scenario (assuming a capable adversary in the future could make use of a quantum computer to snoop on cryptokeys)

Non quantum safe cryptography schemes rely mainly on the assumption that factoring of primes and the discrete log problem are "hard" problems to solve, and thus using these problems as bases for our encryption scheme, we also show that our scheme is secure as well. Thus an encryption algorithm like RSA reduces to solving the prime-factorization problem.

The problem with this approach though is that we have not shown that in fact these problems are "hard" enough to satisfy our requirements of security. (and in fact, quantum computers are able to factor primes (see Shor's algorithm) and are much faster at solving the discrete log problem than computers) This means that if quantum computation takes off, cyphertexts encrypted via an assumption of hardness on prime factorization can be decrypted.

So all someone needs to do (if this is eventually possible) is scrape important cyphertexts and wait for quantum computation to take off as a technology. **Thus, we must invest time into quickly porting encryption schemes to be safe in a post quantum world**.

### Intuition on PQC "hard" problems

In order to make an encryption scheme safe against a quantum capable attacker, we must base the schemes against stronger "hard" problems than just prime-factorization. One popular problem to base algorithms on is the Shortest Vector Problem (SVP) which is an NP-hard problem. Thus basing PQCs on NP-hardness is a pretty good assumption of security (as long as $P \neq NP$ :P).

**Shortest Vector Problem:**

Given the basis of a vector space $V$ and norm $N$ (usually just the $L_2$ norm) of a lattice $L$, find the shortest non-zero vector in $V$ using the norm $N$.

This is an NP-hard problem (and in fact its even NP-hard to approximate! [proof](https://eprint.iacr.org/2025/2181))

(A lattice $L$ is the set of all integral linear combinations of a set of basis vectors $\{b_1, \cdots, b_n\}$. *i.e.* $\mathbb{Z}^n$ is a lattice that is used for most algorithms here)

Thus this ends the intution section and implemented algorithms are listed below:

---------

### Implemented Algorithms:
[ ] - Public Key (Learning With Errors)


## Descriptions

