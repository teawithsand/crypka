# crypka

Crypka is library, which abstracts away crypto, so one can easily do:
- Swap cryptosystems by swapping algorithm object in one place
- Easily and securely marshal keys

Crypka also implemented benchamrking and testing utils for various packag crypto primitives like signing or encryption.

Testing API for now is subject to changes.

## Algorithms
For now following algorithms are implemented and integrated with crypka:
 * Symmetric signing using STL hashes 
 * Symmetric signing using HMAC + STL hashes
 * Asymmetric signing using ed25519
 * Key exchange using x25519
 * Symmetric encryption using any AEAD cipher
 * Symmetric stream encryption using any symmetric encryption
 * RNG from any stream cipher
 * IEC78164 padding algorithm
 * Various other implementations, which combine

## Why even bother doing something like that?
There is a couple of reasons:
 * (IMO) nobody has created library, which allows easy cryptosystem swapping, so one could go from RSA4096 to some quantumm secure algorithm by swapping single algorithm declaration
 * Since it allows easy algorithm swapping, it simplifies performance testing with various algorithms
 * Also APIs here are designed in a way, which is easy for end user(not that much consise though). If some crypto API can be implemented in slower but less error prone way, crypka will provide the 2nd one.

## TODOs:
 * Creating encryption algorithms from key exchange ones(especially from x25519)
 * Support for post quantumm algorithms
 * Rekeing for stream encryptors, so one can encrypt infiite amount of data
 * Slow hashes for passwords and and proof of work