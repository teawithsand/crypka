# crypka

Crypka is library, which abstracts away crypto, so one can easily do:
- Swap cryptosystems by swapping algorithm object in one place
- Easily and securely marshal keys

Crypka also implemented benchamrking and testing utils for various packag crypto primitives like signing or encryption.

## Current status
For now following features are reasonable implemented and won't change soon:
 * Asymmetric signing
 * Symmetric signing(think of HMAC)
 * Symmetric signing using hash functions AKA symmetric signing without key

Testing API for now is subject to many changes.

## Algorithms
For now following algorithms are implemented and integrated with crypka:
 * Symmetric signing using STL hashes 
 * Symmetric signing using HMAC + STL hashes
 * Asymmetric signing using ed25519

## Is it production ready?
Probably not, since I'll change API for non-signing stuff.

## Why even bother doing something like that?
There is a couple of reasons:
 * (IMO) nobody has created library, which allows easy cryptosystem swapping, so one could go from RSA4096 to some quantumm secure algorithm by swapping single algorithm declaration
 * Since it allows easy swapping, it allows easier performance testing with various algorithms
 * Also APIs here are designed in a way, which is easy for end user. If some crypto API can be implemented in slower but less error prone way, crypka will provide the 2nd one.

## TODOs:
 * Better API for encryption, since there is difference between block, chain and stream encryption
 * Support for encryption algorithms
 * API for key exchange algorithms
 * Creating encryption algorithms from key exchange ones(especially from x25519)
 * Support for post quantumm algorithms
 * In general, support for more algorithms(like RSA for instance)
 * Tests for safe serialization - even if key is serialized with json.Marshal it should leak no private data
 * Support for AEAD + PRNG generated nonces, which are not embedded