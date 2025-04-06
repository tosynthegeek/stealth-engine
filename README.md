# Stealth Engine

Implementation of a Secret Computation Engine - executes operations on data that is inaccessible to the public - and produces a resule accesible to the user and a proof.

Note: This part docs contains the technologies explored while building this project. I would talk about why I explored it, and why I decided to use or not use it.

### [FHE with THFE-rs](https://docs.zama.ai/tfhe-rs)

Currently has limitation of running only integer and boolean arithemetic operations on encrytped data. While this seem like a good choice mostly because of its stability and adavtages performance wise, I am looking to make an implementation that makes it possible to run user arbitrary operations.

### [Lit Protocol](https://developer.litprotocol.com/)

### Hybrid Public Key Encryption

### FROST

More suitable for generating signatures.

### Shamir's Secret Sharing

Requires multiple shares to decrypt but we want the engine to be able to run computation when needed without users interaction.
