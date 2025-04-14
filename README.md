# Stealth Engine

Implementation of a Secret Computation Engine - executes operations on data that is inaccessible to the public - and produces a resule accesible to the user and a proof.

Note: This part docs contains the technologies explored while building this project. I would talk about why I explored it, and why I decided to use or not use it.

### [FHE with THFE-rs](https://docs.zama.ai/tfhe-rs)

Currently has limitation of running only integer and boolean arithemetic operations on encrytped data. While this seem like a good choice mostly because of its stability and adavtages performance wise, I am looking to make an implementation that makes it possible to run user arbitrary operations.

### [Lit Protocol](https://developer.litprotocol.com/)

Lit Protocol provides programmable key management and access control. We explored it to handle encryption key access based on programmable conditions. However, due to limitations around general-purpose computation within its system, we decided it’s better suited as an access control layer rather than a computation layer.

I may still integrate it in the future for user authentication, decentralized access control, or proof of eligibility before running a computation.

### Hybrid Public Key Encryption

We chose HPKE for encrypting user data and engine responses due to its efficiency and compatibility with modern cryptographic practices. The engine uses HPKE to perform envelope encryption, ensuring that only the user can decrypt results, even if computation happens inside an untrusted or semi-trusted environment.

### FROST

FROST is a threshold signature scheme used for distributed key generation and signing. It's lightweight and efficient, particularly well-suited for signature generation rather than full-blown encrypted computation.

We evaluated FROST to ensure integrity and non-repudiation of computation proofs, but it's currently reserved for cases where threshold signing is necessary, not core engine computation.

More suitable for generating signatures.

### Shamir's Secret Sharing

Requires multiple shares to decrypt but we want the engine to be able to run computation when needed without users interaction. It’s valuable for splitting access to encryption keys among multiple parties, but not suitable for always-online, autonomous computation — as it requires multiple parties to reconstruct a key or perform decryption.

## Execution Flow

1. User Submits Encrypted Operation

   - Symmetric key is generated client side to encrypt the user data and computation parameters.

   - Using HPKE, the user encrypts the symmetric key with the server public key.

   - These are sent to the Stealth Engine.

2. Enclave Execution (via Enarx)

   - The engine runs inside an Enarx Keep (hardware-isolated secure enclave).

   - The encrypted symmetric key is decrypted inside the enclave using a key seeded from a secure configuration.

   - The decrypted symmetric key is used to decrypt the data and the operation details.

   - The user’s operation is executed securely.

3. Result Encryption and Proof Generation

   - The result is encrypted back to the user using HPKE.

   - (TODO) A cryptographic proof (attestation or signature) would be generated to prove the computation happened inside a secure enclave.

4. Response Delivery

   - The user receives the encrypted result + the \*proof.

   - Only the user can decrypt the result.

## Why Enarx? Why TEE?

TEEs allows running secure isolated computation and data offering confidentiality and integrity of data even when the host is compromised.With Enarx, we can run WASM computations inside TEEs without the need for special drivers. Enarx is also language agnostic.

## Usage

```
cargo run --bin stealth-server
```
