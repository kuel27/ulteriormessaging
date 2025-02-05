use at your own risk

the app implements E2EE communication using X448 to derive a shared secret, then applies Argon2 hashing with a salt, followed by HKDF (with SHA-512), to derive a symmetric key.

for symmetric encryption, it uses a two-layered encryption with ChaCha20-Poly1305 using a randomly generated nonce and AES-GCM-SIV, again with its own random nonce.
