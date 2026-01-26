VAULT LAYOUT (HIGH LEVEL)

+-----------------------------+
| Plaintext Vault Header     |  <-- small, non-secret
+-----------------------------+
| Encrypted Vault Payload    |  <-- everything else
+-----------------------------+


Cryptographic Layout (Authoritative)
Algorithms (lock these early)

KDF: Argon2id

Encryption: XChaCha20-Poly1305 (preferred)
(AES-GCM acceptable but harder to use safely)

Hash: BLAKE2b / SHA-256


Key hierarchy (recap, now concrete)
Master Password  
   ↓ Argon2id(salt, params)
Master Key (MK)
   ↓ HKDF
Vault Key (VK)
   ↓ HKDF
Entry Keys (EK_i)

Master Key never stored
Vault Key encrypted inside vault
Entry Keys derived or stored encrypted

Vault Header (Plaintext, Authenticated)
Purpose
Tell client how to decrypt
Provide anti-rollback guarantees
Enable forward compatibility
