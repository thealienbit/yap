Implementation
---

# Implementation Breakdown (Ordered & Dependency-Aware)

## Phase 0 — Foundations
### 0.1 Project skeleton
* Go module setup
* Package layout
* Error handling conventions
* Logging strategy (no secrets logged)
* Secure config handling
---
### 0.2 Cryptographic primitives wrapper
Implement *thin, well-tested wrappers* around crypto:
* Argon2id KDF
* HKDF expand
* XChaCha20-Poly1305 encrypt/decrypt
* BLAKE2b hashing
* Secure RNG abstraction

**Deliverables**
* `crypto/kdf.go`
* `crypto/aead.go`
* `crypto/hash.go`
* `crypto/rng.go`
---
## Phase 1 — Vault File Format (Core)
### 1.1 Canonical CBOR encoder/decoder
* Enforce:
  * Canonical encoding
  * Sorted map keys
  * No duplicate keys
* Strict decoding (fail on malformed input)
**Deliverables**
* `encoding/cbor.go`
---
### 1.2 Vault header implementation
* Header struct
* Validation rules
* Header hashing / AAD bytes
**Deliverables**
* `vault/header.go`
---
### 1.3 Encrypted payload envelope
* XChaCha20 encryption
* AAD = canonical header bytes
* Nonce generation
* Payload envelope CBOR
**Deliverables**
* `vault/envelope.go`
---
## Phase 2 — Key Management
### 2.1 Master Key derivation
* Argon2id params
* Salt generation
* Memory-hard defaults
**Deliverables**
* `keys/master.go`
---
### 2.2 Vault Key wrapping / unwrapping
* KEK derivation
* Vault Key encryption
* Key epoch handling
* Rotation logic
**Deliverables**
* `keys/vault_key.go`
---
### 2.3 Entry Key lifecycle
* Entry Key generation
* Storage format
* Encryption with Vault Key
**Deliverables**
* `keys/entry_key.go`
---
## Phase 3 — SQLite Layer
### 3.1 SQLite schema creation
* `entries`
* `folders`
* `meta`
**Deliverables**
* `db/schema.sql`
* `db/init.go`
---
### 3.2 Field-level encryption envelope
* CBOR envelope `{v, n, ct}`
* AAD construction
* Encrypt/decrypt helpers
**Deliverables**
* `db/field_crypto.go`
---
### 3.3 Entry CRUD (local, no sync)
* Create entry
* Update entry
* Delete entry
* Read/search
**Deliverables**
* `db/entries.go`
---
## Phase 4 — Vault Open / Write Engine
### 4.1 Vault open pipeline
Implements **OPENING → OPEN**
* Header parsing
* Key derivation
* VK unwrap
* Payload decrypt
* Metadata validation
* Rollback checks
**Deliverables**
* `vault/open.go`
---
### 4.2 Vault in-memory model
* Loaded SQLite handle
* Metadata cache
* Dirty flag
**Deliverables**
* `vault/state.go`
---
### 4.3 Commit pipeline
Implements **DIRTY → COMMIT → CLEAN**
* Version increment
* Payload rebuild
* Encryption
* Atomic file write
**Deliverables**
* `vault/commit.go`
---
## Phase 5 — State Machine Enforcement
### 5.1 Vault state machine
* CLOSED / OPENING / OPEN / DIRTY / CLEAN
* Illegal transition guards
**Deliverables**
* `vault/statemachine.go`
---
### 5.2 Crash-safety guarantees
* Temp files
* fsync
* Atomic rename
**Deliverables**
* `vault/fs.go`
---
## Phase 6 — Git Sync Layer (Untrusted Transport)
### 6.1 Git abstraction
* Pull
* Push
* Status
* Remote version detection
**Deliverables**
* `sync/git.go`
---
### 6.2 Sync conflict detection
* Compare vault_version
* Detect divergence
* Reject overwrite
**Deliverables**
* `sync/conflict.go`
---
### 6.3 Rollback enforcement
* last_seen_vault_version
* last_seen_key_epoch
* Hard failure on downgrade
**Deliverables**
* `sync/rollback.go`
---
## Phase 7 — CLI / UX Layer (Thin)
### 7.1 Vault lifecycle commands
* init
* open
* status
* lock
* rotate-password
* rekey
---
### 7.2 Entry management commands
* add
* edit
* remove
* list
* search
---
### 7.3 Sync commands
* pull
* push
* sync (safe pull+push)
---
## Phase 8 — Safety, Testing, Hardening
### 8.1 Test vectors
* Crypto correctness
* Known-answer tests
* Deterministic CBOR encoding
---
### 8.2 Fuzzing
* CBOR parsing
* Vault open pipeline
* Field decryption
---
### 8.3 Threat-model validation
* Rollback simulation
* Git history replay
* Corrupt vault tests
---
## Phase 9 — Documentation & Guardrails
### 9.1 Security documentation
* Threat model
* What is / isn’t protected
* Recovery limitations
---
### 9.2 User guidance
* Git setup
* Backup strategy
* History rewrite guidance
