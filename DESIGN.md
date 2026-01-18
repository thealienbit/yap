# YAP - Password Manager – Design Summary

## 1. Vision & Core Philosophy

This project is a **developer-centric, zero-knowledge password manager** with the following principles:

* **User owns their data location**
* **No centralized password storage**
* **No trusted backend**
* **Client-side encryption only**
* **Cross-device sync via user-chosen Git remotes**
* **Offline-first**
* **Transparent security model**

The system deliberately targets **technical users first**, prioritizing **security, control, and correctness** over mass-market simplicity.

---

## 2. High-Level Architecture

### Key idea

> **Git is only a transport.
> The encrypted vault is the source of truth.
> Cryptography defines correctness—not Git state.**

### Components

#### Client Application (Primary Trust Boundary)

* Desktop / mobile app
* Responsible for:

  * Key derivation
  * Encryption / decryption
  * Vault integrity checks
  * Sync logic
  * Conflict & rollback detection

#### Vault

* Single **encrypted SQLite file**
* Stored inside a Git repository
* Entire vault encrypted before commit
* Git never sees plaintext

#### Sync Layer (Untrusted)

* Any Git remote:

  * GitHub / GitLab
  * Self-hosted Git
  * Bare SSH repo
* Only stores encrypted blobs + Git metadata

---

## 3. Data Model

### Vault format

* **Encrypted SQLite database**
* Single file (simplifies integrity)
* Contains:

  * Password entries
  * Metadata
  * Internal version counters

### Why SQLite

* Mature
* Transactional
* Portable
* Offline-friendly
* Easy to encrypt as a whole

Performance inefficiency (whole-file encryption) is **acceptable** for security and simplicity.

---

## 4. Cryptographic Design (Non-Negotiable)

### Threat model assumptions

* Git provider is untrusted
* Network is hostile
* Backend does not exist
* Client OS is *assumed trusted* (standard PM assumption)

### Key hierarchy (mandatory)

```
Master Password
   ↓ (Argon2id)
Master Key
   ↓
Vault Key
   ↓
Per-Entry Keys
```

### Requirements

* **Argon2id**

  * High memory cost (≥128MB)
* **Authenticated encryption**

  * AES-256-GCM or XChaCha20-Poly1305
* Random salts & nonces
* No password reuse for crypto keys
* Keys never leave the client

### Security properties achieved

* Zero-knowledge storage
* Forward secrecy on re-encryption
* Limited blast radius per entry

---

## 5. Git-Based Sync Model

### Sync workflow

1. User edits password
2. Vault updated locally
3. Vault re-encrypted
4. Encrypted file committed
5. Commit pushed to user-chosen remote
6. Other devices pull and decrypt

### Branching strategy

* **Single branch**
* No merges
* Explicit pull → decrypt → verify → apply

This avoids Git conflict complexity.

---

## 6. Git-Specific Risks & Mitigations

### 6.1 Immutable history risk

**Problem:**
Old encrypted vaults remain forever in history.

**Mitigations:**

* Full vault re-encryption on:

  * Master password change
  * Security refresh
* Provide **guided history rewrite** command
* Clear user documentation

---

### 6.2 Rollback attacks

**Problem:**
Attacker reverts repo to older commit.

**Mitigations (mandatory):**

* Vault includes:

  * Monotonic version counter
  * Signed metadata
* Client **rejects older versions**
* Optional user warning + override

Git state is never blindly trusted.

---

### 6.3 Metadata leakage

**Leaked:**

* Vault size
* Commit frequency
* Timestamps

**Mitigations (optional):**

* Fixed-size padding
* Single file only
* Delayed commits

This leakage is acceptable for target users.

---

## 7. Conflict Handling Philosophy

### Design choice

* **Correctness over convenience**

### Rules

* Detect divergence
* Reject silent overwrites
* Force explicit user action
* Never auto-merge encrypted vaults

Data loss is worse than inconvenience.

---

## 8. Authentication & Git Access

### Git authentication

* SSH keys or OAuth tokens
* Tokens stored encrypted locally
* Fine-grained permissions only

### Compromise model

* Repo compromise ≠ password compromise
* Attacker gains ciphertext only

---

## 9. User Experience Strategy

### Target audience (Phase 1)

* Developers
* Security-aware users
* Git-literate users

### UX goals

* Clear setup flow:

  * Create repo
  * Connect remote
  * Initialize vault
* Explicit warnings:

  * Password loss = permanent loss
  * Repo loss = permanent loss
* Transparent sync status
* Clear error messages

### UX tradeoffs accepted

* Manual conflict resolution
* No password recovery
* No cloud convenience

---

## 10. What This Is NOT

This project intentionally does **not**:

* Store passwords on a central server
* Provide account recovery
* Hide complexity from users
* Optimize for non-technical audiences (initially)

These are conscious, documented decisions.

---

## 11. Comparison to Existing Tools

| Tool        | Difference                         |
| ----------- | ---------------------------------- |
| pass        | Text files + GPG, CLI-centric      |
| KeePass     | File-based but no Git integration  |
| Bitwarden   | Centralized encrypted storage      |
| Your design | Encrypted SQLite + Git-native sync |

This project fills a **real gap**:

> A modern, structured, Git-native, zero-knowledge password manager.

---

## 12. Design Principles to Keep in Mind

### Security

* Crypto correctness > features
* Client state > remote state
* Fail closed, not open
* Explicit is better than automatic

### Usability

* Guide, don’t hide
* Warn loudly
* Never silently fix
* Power-user friendly first

### Engineering

* Treat Git as dumb storage
* Keep vault self-describing
* Design for re-encryption & rotation
* Expect mistakes and recover safely

---
