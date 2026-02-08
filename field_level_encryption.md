# Field-Level Encryption Envelope (Spec)

## Goals

* Encrypt each sensitive field independently
* Prevent nonce reuse
* Bind ciphertext to its context (entry + column)
* Support future schema evolution
* Keep SQLite rows opaque but structured

---

## What gets encrypted (recap)

Encrypted columns:

* `title`
* `username`
* `password`
* `url`
* `notes`
* `folders.name`
* `entry_key` (special case, wrapped with Vault Key)

Plaintext columns:

* `id`
* `created_at`
* `updated_at`

---

## Envelope Format (CBOR, canonical)

Each encrypted field stores **one CBOR map**, serialized to a BLOB:

```cbor
{
  "v": 1,                ; envelope version
  "n": h'...',           ; nonce (24 bytes)
  "ct": h'...'            ; ciphertext (+ tag if combined)
}
```

### Rules

* Canonical CBOR
* No optional fields
* No extra keys
* Unknown `v` → reject

This keeps parsing simple and auditable.

---

## Encryption Parameters

* **Cipher:** XChaCha20-Poly1305
* **Key:** Entry Key (EK)
* **Nonce:** 24 random bytes (CSPRNG)
* **AAD:** deterministic, context-binding (see below)

---

## AAD (Associated Authenticated Data) — CRITICAL

AAD binds the encrypted field to *exactly where it belongs*.

### AAD format (bytes, not CBOR)

```
"pmgr:field" ||
vault_id ||
entry_id ||
column_name ||
envelope_version
```

Where:

* `vault_id` = UUID bytes
* `entry_id` = UUID bytes
* `column_name` = UTF-8 string (e.g. `"password"`)
* `envelope_version` = single byte (`0x01`)

### Why this matters

* Prevents field swapping
* Prevents cross-entry replay
* Prevents schema confusion
* Prevents downgrade attacks

If **any** of these change → decryption fails.

---

## Encryption Flow (per field)

```text
plaintext_value
   ↓
nonce = random(24)
aad = buildAAD(vault_id, entry_id, column)
ciphertext = XChaCha20-Poly1305(
  key = EntryKey,
  nonce = nonce,
  aad = aad,
  plaintext = value
)
store CBOR{v, n, ct}
```

---

## Decryption Flow

```text
read CBOR envelope
validate v
rebuild AAD
decrypt using EntryKey
on failure → abort
```

No partial recovery. No silent fallback.

---

## Entry Key Handling (special but consistent)

### Entry Key generation

* 32 random bytes per entry

### Storage

* Stored in `entry_key` column
* **Encrypted with Vault Key**
* Uses the *same envelope format*
* AAD uses:

  * column_name = `"entry_key"`

This keeps one uniform encryption model.

---

## Nonce Safety (important note)

* XChaCha20 gives you a **huge nonce space**
* Still:

  * Always generate randomly
  * Never reuse for same key
* You do **not** need counters or determinism

---

## Things you must NOT do

❌ Encrypt multiple fields with the same nonce
❌ Use empty or constant AAD
❌ Share Entry Keys across entries
❌ Store plaintext alongside ciphertext
❌ Allow decryption with missing context

---

