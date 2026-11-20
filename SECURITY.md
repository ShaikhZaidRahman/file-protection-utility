# Security design

## Primitives
- **KDF:** PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP 2023 minimum for this PRF), 16-byte
  random salt per file, 32-byte output. Passwords are NFKC-normalised and UTF-8 encoded.
  The iteration count is stored in the header so it can be raised later without breaking old files.
- **Cipher:** AES-256-GCM via OpenSSL (through `cryptography`). The 128-bit GCM tag is the MAC.

## Container format (version 1)
```
magic "FPU1" | version (1) | iterations (u32) | chunk_size (u32) | salt (16) | nonce_prefix (7) | chunks...
```
Each chunk is `AES-256-GCM(plaintext_chunk)` followed by its 16-byte tag.

## Streaming construction (STREAM)
Nonce per chunk = `nonce_prefix (7) || counter (u32, big-endian) || final_flag (1)`;
the entire header is the AAD of every chunk. Consequences:
- Every (key, nonce) pair is unique: a fresh salt per file already yields a fresh key, and the
  counter makes nonces unique within a file.
- Reordering, duplicating, dropping, or appending chunks fails authentication.
- Truncation (even at a chunk boundary) fails because the new last chunk lacks the final flag.
- Header tampering (iterations, chunk size, salt, prefix) fails authentication.

## Operational safeguards
- Output is written to a private (`0600`) temp file in the destination directory, fsynced, and
  atomically renamed **only after the whole file authenticates**. Failed runs leave no partial
  plaintext and never damage an existing file.
- Existing outputs are not overwritten without `--force`; input == output is rejected.
- Header parameters are range-checked before use (prevents a crafted file from forcing huge
  PBKDF2 work or allocations).
- Wrong-password and tampering produce the same error (no oracle distinguishing them).
- Passwords are never accepted as command-line arguments.

## Limitations (read before relying on this)
- **Security rests on password strength.** PBKDF2 slows guessing but is not memory-hard; use a long
  passphrase. (Argon2/scrypt would be stronger; PBKDF2 was chosen to match the specification.)
- Metadata is not hidden: approximate file size, iteration count, and timestamps of the `.enc`
  file are visible. The original filename is not stored.
- `--remove-source` is a normal delete, **not a secure wipe**; on SSDs and journaling or
  copy-on-write file systems, secure erasure cannot be guaranteed by software.
- Python cannot reliably zero secrets in memory; the password and key may linger in process memory.
- No key-file or public-key mode; a lost password means unrecoverable data by design.

## Reporting
Please report vulnerabilities privately to the maintainers rather than opening a public issue.
