# pwman — Password Manager

[![CI](https://github.com/arcsymer/password-manager/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/arcsymer/password-manager/actions/workflows/ci.yml)
![tests: 28 passing](https://img.shields.io/badge/tests-28%20passing-brightgreen)

This is a learning and portfolio project. It hasn't been through a security audit, so
please don't use it for real secrets.

A command-line password manager written in C++17. It uses
[libsodium](https://libsodium.org/) for authenticated encryption (Argon2id + XSalsa20-Poly1305)
and RFC 6238 TOTP, keeps the library and CLI separate, and writes no custom crypto of its own.

---

## Problem / Solution

**Problem:** Storing credentials on disk needs both strong key derivation (to resist offline
brute-force) and authenticated encryption (to detect tampering or a wrong password without
revealing plaintext). TOTP two-factor tokens have to match the RFC 6238 standard exactly.

**Solution:**
- Argon2id (libsodium `crypto_pwhash`) derives a 256-bit key from the master password and a
  random 16-byte salt, with INTERACTIVE memory/ops limits.
- XSalsa20-Poly1305 (`crypto_secretbox_easy`) encrypts the serialised vault with a random 24-byte
  nonce. The MAC catches any wrong-password or corruption case before any plaintext is returned.
- TOTP uses libsodium `crypto_auth_hmacsha256` to implement RFC 4226/6238 deterministically,
  checked against the official SHA-256 test vectors in Appendix B of RFC 6238.
  libsodium intentionally does not expose HMAC-SHA1, and RFC 6238 permits SHA-256 as the PRF.

---

## Security design

| Layer        | Primitive                                | Library               |
|--------------|------------------------------------------|-----------------------|
| KDF          | Argon2id (INTERACTIVE ops/mem)           | libsodium `crypto_pwhash` |
| Encryption   | XSalsa20-Poly1305 (authenticated)        | libsodium `crypto_secretbox_easy` |
| TOTP MAC     | HMAC-SHA256                              | libsodium `crypto_auth_hmacsha256` |
| CSPRNG       | OS-seeded                                | libsodium `randombytes_buf/uniform` |

No custom cryptography: every primitive comes straight from libsodium.

TOTP compatibility note: libsodium doesn't expose SHA-1 (considered cryptographically
weak), so TOTP here uses HMAC-SHA256, which RFC 6238 allows. Most consumer authenticator
apps (Google Authenticator, Authy, and so on) default to HMAC-SHA1, so codes generated
here won't match a standard SHA-1 authenticator for the same secret. That's a deliberate
trade-off to keep the only dependency libsodium.

### Vault file format

```
[salt: 16 bytes (crypto_pwhash_SALTBYTES)]
[nonce: 24 bytes (crypto_secretbox_NONCEBYTES)]
[ciphertext: plaintext_len + 16 bytes MAC (crypto_secretbox_MACBYTES)]
```

A wrong password causes `crypto_secretbox_open_easy` to return -1; the library throws
`pwman::DecryptionError` before any plaintext is produced.

---

## Architecture

```
password-manager/
├── core/                  # pwman-core (static library)
│   ├── include/pwman/
│   │   ├── entry.hpp      # Entry struct (id, name, username, url, tags, password, notes)
│   │   ├── vault.hpp      # Vault class: add/remove/find/search
│   │   ├── crypto.hpp     # serialize/deserialize + encrypt_vault/decrypt_vault + file I/O
│   │   ├── totp.hpp       # totp() + totp_string() + base32_encode/decode
│   │   └── generator.hpp  # generate_password()
│   └── src/               # Implementations
├── cli/                   # pwman-cli (executable)
│   └── src/main.cpp       # Argument parser + command dispatch
├── tests/                 # pwman-tests (Catch2 v3, via FetchContent)
│   ├── test_totp.cpp      # RFC 6238 vectors
│   ├── test_base32.cpp    # RFC 4648 vectors
│   ├── test_crypto.cpp    # Round-trip + wrong-password + tamper
│   └── test_vault.cpp     # add/remove/find/search
├── scripts/demo.sh        # Non-interactive CI demo
└── .github/workflows/ci.yml
```

**Dependencies:**
- libsodium (system, `libsodium-dev` on Ubuntu)
- Catch2 v3.5.4 (fetched by CMake FetchContent, no system install required)

---

## Build

```bash
# Ubuntu / Debian
sudo apt-get install -y libsodium-dev cmake build-essential pkg-config

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

---

## Tests

```bash
ctest --test-dir build --output-on-failure
```

28 test cases across 4 files:

| File             | Count | What is covered                                                          |
|------------------|-------|--------------------------------------------------------------------------|
| test_totp.cpp    | 3     | RFC 6238 SHA-256 vectors (6 timesteps), default params, invalid arg throws |
| test_base32.cpp  | 5     | RFC 4648 encode + decode vectors, case-insensitive decode, error, round-trip |
| test_crypto.cpp  | 7     | Serialise round-trip, empty vault, minimal entry, encrypt/decrypt, wrong password, truncated input, random salt uniqueness |
| test_vault.cpp   | 13    | add (ids), find, remove, search by name/username/url/tags, case-insensitivity, empty vault, no matches |

### RFC 6238 SHA-256 test vectors (Appendix B)

Key: raw bytes of ASCII `"12345678901234567890123456789012"` (32 bytes), digits=8, period=30:

| Unix time       | Expected code |
|-----------------|---------------|
| 59              | 46119246      |
| 1111111109      | 68084774      |
| 1111111111      | 67062674      |
| 1234567890      | 91819424      |
| 2000000000      | 90698825      |
| 20000000000     | 77737706      |

---

## Usage

### Vault operations

```bash
# Create vault and add entries (synthetic example)
pwman-cli --vault my.vault --password masterpass add \
    --name "GitHub" --username "alice@example.com" \
    --url "https://github.com" --password-entry "s3cr3t" --tags "dev,work"

# List all entries
pwman-cli --vault my.vault --password masterpass list

# Search (case-insensitive, matches name/username/url/tags)
pwman-cli --vault my.vault --password masterpass search dev

# Remove by id
pwman-cli --vault my.vault --password masterpass remove 1

# Verify master password
pwman-cli --vault my.vault --password masterpass unlock
```

### TOTP

```bash
# Decode a Base32 TOTP secret and generate current code
pwman-cli totp --secret JBSWY3DPEHPK3PXP --digits 6 --period 30

# With fixed time (for testing — SHA-256 vector from RFC 6238 Appendix B)
pwman-cli totp --secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ --digits 8 --time 59
# → 46119246  (HMAC-SHA256; differs from SHA-1 authenticators by design)
```

### Password generator

```bash
pwman-cli generate --length 20
pwman-cli generate --length 16 --no-symbols
pwman-cli generate --length 12 --no-symbols --no-digits
```

---

## CI demo session

Captured verbatim from the `demo` step of a GitHub Actions run
(`scripts/demo.sh`, Ubuntu, libsodium):

```text
========================================
 pwman-cli  —  demo session
========================================

[1] Adding synthetic entries...
OK: added entry id=1
OK: added entry id=2
OK: added entry id=3

[2] Listing all entries...
3 entries:
[1] GitHub Demo  user=demouser@example.com  url=https://github.com  tags=dev,work
[2] Email Demo  user=demouser@example.com  url=https://mail.example.com  tags=personal
[3] Jira Demo  user=demouser  url=https://jira.example.com  tags=work

[3] Searching for 'demo'...
3 result(s) for "demo":
[1] GitHub Demo  user=demouser@example.com  url=https://github.com  tags=dev,work
[2] Email Demo  user=demouser@example.com  url=https://mail.example.com  tags=personal
[3] Jira Demo  user=demouser  url=https://jira.example.com  tags=work

[4] Searching for 'work'...
2 result(s) for "work":
[1] GitHub Demo  user=demouser@example.com  url=https://github.com  tags=dev,work
[3] Jira Demo  user=demouser  url=https://jira.example.com  tags=work

[5] Searching for 'nonexistent'...
0 result(s) for "nonexistent":

[6] Unlocking vault with correct password...
OK: vault unlocked, 3 entries.

[7] Attempting unlock with wrong password (expect error)...
ERROR: decryption failed: wrong password or corrupt data
Expected error: decryption failed.

[8] TOTP code at T=59 (HMAC-SHA256, deterministic 8-digit)...
32247374

[9] TOTP at T=1234567890 (HMAC-SHA256, deterministic 8-digit)...
42829826

[10] Generating a random 24-char password...
Z0i1Za.U;-h%-hVz([$ktDnW

[11] Generating alphanumeric-only password (no symbols)...
sKwo0LMXuxO3bJUu

========================================
 Demo complete.
========================================
```

---

## License

MIT
