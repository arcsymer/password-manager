#pragma once

#include "vault.hpp"

#include <string>
#include <vector>
#include <stdexcept>

namespace pwman {

// Thrown when decryption fails (wrong password or corrupt file).
struct DecryptionError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Thrown when the file format is unrecognised or truncated.
struct FormatError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Securely wipe the contents of a std::string that held secret material (e.g.
// the master password) using sodium_memzero, which the compiler is not allowed
// to optimise away, then clear the string. Use this on password buffers as soon
// as they are no longer needed so the plaintext does not linger on the heap.
void secure_clear(std::string& secret);

// ---------------------------------------------------------------------------
// Serialisation (plaintext Vault <-> byte buffer)
// ---------------------------------------------------------------------------
// Format (all values UTF-8, separated by sentinel bytes):
//   HEADER_MAGIC (8 bytes literal "PWMV1\x00\x00\x00")
//   4-byte little-endian entry count
//   For each entry:
//     field separator = 0x1F (ASCII Unit Separator)
//     Fields in order: id(decimal), name, username, url, password, notes,
//                      tags (joined with 0x1E Record Separator)
//     Entry terminated by 0x1D (ASCII Group Separator)
//
// This avoids pulling in JSON and keeps the core self-contained.

std::vector<uint8_t> serialize(const Vault& vault);
Vault                deserialize(const std::vector<uint8_t>& data);

// ---------------------------------------------------------------------------
// Encryption / decryption
// ---------------------------------------------------------------------------
// File layout on disk:
//   [salt : crypto_pwhash_SALTBYTES bytes]
//   [nonce: crypto_secretbox_NONCEBYTES bytes]
//   [ciphertext: len(plaintext) + crypto_secretbox_MACBYTES bytes]
//
// KDF: Argon2id (crypto_pwhash) with MODERATE ops/mem limits
//      (~256 MiB / ~3 passes) — a deliberate step up from INTERACTIVE to make
//      offline brute-force of the master password materially more expensive.
// Cipher: XSalsa20-Poly1305 (crypto_secretbox_easy).

std::vector<uint8_t> encrypt_vault(const Vault& vault,
                                   const std::string& master_password);

Vault decrypt_vault(const std::vector<uint8_t>& file_bytes,
                    const std::string& master_password);

// Convenience wrappers that read/write a file path.
void  save_vault(const std::string& path, const Vault& vault,
                 const std::string& master_password);

Vault load_vault(const std::string& path,
                 const std::string& master_password);

// ---------------------------------------------------------------------------
// Change master password
// ---------------------------------------------------------------------------
// Decrypt the vault with old_password, re-encrypt with new_password, and
// write the result back to the same path. The write is atomic: save_vault()
// serialises to a temp file and rename()s it into place, so a crash can never
// corrupt the existing vault.
// Throws DecryptionError if old_password is wrong, or std::runtime_error on
// I/O failure.
void change_password(const std::string& path,
                     const std::string& old_password,
                     const std::string& new_password);

// ---------------------------------------------------------------------------
// Portable export / import (encrypted bundle)
// ---------------------------------------------------------------------------
// Export: serialize + encrypt the vault with export_password.
// The resulting bytes use the SAME on-disk layout as encrypt_vault(), so the
// bundle can be loaded directly with load_vault() / decrypt_vault().
// Use a different export_password from the master password for separation.
std::vector<uint8_t> export_vault(const Vault& vault,
                                  const std::string& export_password);

// Import: decrypt and deserialize an exported bundle.
// Identical to decrypt_vault(); provided as a named alias for clarity.
Vault import_vault(const std::vector<uint8_t>& bundle,
                   const std::string& export_password);

} // namespace pwman
