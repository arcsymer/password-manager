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
// KDF: Argon2id (crypto_pwhash) with INTERACTIVE ops/mem limits.
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

} // namespace pwman
