// Tests for FormatError handling in deserialize() and resilience of
// decrypt_vault() to truncated / tampered file bytes.
//
// These cover the gap where std::stoull previously leaked
// std::invalid_argument instead of FormatError for a corrupt entry id field.

#include "pwman/crypto.hpp"
#include "pwman/vault.hpp"
#include "pwman/entry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static pwman::Vault one_entry_vault() {
    pwman::Vault v;
    pwman::Entry e;
    e.name     = "Example";
    e.username = "user@example.com";
    e.password = "s3cr3t";
    v.add(std::move(e));
    return v;
}

// ---------------------------------------------------------------------------
// FormatError from deserialize()
// ---------------------------------------------------------------------------

TEST_CASE("deserialize: wrong magic throws FormatError", "[format_error][deserialize]") {
    // Replace the 8-byte magic with garbage.
    pwman::Vault v = one_entry_vault();
    std::vector<uint8_t> data = pwman::serialize(v);
    // Overwrite first 8 bytes.
    for (size_t i = 0; i < 8 && i < data.size(); ++i) {
        data[i] = 0xFF;
    }
    CHECK_THROWS_AS(pwman::deserialize(data), pwman::FormatError);
}

TEST_CASE("deserialize: truncated header throws FormatError", "[format_error][deserialize]") {
    // A buffer with valid magic but too short for the entry count.
    const uint8_t magic[] = {'P','W','M','V','1','\x00','\x00','\x00'};
    std::vector<uint8_t> data(magic, magic + sizeof(magic));
    // No entry count bytes appended — only 8 bytes total.
    CHECK_THROWS_AS(pwman::deserialize(data), pwman::FormatError);
}

TEST_CASE("deserialize: corrupt entry id (non-numeric) throws FormatError",
          "[format_error][deserialize]") {
    // Build a valid serialised vault, then corrupt the id field of entry 0.
    pwman::Vault v = one_entry_vault();
    std::vector<uint8_t> raw = pwman::serialize(v);

    // The id field starts right after the magic (8 bytes) + count (4 bytes)
    // + kFieldSep (1 byte) at offset 13.  The decimal id is "1" (1 byte).
    // Replace "1" with "XY" (invalid for stoull).
    // Find the first kFieldSep (0x1F) after the 12-byte header.
    size_t field_sep_pos = 12; // magic(8) + count(4)
    // Skip the FieldSep at pos 12, the id text starts at 13.
    // We replace that character with a non-digit.
    if (field_sep_pos < raw.size() && raw[field_sep_pos] == 0x1F) {
        // id value is at field_sep_pos + 1
        if (field_sep_pos + 1 < raw.size()) {
            raw[field_sep_pos + 1] = static_cast<uint8_t>('X');
        }
    }
    CHECK_THROWS_AS(pwman::deserialize(raw), pwman::FormatError);
}

TEST_CASE("deserialize: missing field separator throws FormatError",
          "[format_error][deserialize]") {
    // Build valid bytes then clobber the first field separator after the header.
    pwman::Vault v = one_entry_vault();
    std::vector<uint8_t> raw = pwman::serialize(v);
    // Position 12 should be 0x1F.
    if (raw.size() > 12 && raw[12] == 0x1F) {
        raw[12] = 0x00; // break the FieldSep
    }
    CHECK_THROWS_AS(pwman::deserialize(raw), pwman::FormatError);
}

// ---------------------------------------------------------------------------
// decrypt_vault() resilience
// ---------------------------------------------------------------------------

TEST_CASE("decrypt_vault: bit-flipped ciphertext throws DecryptionError",
          "[format_error][decrypt]") {
    // Encrypt a vault, then flip a bit in the ciphertext portion (past the
    // salt + nonce header, i.e. byte index >= 40).  The Poly1305 MAC must
    // catch this and throw DecryptionError, not crash or silently succeed.
    pwman::Vault v = one_entry_vault();
    std::vector<uint8_t> file_bytes = pwman::encrypt_vault(v, "masterpassword");

    // Flip a byte deep in the ciphertext (after the 40-byte header).
    const size_t flip_pos = 50; // well into the ciphertext region
    REQUIRE(file_bytes.size() > flip_pos);
    file_bytes[flip_pos] ^= 0xFF;

    CHECK_THROWS_AS(pwman::decrypt_vault(file_bytes, "masterpassword"),
                    pwman::DecryptionError);
}

TEST_CASE("decrypt_vault: file exactly at minimum size boundary throws FormatError",
          "[format_error][decrypt]") {
    // A buffer exactly 40 bytes (salt=16, nonce=24) with no room for MAC or
    // ciphertext is too short.
    const std::vector<uint8_t> tiny(40, 0x00);
    CHECK_THROWS_AS(pwman::decrypt_vault(tiny, "pw"), pwman::FormatError);
}

TEST_CASE("decrypt_vault: plaintext zeroed after decrypt does not affect returned Vault",
          "[format_error][decrypt]") {
    // After zeroization the Vault returned should still be intact.
    // (This test verifies the zeroization path doesn't corrupt the return value.)
    const pwman::Vault original = one_entry_vault();
    const std::vector<uint8_t> ct = pwman::encrypt_vault(original, "pw");
    const pwman::Vault restored = pwman::decrypt_vault(ct, "pw");
    CHECK(original == restored);
}
