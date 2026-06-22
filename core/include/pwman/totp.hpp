#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <stdexcept>

namespace pwman {

// Thrown when a Base32 string contains invalid characters or padding.
struct Base32Error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// ---------------------------------------------------------------------------
// Base32 (RFC 4648, uppercase alphabet, padded with '=')
// ---------------------------------------------------------------------------
std::string          base32_encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> base32_decode(const std::string& encoded);

// ---------------------------------------------------------------------------
// TOTP (RFC 6238 / RFC 4226) — HMAC-SHA256 variant
// ---------------------------------------------------------------------------
// Computes a TOTP code from raw key bytes, a Unix timestamp, digit count, and
// time-step period in seconds.  Uses HMAC-SHA256 (libsodium
// crypto_auth_hmacsha256), because libsodium intentionally does not expose
// HMAC-SHA1.  RFC 6238 §1.2 permits SHA-256 as the underlying PRF.
//
// Note: most consumer authenticator apps default to HMAC-SHA1.  This
// implementation produces codes that will NOT match a SHA-1 authenticator for
// the same secret — this is a known, intentional trade-off of this portfolio
// project (zero external dependencies beyond libsodium).
//
// The key is the raw secret (NOT Base32-encoded).  Callers that receive a
// Base32 user secret must decode it first with base32_decode().
uint32_t totp(const std::vector<uint8_t>& key,
              uint64_t                    unix_time,
              uint32_t                    digits = 6,
              uint32_t                    period = 30);

// Formatted: zero-padded decimal string of length `digits`.
std::string totp_string(const std::vector<uint8_t>& key,
                        uint64_t                    unix_time,
                        uint32_t                    digits = 6,
                        uint32_t                    period = 30);

} // namespace pwman
