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
// TOTP (RFC 6238 / RFC 4226)
// ---------------------------------------------------------------------------
// Computes a TOTP code from raw key bytes, a Unix timestamp, digit count, and
// time-step period in seconds.  Uses HMAC-SHA1 (libsodium crypto_auth_hmacsha1).
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
