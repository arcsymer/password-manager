#include "pwman/totp.hpp"

// libsodium deliberately does not expose HMAC-SHA1. The umbrella <sodium.h>
// provides HMAC-SHA256 via crypto_auth_hmacsha256, which is used here.
// RFC 6238 explicitly permits SHA-256 as the underlying PRF.
#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace pwman {

// ---------------------------------------------------------------------------
// Base32 (RFC 4648)
// ---------------------------------------------------------------------------
static const char kBase32Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

std::string base32_encode(const std::vector<uint8_t>& data) {
    std::string out;
    size_t bits = 0;
    uint32_t acc = 0;
    for (uint8_t byte : data) {
        acc = (acc << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(kBase32Alphabet[(acc >> bits) & 0x1F]);
        }
    }
    if (bits > 0) {
        out.push_back(kBase32Alphabet[(acc << (5 - bits)) & 0x1F]);
    }
    // Pad to multiple of 8 characters.
    while (out.size() % 8 != 0) {
        out.push_back('=');
    }
    return out;
}

std::vector<uint8_t> base32_decode(const std::string& encoded) {
    // Strip trailing '=' padding.
    size_t end = encoded.size();
    while (end > 0 && encoded[end - 1] == '=') --end;

    std::vector<uint8_t> out;
    uint32_t acc  = 0;
    size_t   bits = 0;

    for (size_t i = 0; i < end; ++i) {
        const char c = static_cast<char>(std::toupper(static_cast<unsigned char>(encoded[i])));
        const char* p = std::find(kBase32Alphabet, kBase32Alphabet + 32, c);
        if (p == kBase32Alphabet + 32) {
            throw Base32Error(std::string("invalid Base32 character: ") + encoded[i]);
        }
        acc  = (acc << 5) | static_cast<uint32_t>(p - kBase32Alphabet);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// TOTP — RFC 6238 / RFC 4226 (using HMAC-SHA256)
// ---------------------------------------------------------------------------
uint32_t totp(const std::vector<uint8_t>& key,
              uint64_t                    unix_time,
              uint32_t                    digits,
              uint32_t                    period) {
    if (digits == 0 || digits > 9) {
        throw std::invalid_argument("TOTP digits must be 1-9");
    }
    if (period == 0) {
        throw std::invalid_argument("TOTP period must be > 0");
    }

    // T = floor(unix_time / period) as big-endian 8-byte integer.
    const uint64_t T = unix_time / static_cast<uint64_t>(period);
    uint8_t T_be[8];
    T_be[0] = static_cast<uint8_t>((T >> 56) & 0xFF);
    T_be[1] = static_cast<uint8_t>((T >> 48) & 0xFF);
    T_be[2] = static_cast<uint8_t>((T >> 40) & 0xFF);
    T_be[3] = static_cast<uint8_t>((T >> 32) & 0xFF);
    T_be[4] = static_cast<uint8_t>((T >> 24) & 0xFF);
    T_be[5] = static_cast<uint8_t>((T >> 16) & 0xFF);
    T_be[6] = static_cast<uint8_t>((T >>  8) & 0xFF);
    T_be[7] = static_cast<uint8_t>( T        & 0xFF);

    // HMAC-SHA256 via the libsodium streaming API.
    // crypto_auth_hmacsha256_init accepts variable-length keys, so Base32
    // secrets of any decoded length are handled correctly.
    // libsodium does not expose HMAC-SHA1; HMAC-SHA256 is used instead
    // (RFC 6238 §1.2 explicitly lists SHA-256 as a supported algorithm).
    uint8_t mac[crypto_auth_hmacsha256_BYTES]; // 32 bytes
    crypto_auth_hmacsha256_state st;
    if (crypto_auth_hmacsha256_init(&st, key.data(), key.size()) != 0 ||
        crypto_auth_hmacsha256_update(&st, T_be, sizeof(T_be))   != 0 ||
        crypto_auth_hmacsha256_final(&st, mac)                   != 0) {
        throw std::runtime_error("HMAC-SHA256 failed");
    }

    // Dynamic truncation (RFC 4226 §5.4).
    // offset is derived from the last byte of the 32-byte SHA-256 MAC.
    const uint8_t offset = mac[crypto_auth_hmacsha256_BYTES - 1] & 0x0F;
    const uint32_t P =
        (static_cast<uint32_t>(mac[offset    ]) << 24)
      | (static_cast<uint32_t>(mac[offset + 1]) << 16)
      | (static_cast<uint32_t>(mac[offset + 2]) <<  8)
      | (static_cast<uint32_t>(mac[offset + 3])      );
    const uint32_t sbits = P & 0x7FFFFFFF;

    // Compute modulus: 10^digits.
    uint32_t modulus = 1;
    for (uint32_t d = 0; d < digits; ++d) {
        modulus *= 10;
    }

    return sbits % modulus;
}

std::string totp_string(const std::vector<uint8_t>& key,
                        uint64_t                    unix_time,
                        uint32_t                    digits,
                        uint32_t                    period) {
    const uint32_t code = totp(key, unix_time, digits, period);
    std::ostringstream oss;
    oss << std::setw(static_cast<int>(digits)) << std::setfill('0') << code;
    return oss.str();
}

// ---------------------------------------------------------------------------
// TOTP clock-drift tolerant verification (RFC 6238 §5.2)
// ---------------------------------------------------------------------------
bool totp_verify(const std::vector<uint8_t>& key,
                 uint32_t                    code,
                 uint64_t                    unix_time,
                 uint32_t                    digits,
                 uint32_t                    period,
                 uint32_t                    window) {
    // Check the current step plus/minus `window` steps.
    // We work in signed space to handle the case where unix_time < window*period
    // (e.g. unit tests using T=0 with window=1 would otherwise underflow uint64).
    const int64_t  step_size   = static_cast<int64_t>(period);
    const int64_t  t_signed    = static_cast<int64_t>(unix_time);
    const int64_t  win         = static_cast<int64_t>(window);

    for (int64_t offset = -win; offset <= win; ++offset) {
        const int64_t t_adj = t_signed + offset * step_size;
        if (t_adj < 0) {
            continue; // timestep before epoch — skip
        }
        if (totp(key, static_cast<uint64_t>(t_adj), digits, period) == code) {
            return true;
        }
    }
    return false;
}

} // namespace pwman
