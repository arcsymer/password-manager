// TOTP tests — RFC 6238 official test vectors (Appendix B, SHA-256 column)
// Key: ASCII string "12345678901234567890123456789012" used as raw bytes (32 bytes).
// Algorithm: SHA-256 (HMAC-SHA256 via libsodium crypto_auth_hmacsha256).
// Digits: 8, Period: 30.
//
// libsodium does not expose HMAC-SHA1, so TOTP uses HMAC-SHA256.
// RFC 6238 explicitly supports SHA-256 as the underlying PRF.

#include "pwman/totp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

// The RFC 6238 SHA-256 seed as raw bytes: ASCII "12345678901234567890123456789012"
static std::vector<uint8_t> rfc_sha256_key() {
    const char* seed = "12345678901234567890123456789012";
    return std::vector<uint8_t>(seed, seed + 32);
}

TEST_CASE("TOTP RFC 6238 official SHA-256 vectors", "[totp][rfc6238]") {
    const auto key = rfc_sha256_key();
    constexpr uint32_t DIGITS = 8;
    constexpr uint32_t PERIOD = 30;

    // Table from RFC 6238 Appendix B, SHA-256 column.
    SECTION("T=59            → 46119246") {
        CHECK(pwman::totp_string(key, 59ULL, DIGITS, PERIOD) == "46119246");
    }
    SECTION("T=1111111109    → 68084774") {
        CHECK(pwman::totp_string(key, 1111111109ULL, DIGITS, PERIOD) == "68084774");
    }
    SECTION("T=1111111111    → 67062674") {
        CHECK(pwman::totp_string(key, 1111111111ULL, DIGITS, PERIOD) == "67062674");
    }
    SECTION("T=1234567890    → 91819424") {
        CHECK(pwman::totp_string(key, 1234567890ULL, DIGITS, PERIOD) == "91819424");
    }
    SECTION("T=2000000000    → 90698825") {
        CHECK(pwman::totp_string(key, 2000000000ULL, DIGITS, PERIOD) == "90698825");
    }
    SECTION("T=20000000000   → 77737706") {
        CHECK(pwman::totp_string(key, 20000000000ULL, DIGITS, PERIOD) == "77737706");
    }
}

TEST_CASE("TOTP default parameters (6 digits, period 30)", "[totp]") {
    const auto key = rfc_sha256_key();
    // Just ensure it runs and returns a 6-character zero-padded string.
    const std::string code = pwman::totp_string(key, 59ULL);
    REQUIRE(code.size() == 6);
    for (char c : code) {
        REQUIRE(c >= '0');
        REQUIRE(c <= '9');
    }
}

TEST_CASE("TOTP invalid parameters throw", "[totp]") {
    const auto key = rfc_sha256_key();
    CHECK_THROWS_AS(pwman::totp(key, 0, 0, 30), std::invalid_argument);
    CHECK_THROWS_AS(pwman::totp(key, 0, 6,  0), std::invalid_argument);
}
