// TOTP tests — RFC 6238 official test vectors (Appendix B)
// Key: ASCII string "12345678901234567890" used as raw bytes (20 bytes for SHA1).
// Algorithm: SHA1 (HMAC-SHA1 via libsodium crypto_auth_hmacsha1).
// Digits: 8, Period: 30.

#include "pwman/totp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

// The RFC 6238 SHA1 seed as raw bytes: ASCII "12345678901234567890"
static std::vector<uint8_t> rfc_sha1_key() {
    const char* seed = "12345678901234567890";
    return std::vector<uint8_t>(seed, seed + 20);
}

TEST_CASE("TOTP RFC 6238 official SHA1 vectors", "[totp][rfc6238]") {
    const auto key = rfc_sha1_key();
    constexpr uint32_t DIGITS = 8;
    constexpr uint32_t PERIOD = 30;

    // Table from RFC 6238 Appendix B.
    SECTION("T=59            → 94287082") {
        CHECK(pwman::totp_string(key, 59ULL, DIGITS, PERIOD) == "94287082");
    }
    SECTION("T=1111111109    → 07081804") {
        CHECK(pwman::totp_string(key, 1111111109ULL, DIGITS, PERIOD) == "07081804");
    }
    SECTION("T=1111111111    → 14050471") {
        CHECK(pwman::totp_string(key, 1111111111ULL, DIGITS, PERIOD) == "14050471");
    }
    SECTION("T=1234567890    → 89005924") {
        CHECK(pwman::totp_string(key, 1234567890ULL, DIGITS, PERIOD) == "89005924");
    }
    SECTION("T=2000000000    → 69279037") {
        CHECK(pwman::totp_string(key, 2000000000ULL, DIGITS, PERIOD) == "69279037");
    }
    SECTION("T=20000000000   → 65353130") {
        CHECK(pwman::totp_string(key, 20000000000ULL, DIGITS, PERIOD) == "65353130");
    }
}

TEST_CASE("TOTP default parameters (6 digits, period 30)", "[totp]") {
    const auto key = rfc_sha1_key();
    // Just ensure it runs and returns a 6-character zero-padded string.
    const std::string code = pwman::totp_string(key, 59ULL);
    REQUIRE(code.size() == 6);
    for (char c : code) {
        REQUIRE(c >= '0');
        REQUIRE(c <= '9');
    }
}

TEST_CASE("TOTP invalid parameters throw", "[totp]") {
    const auto key = rfc_sha1_key();
    CHECK_THROWS_AS(pwman::totp(key, 0, 0, 30), std::invalid_argument);
    CHECK_THROWS_AS(pwman::totp(key, 0, 6,  0), std::invalid_argument);
}
