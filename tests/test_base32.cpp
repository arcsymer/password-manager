// Base32 tests — RFC 4648 §10 official test vectors.

#include "pwman/totp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>
#include <vector>

static std::vector<uint8_t> bytes(const char* s) {
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(s),
                                reinterpret_cast<const uint8_t*>(s) + std::strlen(s));
}

TEST_CASE("Base32 encode — RFC 4648 vectors", "[base32][encode]") {
    // RFC 4648 §10 test vectors.
    CHECK(pwman::base32_encode({})             == "");
    CHECK(pwman::base32_encode(bytes("f"))     == "MY======");
    CHECK(pwman::base32_encode(bytes("fo"))    == "MZXQ====");
    CHECK(pwman::base32_encode(bytes("foo"))   == "MZXW6===");
    CHECK(pwman::base32_encode(bytes("foob"))  == "MZXW6YQ=");
    CHECK(pwman::base32_encode(bytes("fooba")) == "MZXW6YTB");
    CHECK(pwman::base32_encode(bytes("foobar"))== "MZXW6YTBOI======");
}

TEST_CASE("Base32 decode — RFC 4648 vectors (round-trip)", "[base32][decode]") {
    CHECK(pwman::base32_decode("")                 == std::vector<uint8_t>{});
    CHECK(pwman::base32_decode("MY======")         == bytes("f"));
    CHECK(pwman::base32_decode("MZXQ====")         == bytes("fo"));
    CHECK(pwman::base32_decode("MZXW6===")         == bytes("foo"));
    CHECK(pwman::base32_decode("MZXW6YQ=")         == bytes("foob"));
    CHECK(pwman::base32_decode("MZXW6YTB")         == bytes("fooba"));
    CHECK(pwman::base32_decode("MZXW6YTBOI======") == bytes("foobar"));
}

TEST_CASE("Base32 decode — case insensitive", "[base32][decode]") {
    CHECK(pwman::base32_decode("my======")          == bytes("f"));
    CHECK(pwman::base32_decode("mzxw6ytboi======") == bytes("foobar"));
}

TEST_CASE("Base32 decode — invalid character throws", "[base32][decode]") {
    CHECK_THROWS_AS(pwman::base32_decode("MY!===="), pwman::Base32Error);
    CHECK_THROWS_AS(pwman::base32_decode("1======="), pwman::Base32Error);
}

TEST_CASE("Base32 encode→decode round-trip", "[base32]") {
    const std::vector<uint8_t> original = {0x00, 0xFF, 0xAB, 0xCD, 0x12, 0x34};
    const std::string encoded  = pwman::base32_encode(original);
    const auto        decoded  = pwman::base32_decode(encoded);
    CHECK(decoded == original);
}
