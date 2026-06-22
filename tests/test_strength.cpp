// Tests for password-strength estimation (estimate_strength).

#include "pwman/generator.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <cmath>

using pwman::StrengthLevel;
using pwman::estimate_strength;

TEST_CASE("Empty password is VERY_WEAK with 0 bits", "[strength]") {
    const auto r = estimate_strength("");
    CHECK(r.level == StrengthLevel::VERY_WEAK);
    CHECK(r.entropy_bits == 0.0);
}

TEST_CASE("Single lowercase character is VERY_WEAK", "[strength]") {
    // 1 char from alphabet 26 -> log2(26)*1 ~ 4.7 bits
    const auto r = estimate_strength("a");
    CHECK(r.level == StrengthLevel::VERY_WEAK);
    CHECK(r.entropy_bits > 0.0);
    CHECK(r.entropy_bits < 28.0);
}

TEST_CASE("Short all-lowercase password is VERY_WEAK or WEAK", "[strength]") {
    // 5 chars lowercase: log2(26)*5 ~ 23.5 bits -> VERY_WEAK
    const auto r = estimate_strength("abcde");
    CHECK(r.level == StrengthLevel::VERY_WEAK);
}

TEST_CASE("Mixed-case short password is WEAK or VERY_WEAK", "[strength]") {
    // 4 chars mixed case: log2(52)*4 ~ 22.8 bits -> VERY_WEAK
    const auto r = estimate_strength("aBcD");
    CHECK((r.level == StrengthLevel::VERY_WEAK || r.level == StrengthLevel::WEAK));
}

TEST_CASE("Typical 8-char alphanumeric password is FAIR", "[strength]") {
    // 8 chars from 62-char alphabet (a-z + A-Z + 0-9): log2(62)*8 ~ 47.6 bits -> FAIR
    const auto r = estimate_strength("Abc12345");
    CHECK(r.level == StrengthLevel::FAIR);
    CHECK(r.entropy_bits >= 36.0);
    CHECK(r.entropy_bits < 60.0);
}

TEST_CASE("12-char alphanumeric with symbols is STRONG", "[strength]") {
    // 12 chars from ~94-char alphabet: log2(94)*12 ~ 78.7 bits -> STRONG
    const auto r = estimate_strength("Abc1!Def2@Gh");
    CHECK(r.level == StrengthLevel::STRONG);
    CHECK(r.entropy_bits >= 60.0);
}

TEST_CASE("20-char full-charset password is VERY_STRONG", "[strength]") {
    // 20 chars from ~94-char alphabet: log2(94)*20 ~ 131 bits -> VERY_STRONG
    const auto r = estimate_strength("Tr0ub4dor&3!Xy9@ZpQ#");
    CHECK(r.level == StrengthLevel::VERY_STRONG);
    CHECK(r.entropy_bits >= 96.0);
}

TEST_CASE("Strength label strings are non-empty", "[strength]") {
    CHECK(std::string(estimate_strength("").label())             == "VERY_WEAK");
    CHECK(std::string(estimate_strength("abc").label())          == "VERY_WEAK");
    CHECK(std::string(estimate_strength("Abcdefgh").label())     == "FAIR");
    CHECK(std::string(estimate_strength("Tr0ub4dor&3!Xy9@ZpQ#").label()) == "VERY_STRONG");
}

TEST_CASE("Entropy bits increase with length for same charset", "[strength]") {
    const auto r8  = estimate_strength("Abcdefg1");   // 8 chars
    const auto r16 = estimate_strength("Abcdefg1Abcdefg1"); // 16 chars
    CHECK(r16.entropy_bits > r8.entropy_bits);
}

TEST_CASE("Entropy bits increase with larger charset", "[strength]") {
    // lowercase only vs lowercase+digits
    const auto r_lower = estimate_strength("abcdefgh"); // 8 lowercase
    const auto r_mixed = estimate_strength("abcdef12"); // 6 lower + 2 digits
    CHECK(r_mixed.entropy_bits > r_lower.entropy_bits);
}
