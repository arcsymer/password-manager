// Tests for the exclude_ambiguous option in GeneratorOptions.
//
// Verifies that when exclude_ambiguous=true the characters '0', 'O', 'I', 'l',
// '1' never appear in generated passwords, and that the generator still
// produces passwords of the requested length with valid characters.

#include "pwman/generator.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

static const std::string kAmbiguousChars = "0OIl1";

static bool contains_ambiguous(const std::string& pw) {
    for (char c : pw) {
        if (kAmbiguousChars.find(c) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// exclude_ambiguous = false (default) — ambiguous chars may appear
// ---------------------------------------------------------------------------

TEST_CASE("Default generator does not strip ambiguous characters",
          "[generator][ambiguous]") {
    // Generate a large batch and confirm that ambiguous chars can appear.
    // (They won't appear every time, but over 500 chars from a 94-char alphabet
    // the probability of zero ambiguous chars is astronomically small.)
    pwman::GeneratorOptions opts;
    opts.length = 500;
    opts.exclude_ambiguous = false;

    std::string pw = pwman::generate_password(opts);
    REQUIRE(pw.size() == 500);
    // At least one ambiguous character must appear in a 500-char sample
    // drawn from the full alphabet (expected ~26 hits out of 500).
    // We simply document this is NOT forced to be absent.
    // (This test would fail extremely rarely; ~10^-11 probability of no hits.)
    CHECK(contains_ambiguous(pw));
}

// ---------------------------------------------------------------------------
// exclude_ambiguous = true
// ---------------------------------------------------------------------------

TEST_CASE("exclude_ambiguous removes 0, O, I, l, 1 from full-charset passwords",
          "[generator][ambiguous]") {
    pwman::GeneratorOptions opts;
    opts.length             = 200;
    opts.exclude_ambiguous  = true;

    const std::string pw = pwman::generate_password(opts);
    REQUIRE(pw.size() == 200);
    CHECK_FALSE(contains_ambiguous(pw));
}

TEST_CASE("exclude_ambiguous produces correct length", "[generator][ambiguous]") {
    pwman::GeneratorOptions opts;
    opts.length            = 32;
    opts.exclude_ambiguous = true;

    const std::string pw = pwman::generate_password(opts);
    CHECK(pw.size() == 32);
}

TEST_CASE("exclude_ambiguous with digits=false still excludes '1' (already gone)",
          "[generator][ambiguous]") {
    pwman::GeneratorOptions opts;
    opts.length            = 100;
    opts.digits            = false;
    opts.exclude_ambiguous = true;

    const std::string pw = pwman::generate_password(opts);
    REQUIRE(pw.size() == 100);
    CHECK_FALSE(contains_ambiguous(pw));
    // No digit should appear at all (digits disabled).
    for (char c : pw) {
        CHECK(!(c >= '0' && c <= '9'));
    }
}

TEST_CASE("exclude_ambiguous with symbols=false still removes O, I, l",
          "[generator][ambiguous]") {
    pwman::GeneratorOptions opts;
    opts.length            = 200;
    opts.symbols           = false;
    opts.exclude_ambiguous = true;

    const std::string pw = pwman::generate_password(opts);
    REQUIRE(pw.size() == 200);
    CHECK_FALSE(contains_ambiguous(pw));
}

TEST_CASE("exclude_ambiguous with only lowercase still works", "[generator][ambiguous]") {
    // Only lowercase enabled; 'l' must be removed.
    pwman::GeneratorOptions opts;
    opts.length            = 200;
    opts.uppercase         = false;
    opts.digits            = false;
    opts.symbols           = false;
    opts.exclude_ambiguous = true;

    const std::string pw = pwman::generate_password(opts);
    REQUIRE(pw.size() == 200);
    // 'l' must not appear.
    CHECK(pw.find('l') == std::string::npos);
    // All characters must be lowercase letters.
    for (char c : pw) {
        CHECK(c >= 'a');
        CHECK(c <= 'z');
    }
}

TEST_CASE("exclude_ambiguous: all-digit alphabet still removes '0' and '1'",
          "[generator][ambiguous]") {
    // digits=true, everything else off, exclude_ambiguous=true
    // Remaining chars: 2-9 (8 chars)
    pwman::GeneratorOptions opts;
    opts.length            = 100;
    opts.uppercase         = false;
    opts.lowercase         = false;
    opts.symbols           = false;
    opts.digits            = true;
    opts.exclude_ambiguous = true;

    const std::string pw = pwman::generate_password(opts);
    REQUIRE(pw.size() == 100);
    for (char c : pw) {
        CHECK(c >= '2');
        CHECK(c <= '9');
    }
}

TEST_CASE("exclude_ambiguous passwords contain only allowed characters",
          "[generator][ambiguous]") {
    pwman::GeneratorOptions opts;
    opts.length            = 200;
    opts.exclude_ambiguous = true;

    const std::string pw = pwman::generate_password(opts);
    for (char c : pw) {
        // Must be printable ASCII and not one of the ambiguous chars.
        CHECK(c >= 0x20);
        CHECK(kAmbiguousChars.find(c) == std::string::npos);
    }
}

// ---------------------------------------------------------------------------
// Default (exclude_ambiguous = false) still generates correct length
// ---------------------------------------------------------------------------

TEST_CASE("Default generator produces requested length", "[generator][ambiguous]") {
    pwman::GeneratorOptions opts;
    opts.length = 24;
    const std::string pw = pwman::generate_password(opts);
    CHECK(pw.size() == 24);
}
