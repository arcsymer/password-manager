// Tests for totp_verify() — clock-drift tolerant TOTP verification
// as specified in RFC 6238 §5.2.
//
// Uses the same RFC 6238 SHA-256 test key and known good codes to confirm
// that totp_verify() accepts codes within the allowed window and rejects
// codes outside it.

#include "pwman/totp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

// RFC 6238 SHA-256 seed: raw ASCII "12345678901234567890123456789012" (32 bytes)
static std::vector<uint8_t> rfc_key() {
    const char* seed = "12345678901234567890123456789012";
    return std::vector<uint8_t>(seed, seed + 32);
}

// Convenience: compute the exact TOTP code for a given timestamp.
static uint32_t code_at(uint64_t t, uint32_t digits = 8, uint32_t period = 30) {
    return pwman::totp(rfc_key(), t, digits, period);
}

// ---------------------------------------------------------------------------
// Strict mode (window = 0)
// ---------------------------------------------------------------------------

TEST_CASE("totp_verify window=0 accepts exact current code", "[totp_verify]") {
    // T=1234567890 -> RFC vector 91819424 (8 digits, period 30)
    const uint64_t T = 1234567890ULL;
    const uint32_t expected = code_at(T);
    CHECK(pwman::totp_verify(rfc_key(), expected, T, 8, 30, 0));
}

TEST_CASE("totp_verify window=0 rejects code from adjacent timestep", "[totp_verify]") {
    const uint64_t T = 1234567890ULL;
    // Compute code from the next timestep (T + 30 seconds).
    const uint32_t next_code = code_at(T + 30);
    // With window=0, the next-step code must be rejected.
    CHECK_FALSE(pwman::totp_verify(rfc_key(), next_code, T, 8, 30, 0));
}

// ---------------------------------------------------------------------------
// Window = 1 (RFC 6238 §5.2 recommended tolerance)
// ---------------------------------------------------------------------------

TEST_CASE("totp_verify window=1 accepts code from previous timestep (clock fast)",
          "[totp_verify]") {
    // The verifier's clock is one step ahead of the client.
    // The client sends the code for T-30; the server sees T.
    const uint64_t server_T = 1111111109ULL;
    const uint32_t client_code = code_at(server_T - 30); // one step behind
    CHECK(pwman::totp_verify(rfc_key(), client_code, server_T, 8, 30, 1));
}

TEST_CASE("totp_verify window=1 accepts code from next timestep (clock slow)",
          "[totp_verify]") {
    // The verifier's clock is one step behind the client.
    // The client sends the code for T+30; the server sees T.
    const uint64_t server_T = 1111111109ULL;
    const uint32_t client_code = code_at(server_T + 30); // one step ahead
    CHECK(pwman::totp_verify(rfc_key(), client_code, server_T, 8, 30, 1));
}

TEST_CASE("totp_verify window=1 rejects code two timesteps away", "[totp_verify]") {
    const uint64_t T = 1234567890ULL;
    const uint32_t far_code = code_at(T + 60); // two steps ahead
    CHECK_FALSE(pwman::totp_verify(rfc_key(), far_code, T, 8, 30, 1));
}

TEST_CASE("totp_verify window=1 accepts current code", "[totp_verify]") {
    const uint64_t T = 2000000000ULL;
    const uint32_t cur = code_at(T);
    CHECK(pwman::totp_verify(rfc_key(), cur, T, 8, 30, 1));
}

// ---------------------------------------------------------------------------
// Wrong code always rejected
// ---------------------------------------------------------------------------

TEST_CASE("totp_verify rejects obviously wrong code regardless of window",
          "[totp_verify]") {
    const uint64_t T = 59ULL;
    // 99999999 is extremely unlikely to match any of the 3 window steps
    // for this key/time.  Use a code that is known to be wrong.
    const uint32_t known_good = code_at(T, 8, 30); // 46119246
    const uint32_t wrong      = (known_good + 1) % 100000000u;
    // Make sure our "wrong" code doesn't accidentally appear in the window.
    // If it does by collision (1-in-10^8 chance), skip.
    if (wrong != code_at(T - 30, 8, 30) && wrong != code_at(T + 30, 8, 30)) {
        CHECK_FALSE(pwman::totp_verify(rfc_key(), wrong, T, 8, 30, 1));
    }
}

// ---------------------------------------------------------------------------
// Near-epoch edge case: window underflow must not crash
// ---------------------------------------------------------------------------

TEST_CASE("totp_verify with small unix_time and window=1 does not crash",
          "[totp_verify]") {
    // T=5 means T-30 would be negative; totp_verify must skip that step
    // gracefully without underflowing uint64_t.
    const uint64_t T = 5ULL;
    const uint32_t cur = code_at(T);
    // Should return true for the current step even though T-30 is skipped.
    CHECK(pwman::totp_verify(rfc_key(), cur, T, 8, 30, 1));
}

// ---------------------------------------------------------------------------
// Different digit counts and periods
// ---------------------------------------------------------------------------

TEST_CASE("totp_verify works with 6-digit codes and period=60", "[totp_verify]") {
    const uint64_t T = 1234567890ULL;
    const uint32_t c = code_at(T, 6, 60);
    CHECK(pwman::totp_verify(rfc_key(), c, T, 6, 60, 1));
}
