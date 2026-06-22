#pragma once

#include <string>
#include <cstdint>

namespace pwman {

struct GeneratorOptions {
    uint32_t length{20};
    bool     uppercase{true};
    bool     lowercase{true};
    bool     digits{true};
    bool     symbols{true};
};

// Generate a cryptographically random password using libsodium randombytes_buf.
// Throws std::invalid_argument if options would produce an empty alphabet or
// length == 0.
std::string generate_password(const GeneratorOptions& opts = {});

// ---------------------------------------------------------------------------
// Password-strength estimation
// ---------------------------------------------------------------------------
enum class StrengthLevel {
    VERY_WEAK,   // < 28 bits
    WEAK,        // 28-35 bits
    FAIR,        // 36-59 bits
    STRONG,      // 60-95 bits
    VERY_STRONG, // >= 96 bits
};

struct StrengthResult {
    StrengthLevel level;
    double        entropy_bits; // log2(alphabet_size) * length
    const char*   label() const noexcept;
};

// Estimate password strength.  The alphabet size is inferred from which
// character classes appear in the password; length penalties are applied
// for very short passwords.  Does not use external libraries or RNG.
StrengthResult estimate_strength(const std::string& password);

} // namespace pwman
