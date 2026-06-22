#include "pwman/generator.hpp"

#include <sodium.h>

#include <cmath>
#include <stdexcept>
#include <string>

namespace pwman {

std::string generate_password(const GeneratorOptions& opts) {
    if (opts.length == 0) {
        throw std::invalid_argument("password length must be > 0");
    }

    std::string alphabet;
    if (opts.uppercase) alphabet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (opts.lowercase) alphabet += "abcdefghijklmnopqrstuvwxyz";
    if (opts.digits)    alphabet += "0123456789";
    if (opts.symbols)   alphabet += "!@#$%^&*()-_=+[]{}|;:,.<>?";

    if (alphabet.empty()) {
        throw std::invalid_argument("no character classes selected");
    }

    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium initialisation failed");
    }

    const size_t alpha_len = alphabet.size();
    std::string password;
    password.reserve(opts.length);

    for (uint32_t i = 0; i < opts.length; ++i) {
        // randombytes_uniform gives an unbiased random number in [0, upper_bound).
        const uint32_t idx = randombytes_uniform(static_cast<uint32_t>(alpha_len));
        password.push_back(alphabet[idx]);
    }
    return password;
}

// ---------------------------------------------------------------------------
// Password-strength estimation
// ---------------------------------------------------------------------------
const char* StrengthResult::label() const noexcept {
    switch (level) {
        case StrengthLevel::VERY_WEAK:   return "VERY_WEAK";
        case StrengthLevel::WEAK:        return "WEAK";
        case StrengthLevel::FAIR:        return "FAIR";
        case StrengthLevel::STRONG:      return "STRONG";
        case StrengthLevel::VERY_STRONG: return "VERY_STRONG";
    }
    return "UNKNOWN";
}

StrengthResult estimate_strength(const std::string& password) {
    if (password.empty()) {
        return {StrengthLevel::VERY_WEAK, 0.0};
    }

    // Detect which character classes are present.
    bool has_lower   = false;
    bool has_upper   = false;
    bool has_digit   = false;
    bool has_symbol  = false;

    for (unsigned char c : password) {
        if (c >= 'a' && c <= 'z')        has_lower  = true;
        else if (c >= 'A' && c <= 'Z')   has_upper  = true;
        else if (c >= '0' && c <= '9')   has_digit  = true;
        else                              has_symbol = true;
    }

    // Approximate alphabet size from detected character classes.
    int alphabet = 0;
    if (has_lower)  alphabet += 26;
    if (has_upper)  alphabet += 26;
    if (has_digit)  alphabet += 10;
    if (has_symbol) alphabet += 32; // common printable symbols

    const double bits = static_cast<double>(password.size())
                      * std::log2(static_cast<double>(alphabet));

    StrengthLevel level;
    if (bits < 28.0)       level = StrengthLevel::VERY_WEAK;
    else if (bits < 36.0)  level = StrengthLevel::WEAK;
    else if (bits < 60.0)  level = StrengthLevel::FAIR;
    else if (bits < 96.0)  level = StrengthLevel::STRONG;
    else                   level = StrengthLevel::VERY_STRONG;

    return {level, bits};
}

} // namespace pwman
