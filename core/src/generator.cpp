#include "pwman/generator.hpp"

#include <sodium.h>

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

} // namespace pwman
