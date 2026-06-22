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

} // namespace pwman
