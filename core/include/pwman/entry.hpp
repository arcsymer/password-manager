#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace pwman {

// A single credential record stored inside a Vault.
struct Entry {
    uint64_t    id{0};
    std::string name;
    std::string username;
    std::string url;
    std::string password;
    std::string notes;
    std::vector<std::string> tags;

    // Equality: all fields must match.
    bool operator==(const Entry& o) const noexcept {
        return id       == o.id
            && name     == o.name
            && username == o.username
            && url      == o.url
            && password == o.password
            && notes    == o.notes
            && tags     == o.tags;
    }
    bool operator!=(const Entry& o) const noexcept { return !(*this == o); }
};

} // namespace pwman
