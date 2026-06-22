#pragma once

#include "entry.hpp"

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace pwman {

// In-memory collection of Entry objects.
// All persistent I/O is handled by crypto.hpp; Vault is a pure data model.
class Vault {
public:
    Vault() = default;

    // Add a new entry; id is auto-assigned (monotonically increasing).
    // Returns the assigned id.
    uint64_t add(Entry e);

    // Remove entry by id. Returns true if an entry was found and removed.
    bool remove(uint64_t id);

    // Find entry by id. Returns nullopt if not found.
    std::optional<Entry> find(uint64_t id) const;

    // Case-insensitive substring search across name, username, url, and tags.
    // Empty query returns all entries.
    std::vector<Entry> search(const std::string& query) const;

    // Find first entry whose name matches exactly (case-insensitive).
    // Returns nullopt if not found.
    std::optional<Entry> find_by_name(const std::string& name) const;

    // Update an existing entry in-place (identified by e.id).
    // Only fields present in the supplied Entry are modified; id is never changed.
    // Returns true if the entry was found and updated, false otherwise.
    bool update(uint64_t id, const Entry& fields);

    const std::vector<Entry>& entries() const noexcept { return entries_; }

    bool operator==(const Vault& o) const noexcept { return entries_ == o.entries_; }
    bool operator!=(const Vault& o) const noexcept { return !(*this == o); }

    // For use by deserialize() only: insert an entry with a pre-existing id,
    // keeping next_id_ ahead of all restored ids.
    void restore(Entry e);

private:
    std::vector<Entry> entries_;
    uint64_t next_id_{1};
};

} // namespace pwman
