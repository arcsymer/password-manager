#include "pwman/vault.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace pwman {

namespace {
// Convert string to lowercase for case-insensitive comparison.
std::string to_lower(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        out.push_back(static_cast<char>(std::tolower(c)));
    }
    return out;
}

bool contains_icase(const std::string& haystack, const std::string& needle_lower) {
    return to_lower(haystack).find(needle_lower) != std::string::npos;
}
} // anonymous namespace

uint64_t Vault::add(Entry e) {
    e.id = next_id_++;
    entries_.push_back(std::move(e));
    return entries_.back().id;
}

bool Vault::remove(uint64_t id) {
    auto it = std::find_if(entries_.begin(), entries_.end(),
                           [id](const Entry& e) { return e.id == id; });
    if (it == entries_.end()) {
        return false;
    }
    entries_.erase(it);
    return true;
}

std::optional<Entry> Vault::find(uint64_t id) const {
    auto it = std::find_if(entries_.begin(), entries_.end(),
                           [id](const Entry& e) { return e.id == id; });
    if (it == entries_.end()) {
        return std::nullopt;
    }
    return *it;
}

void Vault::restore(Entry e) {
    if (e.id >= next_id_) {
        next_id_ = e.id + 1;
    }
    entries_.push_back(std::move(e));
}

std::optional<Entry> Vault::find_by_name(const std::string& name) const {
    const std::string name_lower = to_lower(name);
    for (const Entry& e : entries_) {
        if (to_lower(e.name) == name_lower) {
            return e;
        }
    }
    return std::nullopt;
}

bool Vault::update(uint64_t id, const Entry& fields) {
    auto it = std::find_if(entries_.begin(), entries_.end(),
                           [id](const Entry& e) { return e.id == id; });
    if (it == entries_.end()) {
        return false;
    }
    // Overwrite all mutable fields; id stays unchanged.
    it->name     = fields.name;
    it->username = fields.username;
    it->url      = fields.url;
    it->password = fields.password;
    it->notes    = fields.notes;
    it->tags     = fields.tags;
    return true;
}

std::vector<Entry> Vault::search(const std::string& query) const {
    if (query.empty()) {
        return entries_;
    }
    const std::string q = to_lower(query);
    std::vector<Entry> results;
    for (const Entry& e : entries_) {
        bool match = contains_icase(e.name, q)
                  || contains_icase(e.username, q)
                  || contains_icase(e.url, q);
        if (!match) {
            for (const auto& tag : e.tags) {
                if (contains_icase(tag, q)) {
                    match = true;
                    break;
                }
            }
        }
        if (match) {
            results.push_back(e);
        }
    }
    return results;
}

} // namespace pwman
