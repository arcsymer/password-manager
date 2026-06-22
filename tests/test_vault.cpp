// Vault data-model tests: add, remove, find, search/filter.

#include "pwman/vault.hpp"
#include "pwman/entry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

static pwman::Entry make_entry(const std::string& name,
                               const std::string& username = "",
                               const std::string& url      = "",
                               std::vector<std::string> tags = {}) {
    pwman::Entry e;
    e.name     = name;
    e.username = username;
    e.url      = url;
    e.tags     = std::move(tags);
    e.password = "irrelevant";
    return e;
}

TEST_CASE("Vault::add assigns monotonically increasing ids", "[vault]") {
    pwman::Vault v;
    const uint64_t id1 = v.add(make_entry("A"));
    const uint64_t id2 = v.add(make_entry("B"));
    const uint64_t id3 = v.add(make_entry("C"));
    CHECK(id1 < id2);
    CHECK(id2 < id3);
}

TEST_CASE("Vault::find returns entry when present", "[vault]") {
    pwman::Vault v;
    const uint64_t id = v.add(make_entry("GitHub", "alice"));
    const auto result = v.find(id);
    REQUIRE(result.has_value());
    CHECK(result->name     == "GitHub");
    CHECK(result->username == "alice");
}

TEST_CASE("Vault::find returns nullopt when absent", "[vault]") {
    pwman::Vault v;
    CHECK_FALSE(v.find(999).has_value());
}

TEST_CASE("Vault::remove returns true and entry is gone", "[vault]") {
    pwman::Vault v;
    const uint64_t id = v.add(make_entry("X"));
    CHECK(v.remove(id));
    CHECK_FALSE(v.find(id).has_value());
}

TEST_CASE("Vault::remove returns false for nonexistent id", "[vault]") {
    pwman::Vault v;
    CHECK_FALSE(v.remove(42));
}

TEST_CASE("Vault::search empty query returns all entries", "[vault][search]") {
    pwman::Vault v;
    v.add(make_entry("GitHub"));
    v.add(make_entry("GitLab"));
    v.add(make_entry("Jira"));
    const auto all = v.search("");
    CHECK(all.size() == 3);
}

TEST_CASE("Vault::search no matches returns empty", "[vault][search]") {
    pwman::Vault v;
    v.add(make_entry("GitHub"));
    v.add(make_entry("GitLab"));
    const auto res = v.search("notexist");
    CHECK(res.empty());
}

TEST_CASE("Vault::search matches on name (case-insensitive)", "[vault][search]") {
    pwman::Vault v;
    v.add(make_entry("GitHub"));
    v.add(make_entry("Gmail"));
    v.add(make_entry("Jira"));

    CHECK(v.search("git").size() == 1);
    CHECK(v.search("GIT").size() == 1);
    CHECK(v.search("Git").size() == 1);
    CHECK(v.search("g").size()   == 2); // GitHub + Gmail
}

TEST_CASE("Vault::search matches on username", "[vault][search]") {
    pwman::Vault v;
    v.add(make_entry("Site A", "alice@corp.com"));
    v.add(make_entry("Site B", "bob@corp.com"));
    v.add(make_entry("Site C", "charlie@example.com"));

    const auto res = v.search("@corp");
    CHECK(res.size() == 2);
}

TEST_CASE("Vault::search matches on url", "[vault][search]") {
    pwman::Vault v;
    v.add(make_entry("Google", "", "https://google.com"));
    v.add(make_entry("DDG",    "", "https://duckduckgo.com"));

    CHECK(v.search("google.com").size() == 1);
    CHECK(v.search("https://").size()   == 2);
}

TEST_CASE("Vault::search matches on tags", "[vault][search]") {
    pwman::Vault v;
    v.add(make_entry("App1", "", "", {"work", "cloud"}));
    v.add(make_entry("App2", "", "", {"personal", "cloud"}));
    v.add(make_entry("App3", "", "", {"work"}));

    CHECK(v.search("cloud").size() == 2);
    CHECK(v.search("WORK").size()  == 2);  // case-insensitive
    CHECK(v.search("personal").size() == 1);
}

TEST_CASE("Vault::search is case-insensitive across all fields", "[vault][search]") {
    pwman::Vault v;
    v.add(make_entry("GitHub", "Alice@Example.COM", "https://GITHUB.COM", {"DEV"}));

    CHECK(v.search("github").size()       == 1);
    CHECK(v.search("ALICE").size()        == 1);
    CHECK(v.search("example.com").size()  == 1);
    CHECK(v.search("dev").size()          == 1);
}

TEST_CASE("Vault with no entries search returns empty", "[vault][search]") {
    pwman::Vault v;
    CHECK(v.search("anything").empty());
    CHECK(v.search("").empty());
}
