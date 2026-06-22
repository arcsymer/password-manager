// Tests for new Vault methods: update() and find_by_name().

#include "pwman/vault.hpp"
#include "pwman/entry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

static pwman::Entry make_entry(const std::string& name,
                               const std::string& username = "",
                               const std::string& url      = "",
                               const std::string& password = "pw",
                               std::vector<std::string> tags = {}) {
    pwman::Entry e;
    e.name     = name;
    e.username = username;
    e.url      = url;
    e.password = password;
    e.tags     = std::move(tags);
    return e;
}

// ---------------------------------------------------------------------------
// Vault::update
// ---------------------------------------------------------------------------
TEST_CASE("Vault::update modifies existing entry in-place", "[vault][update]") {
    pwman::Vault v;
    const uint64_t id = v.add(make_entry("OldName", "old_user", "http://old.com",
                                         "oldpw", {"old_tag"}));

    pwman::Entry updated = make_entry("NewName", "new_user", "http://new.com",
                                      "newpw", {"new_tag"});
    updated.notes = "some notes";

    const bool ok = v.update(id, updated);
    REQUIRE(ok);

    const auto result = v.find(id);
    REQUIRE(result.has_value());
    CHECK(result->id       == id);          // id must not change
    CHECK(result->name     == "NewName");
    CHECK(result->username == "new_user");
    CHECK(result->url      == "http://new.com");
    CHECK(result->password == "newpw");
    CHECK(result->notes    == "some notes");
    REQUIRE(result->tags.size() == 1);
    CHECK(result->tags[0]  == "new_tag");
}

TEST_CASE("Vault::update returns false for nonexistent id", "[vault][update]") {
    pwman::Vault v;
    v.add(make_entry("Existing"));
    pwman::Entry dummy = make_entry("Dummy");
    CHECK_FALSE(v.update(9999, dummy));
}

TEST_CASE("Vault::update preserves id and other entries are untouched",
          "[vault][update]") {
    pwman::Vault v;
    const uint64_t id1 = v.add(make_entry("A", "userA"));
    const uint64_t id2 = v.add(make_entry("B", "userB"));

    pwman::Entry patch = make_entry("A-updated", "userA-updated");
    v.update(id1, patch);

    // Entry 1 was updated.
    const auto e1 = v.find(id1);
    REQUIRE(e1.has_value());
    CHECK(e1->name == "A-updated");

    // Entry 2 is untouched.
    const auto e2 = v.find(id2);
    REQUIRE(e2.has_value());
    CHECK(e2->name == "B");
    CHECK(e2->username == "userB");
}

TEST_CASE("Vault::update on empty vault returns false", "[vault][update]") {
    pwman::Vault v;
    pwman::Entry e = make_entry("Ghost");
    CHECK_FALSE(v.update(1, e));
}

// ---------------------------------------------------------------------------
// Vault::find_by_name
// ---------------------------------------------------------------------------
TEST_CASE("Vault::find_by_name returns matching entry", "[vault][find_by_name]") {
    pwman::Vault v;
    v.add(make_entry("GitHub", "alice"));
    v.add(make_entry("GitLab", "bob"));

    const auto result = v.find_by_name("GitHub");
    REQUIRE(result.has_value());
    CHECK(result->name     == "GitHub");
    CHECK(result->username == "alice");
}

TEST_CASE("Vault::find_by_name is case-insensitive", "[vault][find_by_name]") {
    pwman::Vault v;
    v.add(make_entry("GitHub", "alice"));

    CHECK(v.find_by_name("github").has_value());
    CHECK(v.find_by_name("GITHUB").has_value());
    CHECK(v.find_by_name("GiThUb").has_value());
}

TEST_CASE("Vault::find_by_name returns nullopt when absent", "[vault][find_by_name]") {
    pwman::Vault v;
    v.add(make_entry("GitHub"));
    CHECK_FALSE(v.find_by_name("GitLab").has_value());
    CHECK_FALSE(v.find_by_name("").has_value());
}

TEST_CASE("Vault::find_by_name matches exact name only (not substring)",
          "[vault][find_by_name]") {
    pwman::Vault v;
    v.add(make_entry("My GitHub Account"));

    // Partial match must NOT be returned by find_by_name.
    CHECK_FALSE(v.find_by_name("GitHub").has_value());
    // Exact match must be returned.
    CHECK(v.find_by_name("My GitHub Account").has_value());
}
