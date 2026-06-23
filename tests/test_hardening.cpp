// Tests for the Windows-build hardening pass:
//   - save_vault writes atomically (temp file + rename) and leaves no leftovers
//   - save_vault round-trips through the filesystem
//   - save_vault overwrites an existing vault without corrupting it
//   - secure_clear wipes and empties a secret string

#include "pwman/crypto.hpp"
#include "pwman/vault.hpp"
#include "pwman/entry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>

namespace fs = std::filesystem;

namespace {

fs::path temp_vault_path(const char* stem) {
    // Unique-ish path inside the OS temp dir so tests don't collide.
    static int counter = 0;
    fs::path p = fs::temp_directory_path() /
                 (std::string("pwman_test_") + stem + "_" +
                  std::to_string(++counter) + ".vault");
    std::error_code ec;
    fs::remove(p, ec);
    fs::remove(fs::path(p.string() + ".tmp"), ec);
    return p;
}

pwman::Vault one_entry_vault(const std::string& name, const std::string& pw) {
    pwman::Vault v;
    pwman::Entry e;
    e.name     = name;
    e.password = pw;
    v.add(std::move(e));
    return v;
}

} // namespace

TEST_CASE("save_vault round-trips through the filesystem", "[hardening][io]") {
    const fs::path path = temp_vault_path("roundtrip");
    const pwman::Vault original = one_entry_vault("Example", "p@ss");

    pwman::save_vault(path.string(), original, "master");
    REQUIRE(fs::exists(path));

    const pwman::Vault loaded = pwman::load_vault(path.string(), "master");
    CHECK(original == loaded);

    std::error_code ec;
    fs::remove(path, ec);
}

TEST_CASE("save_vault leaves no .tmp file behind on success",
          "[hardening][atomic]") {
    const fs::path path = temp_vault_path("notmp");
    pwman::save_vault(path.string(),
                      one_entry_vault("A", "x"), "master");

    // The atomic-write implementation renames a sibling ".tmp" file into place;
    // after a successful save the temp file must not exist.
    const fs::path tmp = fs::path(path.string() + ".tmp");
    CHECK_FALSE(fs::exists(tmp));

    std::error_code ec;
    fs::remove(path, ec);
}

TEST_CASE("save_vault atomically overwrites an existing vault",
          "[hardening][atomic]") {
    const fs::path path = temp_vault_path("overwrite");

    // First save: one entry.
    pwman::save_vault(path.string(), one_entry_vault("First", "p1"), "master");
    REQUIRE(pwman::load_vault(path.string(), "master").entries().size() == 1);

    // Second save to the SAME path with different content must replace it
    // cleanly (rename over the existing file) and stay readable.
    pwman::Vault v2 = one_entry_vault("Second", "p2");
    v2.add([]{ pwman::Entry e; e.name = "Third"; e.password = "p3"; return e; }());
    pwman::save_vault(path.string(), v2, "master");

    const pwman::Vault reloaded = pwman::load_vault(path.string(), "master");
    REQUIRE(reloaded.entries().size() == 2);
    CHECK(reloaded.entries()[0].name == "Second");
    CHECK(reloaded.entries()[1].name == "Third");

    std::error_code ec;
    fs::remove(path, ec);
}

TEST_CASE("secure_clear wipes and empties a secret string",
          "[hardening][secret]") {
    std::string secret = "super-secret-master-password";
    pwman::secure_clear(secret);
    CHECK(secret.empty());

    // Clearing an already-empty string must be safe (no UB on &secret[0]).
    std::string empty;
    pwman::secure_clear(empty);
    CHECK(empty.empty());
}
