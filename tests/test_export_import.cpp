// Tests for export_vault / import_vault and change_password.

#include "pwman/crypto.hpp"
#include "pwman/vault.hpp"
#include "pwman/entry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static pwman::Vault make_test_vault() {
    pwman::Vault v;

    pwman::Entry e1;
    e1.name     = "Service A";
    e1.username = "user@example.com";
    e1.url      = "https://a.example.com";
    e1.password = "secretA!";
    e1.notes    = "primary account";
    e1.tags     = {"work"};
    v.add(std::move(e1));

    pwman::Entry e2;
    e2.name     = "Service B";
    e2.username = "bob";
    e2.url      = "https://b.example.com";
    e2.password = "secretB@";
    e2.tags     = {"personal", "cloud"};
    v.add(std::move(e2));

    return v;
}

// ---------------------------------------------------------------------------
// export_vault / import_vault round-trip
// ---------------------------------------------------------------------------
TEST_CASE("export then import round-trips all entries", "[export_import]") {
    const pwman::Vault original = make_test_vault();
    const std::string  exp_pass = "export-secret-42";

    const std::vector<uint8_t> bundle = pwman::export_vault(original, exp_pass);
    const pwman::Vault restored = pwman::import_vault(bundle, exp_pass);

    CHECK(original == restored);
}

TEST_CASE("import with wrong export password throws DecryptionError",
          "[export_import]") {
    const pwman::Vault v = make_test_vault();
    const std::vector<uint8_t> bundle = pwman::export_vault(v, "correct-exp-pass");

    CHECK_THROWS_AS(pwman::import_vault(bundle, "wrong-exp-pass"),
                    pwman::DecryptionError);
}

TEST_CASE("export of empty vault round-trips correctly", "[export_import]") {
    const pwman::Vault empty;
    const std::vector<uint8_t> bundle = pwman::export_vault(empty, "pass");
    const pwman::Vault restored = pwman::import_vault(bundle, "pass");
    CHECK(restored.entries().empty());
}

TEST_CASE("two exports of same vault produce different bytes (random nonce/salt)",
          "[export_import]") {
    const pwman::Vault v = make_test_vault();
    const auto b1 = pwman::export_vault(v, "pass");
    const auto b2 = pwman::export_vault(v, "pass");
    CHECK(b1 != b2);
}

TEST_CASE("export can use different password from vault master password",
          "[export_import]") {
    // Encrypted under master; exported under a separate export password.
    const pwman::Vault v = make_test_vault();
    const std::string master = "master-pw";
    const std::string exp_pw = "export-pw";

    // They must be different for this test to be meaningful.
    REQUIRE(master != exp_pw);

    const std::vector<uint8_t> bundle = pwman::export_vault(v, exp_pw);

    // Must open with exp_pw.
    const pwman::Vault imported = pwman::import_vault(bundle, exp_pw);
    CHECK(v == imported);

    // Must NOT open with master.
    CHECK_THROWS_AS(pwman::import_vault(bundle, master), pwman::DecryptionError);
}

// ---------------------------------------------------------------------------
// change_password
// ---------------------------------------------------------------------------
TEST_CASE("change_password re-encrypts vault under new master password",
          "[change_password]") {
    // We use encrypt_vault/decrypt_vault directly (no file I/O) to keep tests
    // self-contained, but we need to test change_password which requires a file.
    // We create a temp file path and use save_vault / load_vault.
    const pwman::Vault original = make_test_vault();
    const std::string old_pw = "old-master";
    const std::string new_pw = "new-master";

    // Write to a temp path.
    const std::string tmp = "test_change_pw_tmp.vault";
    pwman::save_vault(tmp, original, old_pw);

    // Change the password.
    pwman::change_password(tmp, old_pw, new_pw);

    // Must open with new password.
    const pwman::Vault reloaded = pwman::load_vault(tmp, new_pw);
    CHECK(original == reloaded);

    // Must NOT open with old password.
    CHECK_THROWS_AS(pwman::load_vault(tmp, old_pw), pwman::DecryptionError);
}

TEST_CASE("change_password with wrong old password throws DecryptionError",
          "[change_password]") {
    const pwman::Vault v = make_test_vault();
    const std::string tmp = "test_change_pw_wrong_tmp.vault";
    pwman::save_vault(tmp, v, "real-password");

    CHECK_THROWS_AS(pwman::change_password(tmp, "wrong-password", "new-pw"),
                    pwman::DecryptionError);
}
