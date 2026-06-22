// Crypto round-trip tests and format validation.

#include "pwman/crypto.hpp"
#include "pwman/vault.hpp"
#include "pwman/entry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

static pwman::Vault make_test_vault() {
    pwman::Vault v;

    pwman::Entry e1;
    e1.name     = "GitHub";
    e1.username = "alice@example.com";
    e1.url      = "https://github.com";
    e1.password = "s3cr3t!";
    e1.notes    = "main account";
    e1.tags     = {"work", "dev"};
    v.add(std::move(e1));

    pwman::Entry e2;
    e2.name     = "GitLab";
    e2.username = "alice";
    e2.url      = "https://gitlab.com";
    e2.password = "p@ssw0rd";
    e2.tags     = {"dev"};
    v.add(std::move(e2));

    return v;
}

TEST_CASE("Vault serialise → deserialise round-trip", "[crypto][serialise]") {
    const pwman::Vault original = make_test_vault();
    const std::vector<uint8_t> bytes = pwman::serialize(original);
    const pwman::Vault restored = pwman::deserialize(bytes);
    CHECK(original == restored);
}

TEST_CASE("Serialise empty vault", "[crypto][serialise]") {
    const pwman::Vault empty;
    const std::vector<uint8_t> bytes = pwman::serialize(empty);
    const pwman::Vault restored = pwman::deserialize(bytes);
    CHECK(restored.entries().empty());
}

TEST_CASE("Serialise entry with empty optional fields", "[crypto][serialise]") {
    pwman::Vault v;
    pwman::Entry e;
    e.name     = "BareMinimum";
    e.password = "pw";
    v.add(std::move(e));

    const auto restored = pwman::deserialize(pwman::serialize(v));
    REQUIRE(restored.entries().size() == 1);
    CHECK(restored.entries()[0].name     == "BareMinimum");
    CHECK(restored.entries()[0].username == "");
    CHECK(restored.entries()[0].url      == "");
    CHECK(restored.entries()[0].notes    == "");
    CHECK(restored.entries()[0].tags.empty());
}

TEST_CASE("Encrypt → decrypt with correct password", "[crypto][encryption]") {
    const pwman::Vault original = make_test_vault();
    const std::string  password = "master-password-42";

    const std::vector<uint8_t> cipher = pwman::encrypt_vault(original, password);
    const pwman::Vault restored = pwman::decrypt_vault(cipher, password);

    CHECK(original == restored);
}

TEST_CASE("Decrypt with wrong password throws DecryptionError", "[crypto][encryption]") {
    const pwman::Vault original = make_test_vault();
    const std::vector<uint8_t> cipher = pwman::encrypt_vault(original, "correct");
    CHECK_THROWS_AS(pwman::decrypt_vault(cipher, "wrong"), pwman::DecryptionError);
}

TEST_CASE("Decrypt truncated data throws FormatError", "[crypto][encryption]") {
    // Too short to be valid.
    const std::vector<uint8_t> garbage(10, 0xAB);
    CHECK_THROWS_AS(pwman::decrypt_vault(garbage, "any"), pwman::FormatError);
}

TEST_CASE("Encrypt produces different ciphertext each call (random salt+nonce)",
          "[crypto][encryption]") {
    pwman::Vault v;
    pwman::Entry e;
    e.name = "test";
    e.password = "pw";
    v.add(std::move(e));

    const auto c1 = pwman::encrypt_vault(v, "pass");
    const auto c2 = pwman::encrypt_vault(v, "pass");
    // Salt and nonce are random — outputs must differ.
    CHECK(c1 != c2);
}
