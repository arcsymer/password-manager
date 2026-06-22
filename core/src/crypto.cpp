#include "pwman/crypto.hpp"

#include <sodium.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace pwman {

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------
// Delimiters (chosen from ASCII control-character range, never valid in UTF-8
// user data in practice, and cleanly distinguishable from each other).
static constexpr uint8_t kFieldSep  = 0x1F; // Unit Separator
static constexpr uint8_t kTagSep    = 0x1E; // Record Separator
static constexpr uint8_t kEntrySep  = 0x1D; // Group Separator
static constexpr uint8_t kMagic[]   = {'P','W','M','V','1','\x00','\x00','\x00'};
static constexpr size_t  kMagicLen  = sizeof(kMagic);

namespace {

void write_u32le(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v       & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >>16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >>24) & 0xFF));
}

uint32_t read_u32le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) <<  8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

void append_field(std::vector<uint8_t>& buf, const std::string& s) {
    buf.push_back(kFieldSep);
    buf.insert(buf.end(), s.begin(), s.end());
}

// Read bytes up to the next sentinel (sentinel is consumed but not included).
// Returns false if eof is hit before sentinel when mandatory=true.
std::string read_until(const uint8_t* data, size_t len, size_t& pos,
                       uint8_t sentinel) {
    std::string out;
    while (pos < len && data[pos] != sentinel) {
        out.push_back(static_cast<char>(data[pos++]));
    }
    if (pos < len) ++pos; // consume sentinel
    return out;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
std::vector<uint8_t> serialize(const Vault& vault) {
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), kMagic, kMagic + kMagicLen);

    const auto& entries = vault.entries();
    write_u32le(buf, static_cast<uint32_t>(entries.size()));

    for (const Entry& e : entries) {
        // id as decimal string
        append_field(buf, std::to_string(e.id));
        append_field(buf, e.name);
        append_field(buf, e.username);
        append_field(buf, e.url);
        append_field(buf, e.password);
        append_field(buf, e.notes);

        // Tags: join with kTagSep
        std::string tags_blob;
        for (size_t i = 0; i < e.tags.size(); ++i) {
            if (i) tags_blob.push_back(static_cast<char>(kTagSep));
            tags_blob += e.tags[i];
        }
        append_field(buf, tags_blob);

        buf.push_back(kEntrySep);
    }
    return buf;
}

Vault deserialize(const std::vector<uint8_t>& data) {
    const size_t sz = data.size();
    size_t pos = 0;

    // Magic
    if (sz < kMagicLen || std::memcmp(data.data(), kMagic, kMagicLen) != 0) {
        throw FormatError("invalid vault magic");
    }
    pos = kMagicLen;

    // Entry count
    if (sz - pos < 4) {
        throw FormatError("truncated vault header");
    }
    const uint32_t count = read_u32le(data.data() + pos);
    pos += 4;

    Vault vault;
    for (uint32_t i = 0; i < count; ++i) {
        Entry e;

        // Each field starts with kFieldSep then content up to next kFieldSep
        // or kEntrySep.  We parse each field with read_until(kFieldSep), except
        // for the last field (tags) which ends with kEntrySep.

        auto expect_field_sep = [&]() {
            if (pos >= sz || data[pos] != kFieldSep) {
                throw FormatError("expected field separator in entry");
            }
            ++pos;
        };

        auto next_field = [&](uint8_t end_sentinel) -> std::string {
            return read_until(data.data(), sz, pos, end_sentinel);
        };

        expect_field_sep();
        std::string id_str = next_field(kFieldSep);
        e.id = std::stoull(id_str);

        e.name     = next_field(kFieldSep);
        e.username = next_field(kFieldSep);
        e.url      = next_field(kFieldSep);
        e.password = next_field(kFieldSep);
        e.notes    = next_field(kFieldSep);

        // Tags field ends with kEntrySep
        std::string tags_blob = next_field(kEntrySep);
        if (!tags_blob.empty()) {
            // Split on kTagSep
            size_t tag_start = 0;
            for (size_t j = 0; j <= tags_blob.size(); ++j) {
                if (j == tags_blob.size() ||
                    static_cast<uint8_t>(tags_blob[j]) == kTagSep) {
                    e.tags.push_back(tags_blob.substr(tag_start, j - tag_start));
                    tag_start = j + 1;
                }
            }
        }

        // Restore entry with its original id; vault.restore() keeps next_id_ consistent.
        vault.restore(std::move(e));
    }
    return vault;
}

// ---------------------------------------------------------------------------
// Encryption / decryption
// ---------------------------------------------------------------------------
static void sodium_init_once() {
    static bool done = false;
    if (!done) {
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium initialisation failed");
        }
        done = true;
    }
}

std::vector<uint8_t> encrypt_vault(const Vault& vault,
                                   const std::string& master_password) {
    sodium_init_once();

    const std::vector<uint8_t> plaintext = serialize(vault);

    // Generate random salt and nonce.
    uint8_t salt [crypto_pwhash_SALTBYTES];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(salt,  sizeof(salt));
    randombytes_buf(nonce, sizeof(nonce));

    // Derive 256-bit key from master password + salt via Argon2id.
    uint8_t key[crypto_secretbox_KEYBYTES];
    if (crypto_pwhash(key, sizeof(key),
                      master_password.c_str(),
                      master_password.size(),
                      salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("KDF failed (out of memory?)");
    }

    // Encrypt plaintext.
    const size_t ciphertext_len = plaintext.size() + crypto_secretbox_MACBYTES;
    std::vector<uint8_t> ciphertext(ciphertext_len);
    crypto_secretbox_easy(ciphertext.data(),
                          plaintext.data(), plaintext.size(),
                          nonce, key);

    // Wipe key from memory.
    sodium_memzero(key, sizeof(key));

    // Layout: [salt][nonce][ciphertext]
    std::vector<uint8_t> file_bytes;
    file_bytes.reserve(sizeof(salt) + sizeof(nonce) + ciphertext_len);
    file_bytes.insert(file_bytes.end(), salt,  salt  + sizeof(salt));
    file_bytes.insert(file_bytes.end(), nonce, nonce + sizeof(nonce));
    file_bytes.insert(file_bytes.end(), ciphertext.begin(), ciphertext.end());
    return file_bytes;
}

Vault decrypt_vault(const std::vector<uint8_t>& file_bytes,
                    const std::string& master_password) {
    sodium_init_once();

    constexpr size_t kHeaderLen =
        crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES;

    if (file_bytes.size() <= kHeaderLen + crypto_secretbox_MACBYTES) {
        throw FormatError("file too short to be a valid vault");
    }

    const uint8_t* salt  = file_bytes.data();
    const uint8_t* nonce = file_bytes.data() + crypto_pwhash_SALTBYTES;
    const uint8_t* ct    = file_bytes.data() + kHeaderLen;
    const size_t   ct_len = file_bytes.size() - kHeaderLen;

    // Derive key.
    uint8_t key[crypto_secretbox_KEYBYTES];
    if (crypto_pwhash(key, sizeof(key),
                      master_password.c_str(),
                      master_password.size(),
                      salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("KDF failed (out of memory?)");
    }

    // Decrypt.
    const size_t pt_len = ct_len - crypto_secretbox_MACBYTES;
    std::vector<uint8_t> plaintext(pt_len);
    const int rc = crypto_secretbox_open_easy(plaintext.data(),
                                              ct, ct_len,
                                              nonce, key);
    sodium_memzero(key, sizeof(key));

    if (rc != 0) {
        throw DecryptionError("decryption failed: wrong password or corrupt data");
    }

    return deserialize(plaintext);
}

void save_vault(const std::string& path, const Vault& vault,
                const std::string& master_password) {
    const std::vector<uint8_t> bytes = encrypt_vault(vault, master_password);
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        throw std::runtime_error("cannot open file for writing: " + path);
    }
    ofs.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    if (!ofs) {
        throw std::runtime_error("write error: " + path);
    }
}

Vault load_vault(const std::string& path, const std::string& master_password) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        throw std::runtime_error("cannot open file: " + path);
    }
    std::vector<uint8_t> bytes(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>()
    );
    return decrypt_vault(bytes, master_password);
}

} // namespace pwman
