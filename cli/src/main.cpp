// pwman-cli — command-line front-end for pwman-core.
//
// Usage:
//   pwman-cli --vault <file> --password <pass> unlock
//   pwman-cli --vault <file> --password <pass> add --name <n> --username <u>
//             --url <url> --password-entry <p> [--notes <t>] [--tags t1,t2]
//   pwman-cli --vault <file> --password <pass> list
//   pwman-cli --vault <file> --password <pass> get <id>
//   pwman-cli --vault <file> --password <pass> search <query>
//   pwman-cli --vault <file> --password <pass> remove <id>
//   pwman-cli --vault <file> --password <pass> remove-by-name <name>
//   pwman-cli --vault <file> --password <pass> update <id>
//             [--name <n>] [--username <u>] [--url <url>]
//             [--password-entry <p>] [--notes <t>] [--tags t1,t2]
//   pwman-cli --vault <file> --password <pass> change-password --new-password <p>
//   pwman-cli --vault <file> --password <pass> export --out <file> --export-password <p>
//   pwman-cli import --in <file> --export-password <p> --vault <out> --password <p>
//   pwman-cli totp --secret <base32-secret> [--digits 6] [--period 30] [--time <unix>]
//   pwman-cli generate [--length 20] [--no-symbols] [--no-digits] [--no-upper] [--no-lower]
//   pwman-cli strength <password>
//
// All flags are parsed from argv so CI scripts can run non-interactively.
// Passwords can also be read from stdin by setting --password - (a single dash).

#include "pwman/crypto.hpp"
#include "pwman/generator.hpp"
#include "pwman/totp.hpp"
#include "pwman/vault.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal argument parser
// ---------------------------------------------------------------------------
struct Args {
    std::string              command;
    std::string              vault_path;
    std::string              master_password;
    std::string              new_password;
    std::string              export_password;
    std::string              import_path;   // --in
    std::string              export_path;   // --out
    std::string              search_query;
    std::string              name_query;    // for remove-by-name / update
    std::string              totp_secret;
    std::string              entry_name;
    std::string              entry_username;
    std::string              entry_url;
    std::string              entry_password;
    std::string              entry_notes;
    std::string              strength_input;
    std::vector<std::string> entry_tags;
    uint64_t                 target_id{0};  // for get / remove / update
    uint32_t                 totp_digits{6};
    uint32_t                 totp_period{30};
    uint64_t                 totp_time{0};
    bool                     totp_time_set{false};
    uint32_t                 gen_length{20};
    bool                     gen_no_symbols{false};
    bool                     gen_no_digits{false};
    bool                     gen_no_upper{false};
    bool                     gen_no_lower{false};
    // Update flags: only update fields that were explicitly supplied.
    bool                     update_name{false};
    bool                     update_username{false};
    bool                     update_url{false};
    bool                     update_password{false};
    bool                     update_notes{false};
    bool                     update_tags{false};
};

static std::string next_arg(const std::vector<std::string>& argv, size_t& i,
                             const char* flag_name) {
    if (i + 1 >= argv.size()) {
        throw std::runtime_error(std::string("flag ") + flag_name +
                                 " requires an argument");
    }
    return argv[++i];
}

static std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream ss(s);
    std::string tok;
    while (std::getline(ss, tok, ',')) {
        if (!tok.empty()) out.push_back(tok);
    }
    return out;
}

// Safe integer parsing — converts std::stoul/stoull exceptions into a user-
// friendly error message with the offending value included.
static uint64_t parse_id(const std::string& s, const char* context) {
    try {
        return std::stoull(s);
    } catch (const std::exception&) {
        throw std::runtime_error(std::string(context) +
                                 ": expected a numeric id, got: " + s);
    }
}

static uint32_t parse_u32(const std::string& s, const char* flag_name) {
    try {
        const unsigned long v = std::stoul(s);
        if (v > 0xFFFFFFFFUL) throw std::out_of_range("overflow");
        return static_cast<uint32_t>(v);
    } catch (const std::exception&) {
        throw std::runtime_error(std::string(flag_name) +
                                 ": expected a positive integer, got: " + s);
    }
}

Args parse(int argc, char** argv_raw) {
    std::vector<std::string> argv(argv_raw, argv_raw + argc);
    Args a;

    for (size_t i = 1; i < argv.size(); ++i) {
        const std::string& s = argv[i];
        if (s == "--vault") {
            a.vault_path = next_arg(argv, i, "--vault");
        } else if (s == "--password") {
            a.master_password = next_arg(argv, i, "--password");
            if (a.master_password == "-") {
                // Read from stdin (no echo — caller sets up terminal if needed).
                std::getline(std::cin, a.master_password);
            }
        } else if (s == "--new-password") {
            a.new_password = next_arg(argv, i, "--new-password");
        } else if (s == "--export-password") {
            a.export_password = next_arg(argv, i, "--export-password");
        } else if (s == "--out") {
            a.export_path = next_arg(argv, i, "--out");
        } else if (s == "--in") {
            a.import_path = next_arg(argv, i, "--in");
        } else if (s == "--name") {
            a.entry_name = next_arg(argv, i, "--name");
            a.update_name = true;
        } else if (s == "--username") {
            a.entry_username = next_arg(argv, i, "--username");
            a.update_username = true;
        } else if (s == "--url") {
            a.entry_url = next_arg(argv, i, "--url");
            a.update_url = true;
        } else if (s == "--password-entry") {
            a.entry_password = next_arg(argv, i, "--password-entry");
            a.update_password = true;
        } else if (s == "--notes") {
            a.entry_notes = next_arg(argv, i, "--notes");
            a.update_notes = true;
        } else if (s == "--tags") {
            a.entry_tags = split_csv(next_arg(argv, i, "--tags"));
            a.update_tags = true;
        } else if (s == "--secret") {
            a.totp_secret = next_arg(argv, i, "--secret");
        } else if (s == "--digits") {
            a.totp_digits = parse_u32(next_arg(argv, i, "--digits"), "--digits");
        } else if (s == "--period") {
            a.totp_period = parse_u32(next_arg(argv, i, "--period"), "--period");
        } else if (s == "--time") {
            try {
                a.totp_time = std::stoull(next_arg(argv, i, "--time"));
            } catch (const std::exception&) {
                throw std::runtime_error("--time: expected a unix timestamp");
            }
            a.totp_time_set = true;
        } else if (s == "--length") {
            a.gen_length = parse_u32(next_arg(argv, i, "--length"), "--length");
        } else if (s == "--no-symbols") {
            a.gen_no_symbols = true;
        } else if (s == "--no-digits") {
            a.gen_no_digits = true;
        } else if (s == "--no-upper") {
            a.gen_no_upper = true;
        } else if (s == "--no-lower") {
            a.gen_no_lower = true;
        } else if (a.command.empty() && s[0] != '-') {
            a.command = s;
        } else if (!a.command.empty() && s[0] != '-') {
            // Positional argument after a command.
            if (a.command == "search") {
                if (a.search_query.empty()) a.search_query = s;
            } else if (a.command == "remove") {
                if (a.target_id == 0) a.target_id = parse_id(s, "remove");
            } else if (a.command == "get") {
                if (a.target_id == 0) a.target_id = parse_id(s, "get");
            } else if (a.command == "update") {
                if (a.target_id == 0) a.target_id = parse_id(s, "update");
            } else if (a.command == "remove-by-name") {
                if (a.name_query.empty()) a.name_query = s;
            } else if (a.command == "strength") {
                if (a.strength_input.empty()) a.strength_input = s;
            }
        }
    }
    return a;
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------
static void cmd_unlock(const Args& a) {
    try {
        const pwman::Vault v = pwman::load_vault(a.vault_path, a.master_password);
        std::cout << "OK: vault unlocked, " << v.entries().size()
                  << " entries.\n";
    } catch (const pwman::DecryptionError& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        std::exit(1);
    }
}

static void cmd_add(const Args& a) {
    pwman::Vault v;
    try {
        v = pwman::load_vault(a.vault_path, a.master_password);
    } catch (const std::runtime_error&) {
        // File doesn't exist yet — create a new vault.
    }

    pwman::Entry e;
    e.name     = a.entry_name;
    e.username = a.entry_username;
    e.url      = a.entry_url;
    e.password = a.entry_password;
    e.notes    = a.entry_notes;
    e.tags     = a.entry_tags;

    const uint64_t id = v.add(std::move(e));
    pwman::save_vault(a.vault_path, v, a.master_password);
    std::cout << "OK: added entry id=" << id << "\n";
}

static void print_entry_short(const pwman::Entry& e) {
    std::cout << "[" << e.id << "] " << e.name;
    if (!e.username.empty()) std::cout << "  user=" << e.username;
    if (!e.url.empty())      std::cout << "  url=" << e.url;
    if (!e.tags.empty()) {
        std::cout << "  tags=";
        for (size_t i = 0; i < e.tags.size(); ++i) {
            if (i) std::cout << ",";
            std::cout << e.tags[i];
        }
    }
    std::cout << "\n";
}

static void print_entry_full(const pwman::Entry& e) {
    std::cout << "id:       " << e.id       << "\n"
              << "name:     " << e.name     << "\n"
              << "username: " << e.username << "\n"
              << "url:      " << e.url      << "\n"
              << "password: " << e.password << "\n"
              << "notes:    " << e.notes    << "\n"
              << "tags:     ";
    for (size_t i = 0; i < e.tags.size(); ++i) {
        if (i) std::cout << ",";
        std::cout << e.tags[i];
    }
    std::cout << "\n";
}

static void cmd_list(const Args& a) {
    const pwman::Vault v = pwman::load_vault(a.vault_path, a.master_password);
    const auto& entries = v.entries();
    std::cout << entries.size() << " entries:\n";
    for (const auto& e : entries) {
        print_entry_short(e);
    }
}

static void cmd_get(const Args& a) {
    if (a.target_id == 0) {
        std::cerr << "ERROR: get requires a numeric <id> argument\n";
        std::exit(1);
    }
    const pwman::Vault v = pwman::load_vault(a.vault_path, a.master_password);
    const auto entry = v.find(a.target_id);
    if (!entry) {
        std::cerr << "ERROR: no entry with id=" << a.target_id << "\n";
        std::exit(1);
    }
    print_entry_full(*entry);
}

static void cmd_search(const Args& a) {
    const pwman::Vault v = pwman::load_vault(a.vault_path, a.master_password);
    const auto results = v.search(a.search_query);
    std::cout << results.size() << " result(s) for \"" << a.search_query << "\":\n";
    for (const auto& e : results) {
        print_entry_short(e);
    }
}

static void cmd_remove(const Args& a) {
    if (a.target_id == 0) {
        std::cerr << "ERROR: remove requires a numeric <id> argument\n";
        std::exit(1);
    }
    pwman::Vault v = pwman::load_vault(a.vault_path, a.master_password);
    if (!v.remove(a.target_id)) {
        std::cerr << "ERROR: no entry with id=" << a.target_id << "\n";
        std::exit(1);
    }
    pwman::save_vault(a.vault_path, v, a.master_password);
    std::cout << "OK: removed entry id=" << a.target_id << "\n";
}

static void cmd_remove_by_name(const Args& a) {
    if (a.name_query.empty()) {
        std::cerr << "ERROR: remove-by-name requires a <name> argument\n";
        std::exit(1);
    }
    pwman::Vault v = pwman::load_vault(a.vault_path, a.master_password);
    const auto entry = v.find_by_name(a.name_query);
    if (!entry) {
        std::cerr << "ERROR: no entry with name=\"" << a.name_query << "\"\n";
        std::exit(1);
    }
    const uint64_t id = entry->id;
    v.remove(id);
    pwman::save_vault(a.vault_path, v, a.master_password);
    std::cout << "OK: removed entry id=" << id
              << " name=\"" << a.name_query << "\"\n";
}

static void cmd_update(const Args& a) {
    if (a.target_id == 0) {
        std::cerr << "ERROR: update requires a numeric <id> argument\n";
        std::exit(1);
    }
    pwman::Vault v = pwman::load_vault(a.vault_path, a.master_password);
    const auto existing = v.find(a.target_id);
    if (!existing) {
        std::cerr << "ERROR: no entry with id=" << a.target_id << "\n";
        std::exit(1);
    }

    // Build updated entry from existing, applying only supplied flags.
    pwman::Entry updated = *existing;
    if (a.update_name)     updated.name     = a.entry_name;
    if (a.update_username) updated.username = a.entry_username;
    if (a.update_url)      updated.url      = a.entry_url;
    if (a.update_password) updated.password = a.entry_password;
    if (a.update_notes)    updated.notes    = a.entry_notes;
    if (a.update_tags)     updated.tags     = a.entry_tags;

    v.update(a.target_id, updated);
    pwman::save_vault(a.vault_path, v, a.master_password);
    std::cout << "OK: updated entry id=" << a.target_id << "\n";
}

static void cmd_change_password(const Args& a) {
    if (a.new_password.empty()) {
        std::cerr << "ERROR: change-password requires --new-password\n";
        std::exit(1);
    }
    try {
        pwman::change_password(a.vault_path, a.master_password, a.new_password);
        std::cout << "OK: master password changed.\n";
    } catch (const pwman::DecryptionError& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        std::exit(1);
    }
}

static void cmd_export(const Args& a) {
    if (a.export_path.empty()) {
        std::cerr << "ERROR: export requires --out <file>\n";
        std::exit(1);
    }
    if (a.export_password.empty()) {
        std::cerr << "ERROR: export requires --export-password\n";
        std::exit(1);
    }
    const pwman::Vault v = pwman::load_vault(a.vault_path, a.master_password);
    const std::vector<uint8_t> bundle = pwman::export_vault(v, a.export_password);
    std::ofstream ofs(a.export_path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        throw std::runtime_error("cannot open export file: " + a.export_path);
    }
    ofs.write(reinterpret_cast<const char*>(bundle.data()),
              static_cast<std::streamsize>(bundle.size()));
    if (!ofs) {
        throw std::runtime_error("write error: " + a.export_path);
    }
    std::cout << "OK: exported " << v.entries().size()
              << " entries to " << a.export_path << "\n";
}

static void cmd_import(const Args& a) {
    if (a.import_path.empty()) {
        std::cerr << "ERROR: import requires --in <file>\n";
        std::exit(1);
    }
    if (a.export_password.empty()) {
        std::cerr << "ERROR: import requires --export-password\n";
        std::exit(1);
    }
    if (a.vault_path.empty() || a.master_password.empty()) {
        std::cerr << "ERROR: import requires --vault and --password (output vault)\n";
        std::exit(1);
    }

    std::ifstream ifs(a.import_path, std::ios::binary);
    if (!ifs) {
        throw std::runtime_error("cannot open import file: " + a.import_path);
    }
    const std::vector<uint8_t> bundle(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>());

    const pwman::Vault imported = pwman::import_vault(bundle, a.export_password);
    pwman::save_vault(a.vault_path, imported, a.master_password);
    std::cout << "OK: imported " << imported.entries().size()
              << " entries to " << a.vault_path << "\n";
}

static void cmd_totp(const Args& a) {
    if (a.totp_secret.empty()) {
        std::cerr << "ERROR: --secret is required\n";
        std::exit(1);
    }
    const std::vector<uint8_t> key = pwman::base32_decode(a.totp_secret);
    const uint64_t t = a.totp_time_set
        ? a.totp_time
        : static_cast<uint64_t>(
              std::chrono::duration_cast<std::chrono::seconds>(
                  std::chrono::system_clock::now().time_since_epoch())
              .count());
    const std::string code = pwman::totp_string(key, t, a.totp_digits, a.totp_period);
    std::cout << code << "\n";
}

static void cmd_generate(const Args& a) {
    pwman::GeneratorOptions opts;
    opts.length    = a.gen_length;
    opts.symbols   = !a.gen_no_symbols;
    opts.digits    = !a.gen_no_digits;
    opts.uppercase = !a.gen_no_upper;
    opts.lowercase = !a.gen_no_lower;
    const std::string pw = pwman::generate_password(opts);
    const pwman::StrengthResult sr = pwman::estimate_strength(pw);
    std::cout << pw << "\n";
    std::cout << "strength: " << sr.label()
              << " (" << static_cast<int>(sr.entropy_bits) << " bits)\n";
}

static void cmd_strength(const Args& a) {
    if (a.strength_input.empty()) {
        std::cerr << "ERROR: strength requires a <password> argument\n";
        std::exit(1);
    }
    const pwman::StrengthResult sr = pwman::estimate_strength(a.strength_input);
    std::cout << sr.label()
              << " (" << static_cast<int>(sr.entropy_bits) << " bits)\n";
}

// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    try {
        const Args a = parse(argc, argv);

        if (a.command == "unlock") {
            if (a.vault_path.empty() || a.master_password.empty()) {
                std::cerr << "ERROR: unlock requires --vault and --password\n";
                return 1;
            }
            cmd_unlock(a);
        } else if (a.command == "add") {
            if (a.vault_path.empty() || a.master_password.empty()) {
                std::cerr << "ERROR: add requires --vault and --password\n";
                return 1;
            }
            cmd_add(a);
        } else if (a.command == "list") {
            if (a.vault_path.empty() || a.master_password.empty()) {
                std::cerr << "ERROR: list requires --vault and --password\n";
                return 1;
            }
            cmd_list(a);
        } else if (a.command == "get") {
            if (a.vault_path.empty() || a.master_password.empty()) {
                std::cerr << "ERROR: get requires --vault and --password\n";
                return 1;
            }
            cmd_get(a);
        } else if (a.command == "search") {
            if (a.vault_path.empty() || a.master_password.empty()) {
                std::cerr << "ERROR: search requires --vault and --password\n";
                return 1;
            }
            cmd_search(a);
        } else if (a.command == "remove") {
            if (a.vault_path.empty() || a.master_password.empty()) {
                std::cerr << "ERROR: remove requires --vault and --password\n";
                return 1;
            }
            cmd_remove(a);
        } else if (a.command == "remove-by-name") {
            if (a.vault_path.empty() || a.master_password.empty()) {
                std::cerr << "ERROR: remove-by-name requires --vault and --password\n";
                return 1;
            }
            cmd_remove_by_name(a);
        } else if (a.command == "update") {
            if (a.vault_path.empty() || a.master_password.empty()) {
                std::cerr << "ERROR: update requires --vault and --password\n";
                return 1;
            }
            cmd_update(a);
        } else if (a.command == "change-password") {
            if (a.vault_path.empty() || a.master_password.empty()) {
                std::cerr << "ERROR: change-password requires --vault and --password\n";
                return 1;
            }
            cmd_change_password(a);
        } else if (a.command == "export") {
            if (a.vault_path.empty() || a.master_password.empty()) {
                std::cerr << "ERROR: export requires --vault and --password\n";
                return 1;
            }
            cmd_export(a);
        } else if (a.command == "import") {
            cmd_import(a);
        } else if (a.command == "totp") {
            cmd_totp(a);
        } else if (a.command == "generate") {
            cmd_generate(a);
        } else if (a.command == "strength") {
            cmd_strength(a);
        } else {
            std::cerr <<
                "Usage:\n"
                "  pwman-cli --vault <file> --password <pass> unlock\n"
                "  pwman-cli --vault <file> --password <pass> add"
                " --name <n> --username <u> --url <url>"
                " --password-entry <p> [--notes <t>] [--tags t1,t2]\n"
                "  pwman-cli --vault <file> --password <pass> list\n"
                "  pwman-cli --vault <file> --password <pass> get <id>\n"
                "  pwman-cli --vault <file> --password <pass> search <query>\n"
                "  pwman-cli --vault <file> --password <pass> remove <id>\n"
                "  pwman-cli --vault <file> --password <pass> remove-by-name <name>\n"
                "  pwman-cli --vault <file> --password <pass> update <id>"
                " [--name <n>] [--username <u>] [--url <url>]"
                " [--password-entry <p>] [--notes <t>] [--tags t1,t2]\n"
                "  pwman-cli --vault <file> --password <pass>"
                " change-password --new-password <p>\n"
                "  pwman-cli --vault <file> --password <pass>"
                " export --out <file> --export-password <p>\n"
                "  pwman-cli import --in <file> --export-password <p>"
                " --vault <out> --password <p>\n"
                "  pwman-cli totp --secret <base32> [--digits 6]"
                " [--period 30] [--time <unix>]\n"
                "  pwman-cli generate [--length 20] [--no-symbols]"
                " [--no-digits] [--no-upper] [--no-lower]\n"
                "  pwman-cli strength <password>\n";
            return 1;
        }
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
