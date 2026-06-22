// pwman-cli — command-line front-end for pwman-core.
//
// Usage:
//   pwman-cli --vault <file> --password <pass> unlock
//   pwman-cli --vault <file> --password <pass> add --name <n> --username <u>
//             --url <url> --password-entry <p> [--notes <t>] [--tags t1,t2]
//   pwman-cli --vault <file> --password <pass> list
//   pwman-cli --vault <file> --password <pass> search <query>
//   pwman-cli --vault <file> --password <pass> remove <id>
//   pwman-cli totp --secret <base32-secret> [--digits 6] [--period 30] [--time <unix>]
//   pwman-cli generate [--length 20] [--no-symbols] [--no-digits] [--no-upper] [--no-lower]
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
    std::string              search_query;
    std::string              totp_secret;
    std::string              entry_name;
    std::string              entry_username;
    std::string              entry_url;
    std::string              entry_password;
    std::string              entry_notes;
    std::vector<std::string> entry_tags;
    uint64_t                 remove_id{0};
    uint32_t                 totp_digits{6};
    uint32_t                 totp_period{30};
    uint64_t                 totp_time{0};
    bool                     totp_time_set{false};
    uint32_t                 gen_length{20};
    bool                     gen_no_symbols{false};
    bool                     gen_no_digits{false};
    bool                     gen_no_upper{false};
    bool                     gen_no_lower{false};
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
        } else if (s == "--name") {
            a.entry_name = next_arg(argv, i, "--name");
        } else if (s == "--username") {
            a.entry_username = next_arg(argv, i, "--username");
        } else if (s == "--url") {
            a.entry_url = next_arg(argv, i, "--url");
        } else if (s == "--password-entry") {
            a.entry_password = next_arg(argv, i, "--password-entry");
        } else if (s == "--notes") {
            a.entry_notes = next_arg(argv, i, "--notes");
        } else if (s == "--tags") {
            a.entry_tags = split_csv(next_arg(argv, i, "--tags"));
        } else if (s == "--secret") {
            a.totp_secret = next_arg(argv, i, "--secret");
        } else if (s == "--digits") {
            a.totp_digits = static_cast<uint32_t>(
                std::stoul(next_arg(argv, i, "--digits")));
        } else if (s == "--period") {
            a.totp_period = static_cast<uint32_t>(
                std::stoul(next_arg(argv, i, "--period")));
        } else if (s == "--time") {
            a.totp_time = std::stoull(next_arg(argv, i, "--time"));
            a.totp_time_set = true;
        } else if (s == "--length") {
            a.gen_length = static_cast<uint32_t>(
                std::stoul(next_arg(argv, i, "--length")));
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
        } else if ((a.command == "search" || a.command == "remove") &&
                   a.search_query.empty() && s[0] != '-') {
            if (a.command == "remove") {
                a.remove_id = std::stoull(s);
            } else {
                a.search_query = s;
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
    bool existing = false;
    try {
        v = pwman::load_vault(a.vault_path, a.master_password);
        existing = true;
    } catch (const std::runtime_error&) {
        // File doesn't exist yet — create a new vault.
    }
    (void)existing;

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

static void print_entry(const pwman::Entry& e) {
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

static void cmd_list(const Args& a) {
    const pwman::Vault v = pwman::load_vault(a.vault_path, a.master_password);
    const auto& entries = v.entries();
    std::cout << entries.size() << " entries:\n";
    for (const auto& e : entries) {
        print_entry(e);
    }
}

static void cmd_search(const Args& a) {
    const pwman::Vault v = pwman::load_vault(a.vault_path, a.master_password);
    const auto results = v.search(a.search_query);
    std::cout << results.size() << " result(s) for \"" << a.search_query << "\":\n";
    for (const auto& e : results) {
        print_entry(e);
    }
}

static void cmd_remove(const Args& a) {
    pwman::Vault v = pwman::load_vault(a.vault_path, a.master_password);
    if (!v.remove(a.remove_id)) {
        std::cerr << "ERROR: no entry with id=" << a.remove_id << "\n";
        std::exit(1);
    }
    pwman::save_vault(a.vault_path, v, a.master_password);
    std::cout << "OK: removed entry id=" << a.remove_id << "\n";
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
    opts.length   = a.gen_length;
    opts.symbols  = !a.gen_no_symbols;
    opts.digits   = !a.gen_no_digits;
    opts.uppercase = !a.gen_no_upper;
    opts.lowercase = !a.gen_no_lower;
    std::cout << pwman::generate_password(opts) << "\n";
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
        } else if (a.command == "totp") {
            cmd_totp(a);
        } else if (a.command == "generate") {
            cmd_generate(a);
        } else {
            std::cerr << "Usage:\n"
                      << "  pwman-cli --vault <file> --password <pass> unlock\n"
                      << "  pwman-cli --vault <file> --password <pass> add"
                         " --name <n> --username <u> --url <url>"
                         " --password-entry <p> [--notes <t>] [--tags t1,t2]\n"
                      << "  pwman-cli --vault <file> --password <pass> list\n"
                      << "  pwman-cli --vault <file> --password <pass> search <query>\n"
                      << "  pwman-cli --vault <file> --password <pass> remove <id>\n"
                      << "  pwman-cli totp --secret <base32> [--digits 6]"
                         " [--period 30] [--time <unix>]\n"
                      << "  pwman-cli generate [--length 20] [--no-symbols]"
                         " [--no-digits] [--no-upper] [--no-lower]\n";
            return 1;
        }
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
