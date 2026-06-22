# Improvement Plan — pwman password manager

## Current state (baseline)

- C++17, CMake + Ninja, libsodium 1.0.22, Catch2 v3.5.4 via FetchContent.
- 28 tests, 100% green: vault CRUD, serialise round-trip, encrypt/decrypt,
  Base32 RFC 4648, TOTP RFC 6238 (SHA-256 vectors).
- CLI commands: `unlock`, `add`, `list`, `search`, `remove`, `totp`, `generate`.
- `--password -` reads master password from stdin.
- No custom crypto — all primitives from libsodium.

---

## Gaps identified by rubric

| # | Gap | Risk / Value |
|---|-----|--------------|
| G1 | No `get` / `show` command — cannot retrieve a single entry by id | Medium value, zero risk |
| G2 | No `update` command — fields can only be changed by delete+re-add | Medium value, zero risk |
| G3 | No `remove-by-name` / `delete-by-name` — must know numeric id | Low value, easy to add |
| G4 | No `change-password` command — re-encrypts vault under a new master password | High value, zero risk |
| G5 | No password-strength estimate | Medium value (portfolio), testable |
| G6 | No export / import to a portable encrypted bundle | Medium value |
| G7 | Input hardening: `std::stoul` / `std::stoull` on untrusted CLI args throws ugly std::exception; `--password -` leaves master password in a stack `std::string` with no `sodium_memzero` wipe | Medium risk |
| G8 | README security section is thin: no threat model, no "what is NOT protected" | Low code risk, high rubric value |
| G9 | Vault file format described only as comments/text; no visual diagram | Low risk, high readability |
| G10 | `Vault` has no `update(id, fields)` API — callers must remove+add | Needed for G2 |
| G11 | Generator has no strength estimate in core | Needed for G5 |

---

## Prioritised, bounded improvements

### Tier 1 — Safe API additions + tests (high value, no breakage risk)

1. **`Vault::update(id, Entry)`** — modifies an existing entry in-place; returns
   false if id not found. Tests: field update, id preserved, unknown id.

2. **`strength_score(password) -> PasswordStrength`** — estimates password
   strength (entropy bucket: WEAK / FAIR / STRONG / VERY_STRONG) based on
   length and character-class diversity. Pure function, no libsodium needed.
   Tests: known weak / strong passwords.

3. **`export_vault` / `import_vault`** — serialise + encrypt the vault to a
   self-contained byte blob with a different (export) password; the format is
   identical to the normal vault file so `load_vault` can open it.
   Tests: round-trip import(export(v)) == v; wrong export password throws.

### Tier 2 — CLI commands backed by Tier 1

4. **`get <id>`** — print full entry details (including password and notes, which
   `list` omits).

5. **`update <id> [--name] [--username] [--url] [--password-entry] [--notes]
   [--tags]`** — update only the supplied fields.

6. **`remove-by-name <name>`** — remove first entry whose name matches exactly
   (case-insensitive).

7. **`change-password --new-password <p>`** — decrypt with current master
   password, re-encrypt with new password, write back.

8. **`strength <password>`** — print strength label + bit estimate without
   touching vault.

### Tier 3 — Input hardening

9. Wrap all `std::stoul` / `std::stoull` call-sites in try/catch with a
   user-friendly error message.

10. `sodium_memzero` the master-password string after use in CLI
    (best-effort — stack string, not heap-pinned, but still better than nothing).

### Tier 4 — Documentation (no code changes)

11. Expand README security section: threat model table, what IS / IS NOT
    protected, why HMAC-SHA256 instead of SHA-1, key-derivation parameters.

12. Add a Mermaid diagram of the vault file byte layout and the
    encrypt / decrypt flow.

---

## DONE criterion

- `ctest --test-dir build --output-on-failure` reports **38+ tests, 0 failures**.
- `cmake --build build` produces **zero -Wall -Wextra warnings**.
- All new CLI commands are exercised in `scripts/demo.sh` (or an extended version).
- README contains threat model table and Mermaid diagram.
- No custom crypto introduced. No external dependencies added.
