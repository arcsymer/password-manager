#!/usr/bin/env bash
# Demo script — non-interactive CLI walkthrough for CI.
# Uses ONLY synthetic data. No real credentials.
# Usage: scripts/demo.sh <path-to-pwman-cli>

set -euo pipefail

CLI="${1:-./build/cli/pwman-cli}"
VAULT="$(mktemp /tmp/demo-XXXXXX.vault)"
PASSWORD="demo-master-password"

cleanup() { rm -f "$VAULT"; }
trap cleanup EXIT

echo "========================================"
echo " pwman-cli  —  demo session"
echo "========================================"
echo ""

# ---- Add entries ----
echo "[1] Adding synthetic entries..."
"$CLI" --vault "$VAULT" --password "$PASSWORD" add \
    --name "GitHub Demo" \
    --username "demouser@example.com" \
    --url "https://github.com" \
    --password-entry "demo-gh-password" \
    --tags "dev,work"

"$CLI" --vault "$VAULT" --password "$PASSWORD" add \
    --name "Email Demo" \
    --username "demouser@example.com" \
    --url "https://mail.example.com" \
    --password-entry "demo-mail-password" \
    --notes "personal mailbox" \
    --tags "personal"

"$CLI" --vault "$VAULT" --password "$PASSWORD" add \
    --name "Jira Demo" \
    --username "demouser" \
    --url "https://jira.example.com" \
    --password-entry "demo-jira-password" \
    --tags "work"

echo ""

# ---- List ----
echo "[2] Listing all entries..."
"$CLI" --vault "$VAULT" --password "$PASSWORD" list
echo ""

# ---- Search by name ----
echo "[3] Searching for 'demo'..."
"$CLI" --vault "$VAULT" --password "$PASSWORD" search demo
echo ""

# ---- Search by tag ----
echo "[4] Searching for 'work'..."
"$CLI" --vault "$VAULT" --password "$PASSWORD" search work
echo ""

# ---- Search — no results ----
echo "[5] Searching for 'nonexistent'..."
"$CLI" --vault "$VAULT" --password "$PASSWORD" search nonexistent
echo ""

# ---- Unlock (verify password) ----
echo "[6] Unlocking vault with correct password..."
"$CLI" --vault "$VAULT" --password "$PASSWORD" unlock
echo ""

# ---- Wrong password ----
echo "[7] Attempting unlock with wrong password (expect error)..."
"$CLI" --vault "$VAULT" --password "wrong-password" unlock && echo "UNEXPECTED: succeeded" || echo "Expected error: decryption failed."
echo ""

# ---- TOTP (HMAC-SHA256, deterministic) ----
# Demo secret (Base32). TOTP here uses HMAC-SHA256 (libsodium has no SHA-1);
# the exact RFC 6238 SHA-256 reference vectors are checked in the unit tests.
TOTP_SECRET="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
echo "[8] TOTP code at T=59 (HMAC-SHA256, deterministic 8-digit)..."
"$CLI" totp --secret "$TOTP_SECRET" --digits 8 --period 30 --time 59
echo ""

echo "[9] TOTP at T=1234567890 (HMAC-SHA256, deterministic 8-digit)..."
"$CLI" totp --secret "$TOTP_SECRET" --digits 8 --period 30 --time 1234567890
echo ""

# ---- Password generator ----
echo "[10] Generating a random 24-char password..."
"$CLI" generate --length 24
echo ""

echo "[11] Generating alphanumeric-only password (no symbols)..."
"$CLI" generate --length 16 --no-symbols
echo ""

echo "========================================"
echo " Demo complete."
echo "========================================"
