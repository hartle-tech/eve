#!/usr/bin/env bash
# Obtain and install a Developer ID Application certificate for signing eve.
#
# WHY THIS EXISTS
#
# macOS keys a TCC permission — Full Disk Access, the media library, Photos —
# to the program's *code signing requirement*, not to its path. cargo emits an
# ad-hoc, linker-signed binary whose requirement pins a cdhash derived from
# that exact build, so rebuilding eve makes macOS treat it as a different
# program: every permission the user granted is discarded and the prompts start
# again. Signing with a certificate changes what the requirement pins — the
# leaf certificate and a fixed identifier, neither of which changes between
# builds.
#
# A self-signed certificate is enough for that. A Developer ID Application
# certificate does the same job and two more: Gatekeeper stops calling eve an
# unidentified developer, and the binary becomes notarizable.
#
# Run the phases in order. Each is idempotent.
#
#   scripts/create-signing-identity.sh csr       # make a key + CSR
#   scripts/create-signing-identity.sh install   # after downloading the .cer
#   scripts/create-signing-identity.sh verify

set -euo pipefail

# The private key never goes in the repo — see the no-secrets rule. It lives
# beside the other machine-local credentials and belongs in OpenBao.
KEY_DIR="${EVE_SIGNING_DIR:-$HOME/.config/hartle.tech/signing}"
KEY="$KEY_DIR/eve-developer-id.key"
CSR="$KEY_DIR/eve-developer-id.csr"
CER="${EVE_SIGNING_CER:-$HOME/Downloads/developerID_application.cer}"
P12="$KEY_DIR/eve-developer-id.p12"
KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"

# Apple's intermediates. codesign cannot build a chain without them, and a
# machine with no Xcode has none installed — the failure is an unhelpful
# "unable to build chain to self-signed root" that names nothing.
#
# Developer ID G2 is the one that signs a Developer ID Application certificate.
# WWDR G4 is not needed for that, but is for anything Apple Development signs
# and for notarization tooling, and costs nothing to have present.
# The legacy Developer ID CA is here too, because the portal's default is the
# *previous* Sub-CA and it is one radio button away from G2. A certificate
# issued from it has `OU=Apple Certification Authority` rather than `OU=G2`,
# and without its intermediate codesign fails with the same chain error that
# names nothing. Installing both costs nothing and removes a trap.
CA_URLS=(
    "https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer"
    "https://www.apple.com/certificateauthority/DeveloperIDCA.cer"
    "https://www.apple.com/certificateauthority/AppleWWDRCAG4.cer"
)

phase_csr() {
    mkdir -p "$KEY_DIR"
    chmod 700 "$KEY_DIR"

    # -nodes keeps the key unencrypted so unattended signing works. The
    # directory is 0700 and the key 0600; the real protection is that it is
    # never copied anywhere, and a passphrase would only move the problem to
    # wherever the passphrase had to live for launchd to reach it.
    #
    # An existing key is reused rather than replaced. Regenerating it would
    # orphan any certificate already issued against it, and Developer ID
    # certificates are capped per account — quietly burning one is not a
    # recoverable mistake.
    if [[ -f "$KEY" ]]; then
        echo "Reusing the existing private key at $KEY"
        openssl req -new -key "$KEY" -out "$CSR" \
            -subj "/CN=HARTLE.TECH/emailAddress=contact@hartle.tech/C=PT"
    else
        openssl req -new -newkey rsa:2048 -nodes \
            -keyout "$KEY" -out "$CSR" \
            -subj "/CN=HARTLE.TECH/emailAddress=contact@hartle.tech/C=PT" 2>/dev/null
    fi
    chmod 600 "$KEY"

    cat <<INSTRUCTIONS

Certificate request written to:
  $CSR

Now, at https://developer.apple.com/account/resources/certificates/add

  1. Choose **Developer ID Application**
     — not "Apple Development", which expires in a year and is not for
       distribution
     — if the option is missing you are not the Account Holder on the team
  2. Profile Type: **G2 Sub-CA (Xcode 11.4.1 or later)**
  3. Upload $CSR
  4. Download the .cer — it lands in ~/Downloads/developerID_application.cer

Then run:
  $0 install

Keep $KEY. Losing it means the certificate is
useless and Developer ID certificates are limited per account. Push it to
OpenBao once this works.

INSTRUCTIONS
}

phase_install() {
    [[ -f "$KEY" ]] || { echo "No private key at $KEY — run '$0 csr' first." >&2; exit 1; }
    [[ -f "$CER" ]] || { echo "No certificate at $CER — download it, or set EVE_SIGNING_CER." >&2; exit 1; }

    echo "Installing Apple's intermediate certificates…"
    local url ca
    for url in "${CA_URLS[@]}"; do
        ca="$KEY_DIR/$(basename "$url")"
        # Already fetched is fine — these are public and immutable, and it
        # keeps this phase working on a machine that is offline by the time
        # the certificate comes back from the portal.
        [[ -f "$ca" ]] || curl -fsSL "$url" -o "$ca"
        if security import "$ca" -k "$KEYCHAIN" 2>/dev/null; then
            echo "  installed $(basename "$ca")"
        else
            echo "  $(basename "$ca") already present"
        fi
    done

    echo "Importing the certificate and the private key…"
    # Imported as two separate items rather than bundled into a PKCS#12.
    #
    # The obvious route — build a .p12 and hand it to `security import` — fails
    # with "MAC verification failed during PKCS12 import (wrong password?)",
    # which is a lie: the password is right. OpenSSL 3 defaults a .p12 to an
    # AES-256 / SHA-256 MAC that macOS's importer will not read, so the error
    # names the one thing that is not wrong. Importing the halves separately
    # sidesteps the format entirely; the keychain pairs them by matching the
    # public key.
    #
    # -T authorises codesign to use the key. Without it every signing run pops
    # a keychain dialog, which is the sort of prompt this whole exercise exists
    # to remove.
    # Only "already exists" is tolerated. Swallowing every failure as
    # "already present" hides a genuinely rejected certificate behind a
    # reassuring line, and the next thing the operator sees is a signature
    # that is not the one they just installed.
    local out
    for item in "$CER" "$KEY"; do
        if out="$(security import "$item" -k "$KEYCHAIN" \
                    -T /usr/bin/codesign -T /usr/bin/productsign 2>&1)"; then
            echo "  imported $(basename "$item")"
        elif [[ "$out" == *"already exists"* ]]; then
            echo "  $(basename "$item") already in the keychain"
        else
            echo "  FAILED to import $(basename "$item"): $out" >&2
            exit 1
        fi
    done

    cat <<'NEXT'

One more step, and it needs your login password because it changes what may
use the key without asking. Run it yourself — this script will not take your
password:

  security set-key-partition-list -S apple-tool:,apple:,codesign: \
      -s -k "$(read -rsp 'login password: ' p; echo "$p")" \
      ~/Library/Keychains/login.keychain-db

Then:
  scripts/create-signing-identity.sh verify

NEXT
}

phase_verify() {
    echo "=== code signing identities ==="
    security find-identity -v -p codesigning || true

    local id
    id="$(security find-identity -v -p codesigning 2>/dev/null \
          | grep -o '"Developer ID Application: [^"]*"' | head -1 | tr -d '"')"

    if [[ -z "$id" ]]; then
        echo
        echo "No Developer ID Application identity yet."
        exit 1
    fi

    echo
    echo "Found: $id"
    echo
    echo "Deploy with it:"
    echo "  cd ansible && ansible-playbook -i hosts.ini autoclean.yml \\"
    echo "    -e eve_autoclean_signing_identity='$id'"
    echo
    echo "Then grant Full Disk Access to ~/.local/bin/eve ONCE. From that point"
    echo "the signature stops changing between builds, so the grant sticks."
}

case "${1:-}" in
    csr)     phase_csr ;;
    install) phase_install ;;
    verify)  phase_verify ;;
    *)       echo "usage: $0 {csr|install|verify}" >&2; exit 2 ;;
esac
