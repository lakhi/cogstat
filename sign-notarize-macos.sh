#!/usr/bin/env bash
#
# Sign, notarize and staple the CogStat macOS bundle (arm64, Python 3.12, PyQt6).
#
# Replaces codesign-cogstat-intel-python3_11.sh, which hardcoded ~45 Intel /
# Python 3.11 / PyQt5 paths. This one discovers what to sign instead.
#
# Required environment:
#   IDENTITY    "Developer ID Application: <Name> (<TEAMID>)"
#   API_KEY     path to the App Store Connect .p8 key file
#   API_KEY_ID  the Key ID
#   API_ISSUER  the Issuer ID (UUID)
#
# Usage:  IDENTITY=... API_KEY=... API_KEY_ID=... API_ISSUER=... \
#           caffeinate -dims ./sign-notarize-macos.sh

set -euo pipefail

APP="${APP:-dist/CogStat.app}"
ENTITLEMENTS="${ENTITLEMENTS:-entitlements.plist}"
DMG="${DMG:-CogStat-2.5-macOS-arm64.dmg}"
VOLNAME="${VOLNAME:-CogStat 2.5}"
DMG_BACKGROUND="${DMG_BACKGROUND:-cogstat_dmg.png}"
WORK="${WORK:-$(mktemp -d -t cogstat-sign)}"

: "${IDENTITY:?IDENTITY is not set (see header)}"
: "${API_KEY:?API_KEY is not set (see header)}"
: "${API_KEY_ID:?API_KEY_ID is not set (see header)}"
: "${API_ISSUER:?API_ISSUER is not set (see header)}"

# --timestamp needs network access; --options=runtime is mandatory for notarization.
SIGN_OPTS=(--force --timestamp --options=runtime)
NOTARY_AUTH=(--key "$API_KEY" --key-id "$API_KEY_ID" --issuer "$API_ISSUER")

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------- preflight --
step "Preflight"
[[ -d "$APP" ]]             || { echo "missing $APP"; exit 1; }
[[ -f "$ENTITLEMENTS" ]]    || { echo "missing $ENTITLEMENTS"; exit 1; }
[[ -f "$API_KEY" ]]         || { echo "missing API key $API_KEY"; exit 1; }
security find-identity -v -p codesigning | grep -F "$IDENTITY" \
  || { echo "identity not found in keychain: $IDENTITY"; exit 1; }
echo "work dir: $WORK"

# -------------------------------------------------------------------- clean --
# Extended attributes and dangling symlinks both make the seal unverifiable.
step "Cleaning bundle"
xattr -cr "$APP"
find "$APP" -type l ! -exec test -e {} \; -print -delete 2>/dev/null || true

# ------------------------------------------------- dylibs inside python*.zip --
# Apple's notary service unpacks nested archives and inspects every Mach-O it
# finds, so the PIL dylibs sealed inside python312.zip have to be signed too.
step "Signing dylibs inside python312.zip"
ZIP_DIR="$APP/Contents/Resources/lib"
ZIP_NAME="$(cd "$ZIP_DIR" && ls python3*.zip)"
UNZIPPED="$WORK/zipcontents"
/usr/bin/ditto -x -k "$ZIP_DIR/$ZIP_NAME" "$UNZIPPED"
zip_count=0
while IFS= read -r -d '' lib; do
    codesign --sign "$IDENTITY" "${SIGN_OPTS[@]}" "$lib"
    zip_count=$((zip_count + 1))
done < <(find "$UNZIPPED" \( -name '*.dylib' -o -name '*.so' \) -print0)
echo "signed $zip_count binaries inside $ZIP_NAME"
rm -f "$ZIP_DIR/$ZIP_NAME"
/usr/bin/ditto -c -k --norsrc --noextattr "$UNZIPPED" "$ZIP_DIR/$ZIP_NAME"

# ------------------------------------------------- loose .so / .dylib files --
step "Signing loose .so / .dylib files"
lib_count=0
while IFS= read -r -d '' lib; do
    codesign --sign "$IDENTITY" "${SIGN_OPTS[@]}" "$lib"
    lib_count=$((lib_count + 1))
done < <(find "$APP" -type f \( -name '*.so' -o -name '*.dylib' \) -print0)
echo "signed $lib_count libraries"

# ------------------------------------------------------- any other Mach-O ----
# Safety net for executables with no revealing extension (Qt helper tools,
# the Python.framework stub, etc.) that the extension-based sweep misses.
step "Signing remaining Mach-O executables"
other_count=0
while IFS= read -r -d '' f; do
    case "$f" in *.so|*.dylib) continue ;; esac
    [[ "$f" == "$APP/Contents/MacOS/"* ]] && continue   # signed later, with entitlements
    if file -b "$f" | grep -q 'Mach-O'; then
        codesign --sign "$IDENTITY" "${SIGN_OPTS[@]}" "$f"
        other_count=$((other_count + 1))
    fi
done < <(find "$APP" -type f -perm -u+x -print0)
echo "signed $other_count additional binaries"

# -------------------------------------------------------------- frameworks --
# A framework's bundle root is whichever directory holds the real
# Resources/Info.plist -- NOT always Versions/A. Two shapes occur here:
#   Python.framework  canonical: Resources is a symlink into Versions/Current,
#                     the real plist is at Versions/3.12/Resources/Info.plist
#   Qt frameworks     flattened by py2app: real Resources/ at the framework
#                     root, Versions/A holds only the binary and no Resources
# Signing Versions/A on the flattened shape fails with "bundle format
# unrecognized", so locate the plist instead of assuming a layout.
step "Signing frameworks"
fw_count=0
fw_skipped=0
while IFS= read -r -d '' fw; do
    target=""
    # Prefer a real versioned bundle root (canonical frameworks).
    for vdir in "$fw"/Versions/*; do
        [[ -d "$vdir" && ! -L "$vdir" ]] || continue
        [[ "$(basename "$vdir")" == "Current" ]] && continue
        if [[ -f "$vdir/Resources/Info.plist" ]]; then
            target="$vdir"
            break
        fi
    done
    # Otherwise the framework root itself, if that is where the plist lives.
    if [[ -z "$target" && -f "$fw/Resources/Info.plist" ]]; then
        target="$fw"
    fi
    if [[ -z "$target" ]]; then
        # No bundle metadata at all: the binary was already signed as a plain
        # Mach-O in the sweep above, which is all notarization requires.
        fw_skipped=$((fw_skipped + 1))
        continue
    fi
    codesign --sign "$IDENTITY" "${SIGN_OPTS[@]}" "$target"
    fw_count=$((fw_count + 1))
done < <(find "$APP" -name '*.framework' -type d -print0)
echo "signed $fw_count frameworks ($fw_skipped had no bundle metadata, already covered)"

# -------------------------------- main executables + bundle, w/ entitlements --
# The entitlements must land on whatever actually executes: both py2app stubs
# and the bundle itself. disable-library-validation on the main executable is
# what lets CPython dlopen() everything signed above.
step "Signing main executables and app bundle"
for exe in "$APP/Contents/MacOS/python" "$APP/Contents/MacOS/CogStat"; do
    [[ -f "$exe" ]] && codesign --sign "$IDENTITY" "${SIGN_OPTS[@]}" \
        --entitlements "$ENTITLEMENTS" "$exe"
done
codesign --sign "$IDENTITY" "${SIGN_OPTS[@]}" \
    --entitlements "$ENTITLEMENTS" "$APP"

step "Verifying signature"
codesign --verify --deep --strict --verbose=2 "$APP"
codesign -dv --verbose=4 "$APP" 2>&1 | grep -E 'Authority|TeamIdentifier|flags|Identifier'

# ----------------------------------------------------- notarize + staple app --
step "Notarizing the app"
APP_ZIP="$WORK/CogStat.zip"
/usr/bin/ditto -c -k --keepParent "$APP" "$APP_ZIP"
xcrun notarytool submit "$APP_ZIP" "${NOTARY_AUTH[@]}" --wait --timeout 3h
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"

# ------------------------------------------------------- build + sign the DMG --
# APFS, not HFS+: HFS+ stores filenames decomposed (NFD), which rewrites the
# Hungarian dataset filenames and breaks the signature seal inside the image.
step "Building the DMG from the stapled app"
rm -f "$DMG"
create-dmg \
  --volname "$VOLNAME" \
  --filesystem APFS \
  --background "$DMG_BACKGROUND" \
  --window-pos 200 120 \
  --window-size 680 420 \
  --icon-size 100 \
  --icon "CogStat.app" 170 300 \
  --hide-extension "CogStat.app" \
  --app-drop-link 510 300 \
  --no-internet-enable \
  "$DMG" \
  "$(dirname "$APP")/"

step "Signing the DMG"
codesign --sign "$IDENTITY" --force --timestamp "$DMG"

step "Notarizing the DMG"
xcrun notarytool submit "$DMG" "${NOTARY_AUTH[@]}" --wait --timeout 3h
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"

# ------------------------------------------------------------------- verify --
step "Final Gatekeeper assessment"
# -t exec assesses an app bundle; -t install assesses the disk image.
spctl -a -vvv -t exec "$APP"
spctl -a -vvv -t install "$DMG"
codesign --verify --deep --strict --verbose=2 "$APP"
echo
echo "DMG:    $DMG"
echo "size:   $(du -h "$DMG" | cut -f1)"
echo "sha256: $(shasum -a 256 "$DMG" | cut -d' ' -f1)"
echo
echo "Done. Clean up the work dir when satisfied:  rm -rf $WORK"
