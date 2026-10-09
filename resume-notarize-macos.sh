#!/usr/bin/env bash
#
# Resume after a notarytool --wait timeout. The app bundle is already signed
# and the submission already exists at Apple, so nothing is re-signed and
# nothing is re-uploaded: this attaches to the existing submission by ID.
#
# Usage: APP_SUBMISSION_ID=<uuid> IDENTITY=... API_KEY=... API_KEY_ID=... \
#          API_ISSUER=... caffeinate -dims ./resume-notarize-macos.sh

set -euo pipefail

APP="${APP:-dist/CogStat.app}"
DMG="${DMG:-CogStat-2.5-macOS-arm64.dmg}"
VOLNAME="${VOLNAME:-CogStat 2.5}"
DMG_BACKGROUND="${DMG_BACKGROUND:-cogstat_dmg.png}"

: "${APP_SUBMISSION_ID:?set APP_SUBMISSION_ID to the pending submission UUID}"
: "${IDENTITY:?}"; : "${API_KEY:?}"; : "${API_KEY_ID:?}"; : "${API_ISSUER:?}"

AUTH=(--key "$API_KEY" --key-id "$API_KEY_ID" --issuer "$API_ISSUER")
step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# Wait on the EXISTING submission. 3h ceiling: this bundle carries 783 Mach-O
# binaries and the notary service analyses each one, so the default 45m that
# the first run used was simply too short.
step "Waiting on existing app submission $APP_SUBMISSION_ID"
xcrun notarytool wait "$APP_SUBMISSION_ID" "${AUTH[@]}" --timeout 3h

status="$(xcrun notarytool info "$APP_SUBMISSION_ID" "${AUTH[@]}" \
            | awk '/status:/ {print $2; exit}')"
echo "final status: $status"
if [[ "$status" != "Accepted" ]]; then
    step "Rejected - fetching the notary log"
    xcrun notarytool log "$APP_SUBMISSION_ID" "${AUTH[@]}"
    exit 1
fi

step "Stapling the app"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"

step "Building the DMG from the stapled app"
# APFS, not HFS+: HFS+ normalises filenames to NFD, which rewrites the
# Hungarian dataset filenames and breaks the signature seal inside the image.
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
# The DMG is one file wrapping an already-notarized app, so this pass is much
# quicker than the app submission.
xcrun notarytool submit "$DMG" "${AUTH[@]}" --wait --timeout 3h
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"

step "Final Gatekeeper assessment"
spctl -a -vvv -t exec "$APP"
spctl -a -vvv -t install "$DMG"
codesign --verify --deep --strict --verbose=2 "$APP"

echo
echo "DMG:    $DMG"
echo "size:   $(du -h "$DMG" | cut -f1)"
echo "sha256: $(shasum -a 256 "$DMG" | cut -d' ' -f1)"
