#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
BUILD_DIR="$PROJECT_DIR/build/iphoneos"
OUTPUT_DIR="$PROJECT_DIR/output"
APP_PATH="$OUTPUT_DIR/Payload/TunnelClient.app"
TUNNEL_PATH="$APP_PATH/PlugIns/PacketTunnelService.appex"
RESIGN_ENTITLEMENTS="$PROJECT_DIR/Config/ResignReady.entitlements"
IPA_PATH="$OUTPUT_DIR/TunnelClient-resign-ready.ipa"

cd "$PROJECT_DIR"
sh "$SCRIPT_DIR/fetch-geo.sh"
xcodegen generate

rm -rf "$BUILD_DIR" "$OUTPUT_DIR/Payload"
mkdir -p "$BUILD_DIR" "$OUTPUT_DIR/Payload"

xcodebuild \
    -project TunnelClient.xcodeproj \
    -scheme TunnelClient \
    -configuration Release \
    -sdk iphoneos \
    -destination 'generic/platform=iOS' \
    -derivedDataPath "$PROJECT_DIR/build/DerivedData" \
    CODE_SIGNING_ALLOWED=NO \
    CODE_SIGNING_REQUIRED=NO \
    DEVELOPMENT_TEAM= \
    CONFIGURATION_BUILD_DIR="$BUILD_DIR" \
    build

cp -R "$BUILD_DIR/TunnelClient.app" "$OUTPUT_DIR/Payload/"

# Seed the unsigned archive with the capabilities a re-signing tool must
# preserve.  The ad-hoc signatures are intentionally not installable on their
# own; the user's certificate/profile still has to authorize these exact
# entitlements.  Sign the nested extension first, then its containing app.
/usr/bin/codesign \
    --force \
    --sign - \
    --entitlements "$RESIGN_ENTITLEMENTS" \
    --generate-entitlement-der \
    "$TUNNEL_PATH"
/usr/bin/codesign \
    --force \
    --sign - \
    --entitlements "$RESIGN_ENTITLEMENTS" \
    --generate-entitlement-der \
    "$APP_PATH"
/usr/bin/codesign --verify --deep --strict "$APP_PATH"

for bundle in "$APP_PATH" "$TUNNEL_PATH"; do
    /usr/bin/codesign -d --entitlements :- "$bundle" \
        > "$OUTPUT_DIR/client-entitlements.plist" 2>/dev/null
    value=$(/usr/libexec/PlistBuddy \
        -c "Print :com.apple.developer.networking.networkextension:0" \
        "$OUTPUT_DIR/client-entitlements.plist")
    if [ "$value" != "packet-tunnel-provider" ]; then
        echo "Required Packet Tunnel entitlement is missing from $bundle" >&2
        exit 1
    fi
done
rm -f "$OUTPUT_DIR/client-entitlements.plist"

cd "$OUTPUT_DIR"
rm -f "$IPA_PATH" "$IPA_PATH.sha256"
ditto -c -k --sequesterRsrc --keepParent Payload "$IPA_PATH"
shasum -a 256 "$IPA_PATH" > "$IPA_PATH.sha256"
python3 "$SCRIPT_DIR/audit-ipa.py" "$IPA_PATH"
