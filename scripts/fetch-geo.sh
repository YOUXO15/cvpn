#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DESTINATION="$SCRIPT_DIR/../Resources/Tunnel/Geo"
mkdir -p "$DESTINATION"

GEOIP_URL="https://github.com/v2fly/geoip/releases/download/202608050239/geoip.dat"
GEOIP_SHA256="c67bd077eb102cec74fab759b73d17f99275f56af10a87c14d9fd983508f5ce1"
GEOSITE_URL="https://github.com/v2fly/domain-list-community/releases/download/20260827152101/dlc.dat"
GEOSITE_SHA256="ba1adf51d4d724abbc157c53234a02bda00c94cdb8211709682e51a6855520b7"

download_verified() {
    url="$1"
    expected="$2"
    destination="$3"
    temporary="${destination}.download"

    if [ -f "$destination" ]; then
        actual=$(shasum -a 256 "$destination" | awk '{print $1}')
        if [ "$actual" = "$expected" ]; then
            return
        fi
    fi

    curl --fail --location --proto '=https' --tlsv1.2 --output "$temporary" "$url"
    actual=$(shasum -a 256 "$temporary" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
        rm -f "$temporary"
        echo "Checksum mismatch for $destination" >&2
        exit 1
    fi
    mv "$temporary" "$destination"
}

download_verified "$GEOIP_URL" "$GEOIP_SHA256" "$DESTINATION/geoip.dat"
download_verified "$GEOSITE_URL" "$GEOSITE_SHA256" "$DESTINATION/geosite.dat"

