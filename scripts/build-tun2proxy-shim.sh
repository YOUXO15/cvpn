#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
SHIM_DIR="$PROJECT_DIR/Vendor/Tun2ProxyShim"
TARGET_DIR="$SHIM_DIR/target"
OUTPUT="$PROJECT_DIR/Vendor/Tun2ProxyShim.xcframework"
SIMULATOR_LIBRARY="$TARGET_DIR/ios-simulator/libtunnel_proxy_shim.a"
RUST_TOOLCHAIN=1.85.1

rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
rustup target add --toolchain "$RUST_TOOLCHAIN" \
    aarch64-apple-ios \
    aarch64-apple-ios-sim \
    x86_64-apple-ios

export IPHONEOS_DEPLOYMENT_TARGET=16.0
cargo +"$RUST_TOOLCHAIN" build --locked --manifest-path "$SHIM_DIR/Cargo.toml" --release --target aarch64-apple-ios
cargo +"$RUST_TOOLCHAIN" build --locked --manifest-path "$SHIM_DIR/Cargo.toml" --release --target aarch64-apple-ios-sim
cargo +"$RUST_TOOLCHAIN" build --locked --manifest-path "$SHIM_DIR/Cargo.toml" --release --target x86_64-apple-ios

rm -rf "$TARGET_DIR/ios-simulator" "$OUTPUT"
mkdir -p "$TARGET_DIR/ios-simulator"
lipo -create \
    "$TARGET_DIR/aarch64-apple-ios-sim/release/libtunnel_proxy_shim.a" \
    "$TARGET_DIR/x86_64-apple-ios/release/libtunnel_proxy_shim.a" \
    -output "$SIMULATOR_LIBRARY"

xcodebuild -create-xcframework \
    -library "$TARGET_DIR/aarch64-apple-ios/release/libtunnel_proxy_shim.a" \
    -headers "$SHIM_DIR/include" \
    -library "$SIMULATOR_LIBRARY" \
    -headers "$SHIM_DIR/include" \
    -output "$OUTPUT"
