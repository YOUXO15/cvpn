from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import plistlib
import zipfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit the iOS client IPA bundle layout")
    parser.add_argument("ipa", type=Path)
    parser.add_argument(
        "--signed",
        action="store_true",
        help="require provisioning profiles instead of rejecting them",
    )
    args = parser.parse_args()
    ipa_path = args.ipa
    required = {
        "Payload/TunnelClient.app/TunnelClient",
        "Payload/TunnelClient.app/Info.plist",
        "Payload/TunnelClient.app/Assets.car",
        "Payload/TunnelClient.app/SecurityPolicy.plist",
        "Payload/TunnelClient.app/PrivacyInfo.xcprivacy",
        "Payload/TunnelClient.app/PlugIns/PacketTunnelService.appex/PacketTunnelService",
        "Payload/TunnelClient.app/PlugIns/PacketTunnelService.appex/Info.plist",
        "Payload/TunnelClient.app/PlugIns/PacketTunnelService.appex/PrivacyInfo.xcprivacy",
        "Payload/TunnelClient.app/PlugIns/PacketTunnelService.appex/Geo/geoip.dat",
        "Payload/TunnelClient.app/PlugIns/PacketTunnelService.appex/Geo/geosite.dat",
    }

    with zipfile.ZipFile(ipa_path) as archive:
        names = set(archive.namelist())
        missing = sorted(required - names)
        if missing:
            raise RuntimeError(f"IPA is missing required bundle files: {missing}")

        app_info = plistlib.loads(archive.read("Payload/TunnelClient.app/Info.plist"))
        extension_info = plistlib.loads(
            archive.read("Payload/TunnelClient.app/PlugIns/PacketTunnelService.appex/Info.plist")
        )
        policy = plistlib.loads(archive.read("Payload/TunnelClient.app/SecurityPolicy.plist"))

        if app_info.get("CFBundleIdentifier") != "com.example.tunnelclient":
            raise RuntimeError("Unexpected application bundle identifier")
        if extension_info.get("CFBundleIdentifier") != "com.example.tunnelclient.PacketTunnel":
            raise RuntimeError("Unexpected packet tunnel bundle identifier")
        transport_security = app_info.get("NSAppTransportSecurity", {})
        if transport_security.get("NSAllowsArbitraryLoads") is not False:
            raise RuntimeError("Application Transport Security is not fail-closed")
        if policy.get("requireSignedEnvelope") is not True:
            raise RuntimeError("Signed configuration envelopes are not required by default")
        maximum_response_bytes = policy.get("maximumResponseBytes")
        if (
            not isinstance(maximum_response_bytes, int)
            or isinstance(maximum_response_bytes, bool)
            or not 0 < maximum_response_bytes <= 4 * 1024 * 1024
        ):
            raise RuntimeError("Pinned response size policy is invalid")
        allowed_hosts = set(policy.get("allowedHosts", []))
        raw_hosts = set(policy.get("rawSubscriptionHosts", []))
        pins = policy.get("spkiPins", {})
        if not allowed_hosts or set(pins) != allowed_hosts:
            raise RuntimeError("Pinned-host policy is inconsistent")
        if not raw_hosts.issubset(allowed_hosts):
            raise RuntimeError("Raw-subscription policy is inconsistent")
        for host_index, host in enumerate(sorted(allowed_hosts)):
            if host != host.lower() or "*" in host or "/" in host:
                raise RuntimeError(f"Pinned host {host_index} is not exact")
            host_pins = pins.get(host, [])
            if len(host_pins) < 2:
                raise RuntimeError(f"Pinned host {host_index} lacks rotation overlap")
            for pin_index, pin in enumerate(host_pins):
                encoded = pin.removeprefix("sha256/")
                try:
                    decoded = base64.b64decode(encoded, validate=True)
                except (binascii.Error, ValueError) as error:
                    raise RuntimeError(
                        f"Pin {pin_index} for host {host_index} is malformed"
                    ) from error
                if len(decoded) != 32:
                    raise RuntimeError(
                        f"Pin {pin_index} for host {host_index} has wrong length"
                    )
        provisioning_profiles = {
            "Payload/TunnelClient.app/embedded.mobileprovision",
            "Payload/TunnelClient.app/PlugIns/PacketTunnelService.appex/embedded.mobileprovision",
        }
        present_profiles = provisioning_profiles & names
        if args.signed and present_profiles != provisioning_profiles:
            missing_profiles = sorted(provisioning_profiles - present_profiles)
            raise RuntimeError(f"Signed artifact is missing provisioning profiles: {missing_profiles}")
        if not args.signed and present_profiles:
            raise RuntimeError("Unsigned artifact unexpectedly contains a provisioning profile")

    print(json.dumps({
        "ipa": ipa_path.name,
        "sha256": hashlib.sha256(ipa_path.read_bytes()).hexdigest(),
        "required_bundle_files": len(required),
        "signed": args.signed,
        "status": "ok",
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
