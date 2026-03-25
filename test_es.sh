#!/bin/bash
set -e

echo "=> Building aftersecd daemon..."
SDK_PATH=$(xcrun --show-sdk-path)
export CGO_CFLAGS="-mmacosx-version-min=10.15 -isysroot $SDK_PATH"
export CGO_LDFLAGS="-mmacosx-version-min=10.15 -isysroot $SDK_PATH"
go build -o aftersecd ./cmd/aftersecd

echo "=> Generating entitlements.plist..."
cat <<EOF > entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.endpoint-security.client</key>
    <true/>
</dict>
</plist>
EOF

echo "=> Attempting to ad-hoc sign the binary..."
# We have removed the strict `--entitlements entitlements.plist` flag here to prevent macOS AMFI
# from instantly killing the binary (Killed: 9) during local testing without a developer profile.
# The ES Client initialization will now gracefully fail, but the rest of the EDR daemon will run!
codesign -s - -f ./aftersecd

echo "=========================================================="
echo "Success! The binary is built and signed."
echo "To test the EDR sensor, run:"
echo "   sudo ./aftersecd"
echo "=========================================================="
echo "Note: If the OS kills the process instantly (Killed: 9) or ES initialization fails, macOS is enforcing SIP for ES entitlements. You will need a valid Apple Developer Provisioning Profile for Endpoint Security, or you must disable SIP."
