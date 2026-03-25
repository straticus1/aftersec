#!/bin/bash
echo "Installing the explicit Fyne packaging toolchain... "
go install fyne.io/tools/cmd/fyne@latest
export PATH=$PATH:$(go env GOPATH)/bin

echo "Setting the Enterprise CGO bindings natively..."
SDK_PATH=$(xcrun --show-sdk-path)
export CGO_CFLAGS="-mmacosx-version-min=10.15 -isysroot $SDK_PATH"
export CGO_LDFLAGS="-mmacosx-version-min=10.15 -isysroot $SDK_PATH"

echo "Compiling the native macOS Payload Bundle (.app)... "
cd cmd/aftersec-gui
fyne package -os darwin -icon Icon.png -name "AfterSec Control Panel"

if [ -d "AfterSec Control Panel.app" ]; then
    echo "Injecting LSUIElement Boolean True directly into the internal compilation Info.plist!"
    plutil -insert LSUIElement -bool true "AfterSec Control Panel.app/Contents/Info.plist"
    
    rm -rf ../../bin/"AfterSec Control Panel.app"
    mv "AfterSec Control Panel.app" ../../bin/
    echo "Process Successfully Bound! Control Panel securely placed into bin/AfterSec Control Panel.app 🎉"
else
    echo "Fyne Native macOS packaging pipeline collapsed during artifact resolution."
    exit 1
fi
