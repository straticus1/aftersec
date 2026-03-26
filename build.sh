#!/bin/bash

# Set consistent macOS deployment target for all builds
export MACOSX_DEPLOYMENT_TARGET=11.0
export CGO_CFLAGS="-mmacosx-version-min=11.0"
export CGO_LDFLAGS="-mmacosx-version-min=11.0"

function clean() {
	echo "Cleaning..."
	rm -f bin/aftersec
	rm -f bin/aftersec-gui
	rm -f bin/aftersecd
	rm -f bin/aftersec-server
	rm -f bin/afterseclib.*
	rm -rf aftersec-dashboard/.next
	rm -rf aftersec-dashboard/out
}

function cli() {
	echo "Building CLI..."
	go build -trimpath -ldflags="-s -w" -o bin/aftersec ./cmd/aftersec
}

function gui() {
	echo "Building GUI..."
	go build -trimpath -ldflags="-s -w" -o bin/aftersec-gui ./cmd/aftersec-gui
}

function daemon() {
	echo "Building Daemon..."
	go build -trimpath -ldflags="-s -w" -o bin/aftersecd ./cmd/aftersecd
}

function server() {
	echo "Building Server..."
	go build -trimpath -ldflags="-s -w" -o bin/aftersec-server ./cmd/aftersec-server
}

function lib() {
	echo "Building Library..."
	go build -trimpath -ldflags="-s -w" -buildmode=c-shared -o bin/afterseclib.so ./afterseclib
}

function dashboard() {
	echo "Building Dashboard..."
	cd aftersec-dashboard || exit
	npm install
	npm run build
	# Optional: if using "export" in Next.js, copy to bin/dashboard
	# cp -R out ../bin/dashboard
	cd ..
}

function proto() {
	echo "Generating Protocol Buffers..."
	export PATH="$PATH:$(go env GOPATH)/bin"
	if ! command -v protoc-gen-go &> /dev/null; then
		echo "Installing missing protoc-gen-go dependencies..."
		go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
		go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	fi
	protoc --go_out=. --go-grpc_out=. api/proto/aftersec.proto
}

function debug() {
	echo "Building all in debug mode..."
	go build -gcflags="all=-N -l" -o bin/aftersec ./cmd/aftersec
	go build -gcflags="all=-N -l" -o bin/aftersec-gui ./cmd/aftersec-gui
	go build -gcflags="all=-N -l" -o bin/aftersecd ./cmd/aftersecd
	go build -gcflags="all=-N -l" -o bin/aftersec-server ./cmd/aftersec-server
	go build -gcflags="all=-N -l" -buildmode=c-shared -o bin/afterseclib.so ./afterseclib
}

function build-installer() {
	echo "Building macOS Installer PKG..."
	if [ ! -f "bin/aftersecd" ] || [ ! -f "bin/aftersec-gui" ] || [ ! -f "bin/aftersec" ]; then
		echo "Missing binaries. Building first..."
		cli
		gui
		daemon
	fi
	
	PKG_ROOT="build/pkg_root"
	
	# Daemons and CLI go to /usr/local/bin
	INSTALL_DIR="$PKG_ROOT/usr/local/bin"
	mkdir -p "$INSTALL_DIR"
	cp bin/aftersec "$INSTALL_DIR/"
	cp bin/aftersecd "$INSTALL_DIR/"
	
	# GUI goes to /Applications as a standard .app bundle
	APP_DIR="$PKG_ROOT/Applications/AfterSec.app/Contents"
	mkdir -p "$APP_DIR/MacOS"
	mkdir -p "$APP_DIR/Resources"
	cp bin/aftersec-gui "$APP_DIR/MacOS/AfterSec"
	[ -f "cmd/aftersec-gui/Icon.png" ] && cp "cmd/aftersec-gui/Icon.png" "$APP_DIR/Resources/Icon.png"
	
	cat <<EOF > "$APP_DIR/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>AfterSec</string>
	<key>CFBundleIconFile</key>
	<string>Icon.png</string>
	<key>CFBundleIdentifier</key>
	<string>com.aftersec.gui</string>
	<key>CFBundleName</key>
	<string>AfterSec</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0.0</string>
	<key>LSMinimumSystemVersion</key>
	<string>10.13.0</string>
</dict>
</plist>
EOF
	
	DAEMON_DIR="$PKG_ROOT/Library/LaunchDaemons"
	mkdir -p "$DAEMON_DIR"
	cat <<EOF > "$DAEMON_DIR/com.aftersec.daemon.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.aftersec.daemon</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/local/bin/aftersecd</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>
EOF

	pkgbuild --root "$PKG_ROOT" --identifier "com.aftersec.suite" --version "1.0.0" --install-location "/" aftersec-installer.pkg
	echo "Installer generated: aftersec-installer.pkg"
	rm -rf build/pkg_root
}

function all() {
	clean
	proto
	cli
	gui
	daemon
	server
	lib
	dashboard
}

function package() {
	echo "Packaging Release Archive..."
	tar -czvf aftersec-macos-release.tar.gz -C bin aftersec aftersec-gui aftersecd aftersec-server
	echo "Archive generated: aftersec-macos-release.tar.gz"
}

mkdir -p bin

case "$1" in
	clean) clean ;;
	cli) cli ;;
	gui) gui ;;
	daemon) daemon ;;
	server) server ;;
	lib) lib ;;
	dashboard) dashboard ;;
	proto) proto ;;
	debug) debug ;;
	package) package ;;
	build-installer) build-installer ;;
	all) all; package ;;
	*) echo "Usage: $0 {clean|cli|gui|daemon|server|lib|dashboard|proto|debug|package|build-installer|all}" ;;
esac
