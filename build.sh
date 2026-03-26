#!/bin/bash

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
	all) all; package ;;
	*) echo "Usage: $0 {clean|cli|gui|daemon|server|lib|dashboard|proto|debug|package|all}" ;;
esac
