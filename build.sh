#!/bin/bash

function clean() {
	echo "Cleaning..."
	rm -f bin/aftersec
	rm -f bin/aftersec-gui
	rm -f bin/aftersecd
	rm -f bin/aftersec-server
	rm -f bin/afterseclib.*
}

function cli() {
	echo "Building CLI..."
	go build -o bin/aftersec ./cmd/aftersec
}

function gui() {
	echo "Building GUI..."
	go build -o bin/aftersec-gui ./cmd/aftersec-gui
}

function daemon() {
	echo "Building Daemon..."
	go build -o bin/aftersecd ./cmd/aftersecd
}

function server() {
	echo "Building Server..."
	go build -o bin/aftersec-server ./cmd/aftersec-server
}

function lib() {
	echo "Building Library..."
	go build -buildmode=c-shared -o bin/afterseclib.so ./afterseclib
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
	cli
	gui
	daemon
	server
	lib
}

mkdir -p bin

case "$1" in
	clean) clean ;;
	cli) cli ;;
	gui) gui ;;
	daemon) daemon ;;
	server) server ;;
	lib) lib ;;
	debug) debug ;;
	all) all ;;
	*) echo "Usage: $0 {clean|cli|gui|daemon|server|lib|debug|all}" ;;
esac
