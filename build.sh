#!/bin/bash

function clean() {
	echo "Cleaning..."
	rm -f bin/aftersec
	rm -f bin/aftersec-gui
	rm -f bin/aftersecd
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

function debug() {
	echo "Building all in debug mode..."
	go build -gcflags="all=-N -l" -o bin/aftersec ./cmd/aftersec
	go build -gcflags="all=-N -l" -o bin/aftersec-gui ./cmd/aftersec-gui
	go build -gcflags="all=-N -l" -o bin/aftersecd ./cmd/aftersecd
}

function all() {
	clean
	cli
	gui
	daemon
}

mkdir -p bin

case "$1" in
	clean) clean ;;
	cli) cli ;;
	gui) gui ;;
	daemon) daemon ;;
	debug) debug ;;
	all) all ;;
	*) echo "Usage: $0 {clean|cli|gui|daemon|debug|all}" ;;
esac
