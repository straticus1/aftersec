#!/bin/sh
# Compile the CO-RE network sensor. This does not sign anything.
# Apple developer ID packaging for the Network Extension is a separate step.
set -eu
cd "$(dirname "$0")"
if ! command -v clang >/dev/null 2>&1; then
  echo "clang is required to build aftersec_network.bpf.o" >&2
  exit 1
fi
clang -O2 -g -target bpf -c aftersec_network.bpf.c -o aftersec_network.bpf.o
test -s aftersec_network.bpf.o
