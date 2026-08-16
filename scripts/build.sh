#!/usr/bin/env bash
# Builds the P2P server/client for Linux and Windows, and the Android AAR.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/bin"
AAR="$ROOT/android"
mkdir -p "$OUT" "$AAR"

build() { # name pkg goos goarch ext
  echo "==> building $1 ($3/$4)"
  GOOS=$3 GOARCH=$4 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$OUT/$1$5" "./cmd/$2"
}

build p2p-server server linux amd64 "-linux"
build p2p-client client linux amd64 "-linux"
build p2p-server server windows amd64 ".exe"
build p2p-client client windows amd64 ".exe"

if [ -n "${ANDROID_HOME:-}" ] && [ -n "${ANDROID_NDK_HOME:-}" ]; then
  echo "==> building Android AAR"
  gomobile bind -target=android -androidapi 21 -o "$AAR/p2p.aar" ./sdk
else
  echo "==> SKIPPING Android AAR (set ANDROID_HOME and ANDROID_NDK_HOME)"
fi

echo "==> done"
