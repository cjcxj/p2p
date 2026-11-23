#!/usr/bin/env bash
# Builds the unified P2P CLI (plus p2p-server/p2p-client compatibility
# copies) for Linux and Windows, and the Android AAR.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/bin"
AAR="$ROOT/android"
mkdir -p "$OUT" "$AAR"

build() { # name pkg goos goarch ext
  echo "==> building $1 ($3/$4)"
  GOOS=$3 GOARCH=$4 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$OUT/$1$5" "./cmd/$2"
}

# One unified binary per platform; legacy names are copies of the same
# executable. cmd/p2p dispatches on argv[0], so p2p-server / p2p-client keep
# their old behavior.
build p2p p2p linux amd64 "-linux"
cp "$OUT/p2p-linux" "$OUT/p2p-server-linux"
cp "$OUT/p2p-linux" "$OUT/p2p-client-linux"
build p2p p2p windows amd64 ".exe"
cp "$OUT/p2p.exe" "$OUT/p2p-server.exe"
cp "$OUT/p2p.exe" "$OUT/p2p-client.exe"

if [ -n "${ANDROID_HOME:-}" ] && [ -n "${ANDROID_NDK_HOME:-}" ]; then
  echo "==> building Android AAR"
  gomobile bind -target=android -androidapi 21 -o "$AAR/p2p.aar" ./sdk
  DEMO_LIBS="$ROOT/android-demo/app/libs"
  mkdir -p "$DEMO_LIBS"
  cp "$AAR/p2p.aar" "$DEMO_LIBS/p2p.aar"
  echo "    -> $DEMO_LIBS/p2p.aar"
else
  echo "==> SKIPPING Android AAR (set ANDROID_HOME and ANDROID_NDK_HOME)"
fi

echo "==> done"
