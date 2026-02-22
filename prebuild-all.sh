#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> Building prebuilds for linux/amd64 and linux/arm64..."
echo ""

rm -rf prebuilds

echo "--- Building linux/amd64 ---"
docker buildx build \
    --platform linux/amd64 \
    --output type=local,dest=./out-amd64 \
    -f ./Dockerfile \
    .

echo "--- Building linux/arm64 ---"
docker buildx build \
    --platform linux/arm64 \
    --output type=local,dest=./out-arm64 \
    -f ./Dockerfile \
    .

mkdir -p prebuilds
cp -r out-amd64/prebuilds/* prebuilds/
cp -r out-arm64/prebuilds/* prebuilds/

rm -rf out-amd64 out-arm64

echo ""
echo "==> Done! Prebuilds:"
find prebuilds -type f
echo ""
echo "Structure should look like:"
echo "  prebuilds/linux-x64/sockdestroy.node"
echo "  prebuilds/linux-arm64/sockdestroy.node"
