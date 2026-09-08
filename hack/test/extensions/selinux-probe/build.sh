#!/bin/sh
# Builds the selinux-probe test extension as an OCI layout, the form the imager reads with ociPath in its profile.
# Nothing is pushed. Usage: build.sh [output dir], default _out/selinux-probe.oci; PLATFORM=linux/arm64 by default.
set -e
cd "$(dirname "$0")"
OUT=${1:-$(git rev-parse --show-toplevel)/_out/selinux-probe.oci}
rm -rf "$OUT" && mkdir -p "$OUT"
docker buildx build --platform "${PLATFORM:-linux/arm64}" --output "type=oci,dest=-" . | tar -x -C "$OUT"
ls "$OUT"
