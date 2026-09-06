#!/usr/bin/env bash
# Assembles a self-contained deploy directory per Lambda function by copying
# the shared lambda/common/ helpers alongside each function's handler.py.
# Run this before `terraform apply`.
set -euo pipefail

cd "$(dirname "$0")"
rm -rf build
mkdir -p build

for fn in detect_console_login detect_iam_user_created detect_sg_open_internet; do
  mkdir -p "build/${fn}"
  cp "lambda/${fn}/handler.py" "build/${fn}/"
  cp lambda/common/*.py "build/${fn}/"
done

echo "Build directories ready under ./build — run 'terraform apply' from ./terraform next."
