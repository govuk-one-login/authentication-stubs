#!/usr/bin/env bash
set -eu

echo "Building di-ipv-credential-issuer-stub"
./gradlew clean build -x test

echo "Starting di-ipv-credential-issuer-stub"
./gradlew run