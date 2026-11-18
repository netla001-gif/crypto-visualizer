#!/bin/sh
# index.html의 <script id="core"> 계산 함수를 표준 벡터·OpenSSL과 대조하는 테스트.
# 필요: node, openssl(3.x, legacy provider — DES/SEED), xxd
# 사용: sh tests/run.sh
set -e
cd "$(dirname "$0")/.."
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0
for t in test mac emv emvlen pin arqc script txn tlv visa; do
  out=$(node "tests/$t.mjs" index.html "$TMP" 2>&1 | tail -1) || true
  case "$out" in *"ALL OK"*|*"COMBOS OK"*) echo "PASS $t: $out";; *) echo "FAIL $t: $out"; fail=1;; esac
done
exit $fail
