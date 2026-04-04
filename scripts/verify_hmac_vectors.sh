#!/usr/bin/env bash
set -euo pipefail

check_hmac() {
	local digest=$1
	local case_name=$2
	local key=$3
	local message=$4
	local expected=$5
	local actual

	actual=$(printf '%s' "$message" | openssl dgst "-$digest" -hmac "$key")
	actual=${actual##*= }

	if [[ "$actual" != "$expected" ]]; then
		printf 'FAIL %s (%s)\n' "$digest" "$case_name" >&2
		printf 'expected: %s\n' "$expected" >&2
		printf 'actual:   %s\n' "$actual" >&2
		return 1
	fi

	printf 'ok   %s (%s)\n' "$digest" "$case_name"
}

quick_message='The quick brown fox jumps over the lazy dog'
long_key=$(printf 'a%.0s' {1..200})

check_hmac sha1 "quick-fox" "key" "$quick_message" "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
check_hmac sha256 "quick-fox" "key" "$quick_message" "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
check_hmac sha512 "quick-fox" "key" "$quick_message" "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"

check_hmac sha1 "empty-message" "key" "" "f42bb0eeb018ebbd4597ae7213711ec60760843f"
check_hmac sha256 "empty-message" "key" "" "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0"
check_hmac sha512 "empty-message" "key" "" "84fa5aa0279bbc473267d05a53ea03310a987cecc4c1535ff29b6d76b8f1444a728df3aadb89d4a9a6709e1998f373566e8f824a8ca93b1821f0b69bc2a2f65e"

check_hmac sha1 "long-key" "$long_key" "Hash Playground HMAC" "85639dc5e3ddac212dece5229bad1e85df46c4c4"
check_hmac sha256 "long-key" "$long_key" "Hash Playground HMAC" "639c387a6d2f6c4247d0eb8f7ef71966692cac1cb457e059e1e7e892c4c0397b"
check_hmac sha512 "long-key" "$long_key" "Hash Playground HMAC" "ac3ed36a7b8e0148df7463013f1ba0498824efb700d7ebc17eb4359b80e2b9425994551714f2da55037c31cc33fc3a386529748fe4a50ca400c38619adaa42e2"

printf 'HMAC host vectors passed.\n'
