#!/bin/sh
set -eu
fuzz_seconds=${FIXER_FUZZ_SECONDS:-60}
case "$fuzz_seconds" in
    ''|*[!0-9]*) echo 'FIXER_FUZZ_SECONDS must be an integer from 1 to 3600' >&2; exit 2 ;;
esac
if [ "$fuzz_seconds" -lt 1 ] || [ "$fuzz_seconds" -gt 3600 ]; then
    echo 'FIXER_FUZZ_SECONDS must be an integer from 1 to 3600' >&2
    exit 2
fi
cmake -S /source -B /build/gcc -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON -DFIXER_REQUIRE_NETWORK_TESTS=ON
cmake --build /build/gcc --parallel 4
ctest --test-dir /build/gcc --output-on-failure
if [ -n "${FIXER_SPACE_TEST_ROOT:-}" ]; then
    /build/gcc/fixer_tests --transaction-space "$FIXER_SPACE_TEST_ROOT"
fi
if [ -f /source/.deps/widevine-linux.crx3 ]; then
    /build/gcc/fixer_tests --verify-package /source/.deps/widevine-linux.crx3
fi
cmake -S /source -B /build/clang -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON -DFIXER_REQUIRE_NETWORK_TESTS=ON \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DFIXER_SANITIZERS=ON -DFIXER_FUZZING=ON
cmake --build /build/clang --parallel 4
ctest --test-dir /build/clang --output-on-failure
if [ -n "${FIXER_SPACE_TEST_ROOT:-}" ]; then
    /build/clang/fixer_tests --transaction-space "$FIXER_SPACE_TEST_ROOT"
fi
mkdir -p /build/fuzz-corpus
python3 /source/tools/seed_fuzz.py /build/fuzz-corpus
if ! /build/clang/fixer_fuzz /build/fuzz-corpus -max_total_time="$fuzz_seconds" -timeout=5 -rss_limit_mb=512 \
    -max_len=65536 -print_final_stats=1 > /build/fuzz.log 2>&1; then
    cat /build/fuzz.log
    exit 1
fi
tail -n 5 /build/fuzz.log
