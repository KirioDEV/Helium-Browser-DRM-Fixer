#!/bin/sh
set -eu
cmake -S /source -B /build/gcc -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build /build/gcc --parallel 4
ctest --test-dir /build/gcc --output-on-failure
if [ -f /source/.deps/widevine-linux.crx3 ]; then
    /build/gcc/fixer_tests --verify-package /source/.deps/widevine-linux.crx3
fi
cmake -S /source -B /build/clang -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DFIXER_SANITIZERS=ON -DFIXER_FUZZING=ON
cmake --build /build/clang --parallel 4
ctest --test-dir /build/clang --output-on-failure
mkdir -p /build/fuzz-corpus
python3 /source/tools/seed_fuzz.py /build/fuzz-corpus
if ! /build/clang/fixer_fuzz /build/fuzz-corpus -max_total_time=15 -timeout=5 -rss_limit_mb=512 \
    -max_len=65536 -print_final_stats=1 > /build/fuzz.log 2>&1; then
    cat /build/fuzz.log
    exit 1
fi
tail -n 5 /build/fuzz.log
