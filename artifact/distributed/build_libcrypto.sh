set -eu
cd "$(dirname "$0")"
version=3.5.9
source="https://github.com/openssl/openssl/releases/download/openssl-$version/openssl-$version.tar.gz"
archive="openssl-$version.tar.gz"
if [ ! -f "openssl-$version/libcrypto.so.3" ]; then
    curl --fail --silent --show-error --location --connect-timeout 20 --max-time 180 --retry 2 "$source" --output "$archive"
    curl --fail --silent --show-error --location --connect-timeout 20 --max-time 60 --retry 2 "$source.sha256" --output "$archive.sha256"
    expected=$(awk 'NR==1 {print $1}' "$archive.sha256")
    [ "${#expected}" -eq 64 ]
    printf '%s  %s\n' "$expected" "$archive" | sha256sum --check --status
    tar -xzf "$archive"
    cd "openssl-$version"
    ./config shared no-tests no-docs --libdir=lib
    make -j 2 build_generated
    make -j 2 libcrypto.so.3
fi
printf 'libcrypto build complete\n'
