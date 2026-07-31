#!/bin/sh
# Build and package Hans with the Cygwin C++ runtimes embedded in hans.exe.
# Cygwin itself cannot be linked statically, so cygwin1.dll is intentionally
# the only non-system DLL shipped next to the executable.

set -eu

LABEL="${1:?usage: build-windows-cygwin.sh <architecture-label>}"

if [ -n "${GITHUB_WORKSPACE:-}" ]; then
    cd "$(cygpath -u "$GITHUB_WORKSPACE")"
fi

make \
    CPPFLAGS='-c -g -std=gnu++98 -fpermissive -Wall -Wextra -Wno-sign-compare -Wno-missing-field-initializers -DWIN32' \
    LDFLAGS='-static'

# Cygwin creates hans.exe even though the Makefile target is named "hans".
if [ -f hans.exe ] && [ ! -f hans ]; then
    cp hans.exe hans
fi

chmod +x scripts/test-hans.sh
BIN=hans
[ -f hans.exe ] && BIN=hans.exe
./scripts/test-hans.sh "./$BIN" "windows-$LABEL-cygwin"

# Keep symbols in the build-time test binary, then strip the exact executable
# that will be copied into the release package and isolated-test it later.
strip -s hans.exe

# Fail if a compiler/runtime package becomes dynamically linked again.
# Windows system DLLs are allowed; the sole Cygwin import must be cygwin1.dll.
cyg_imports="$({
    objdump -p hans.exe |
        awk '/DLL Name:/ { name=tolower($3); if (name ~ /^cyg.*\.dll$/) print name }'
} | sort -u)"

if [ "$cyg_imports" != "cygwin1.dll" ]; then
    echo "FAIL [windows-$LABEL-cygwin]: unexpected dynamic Cygwin imports:" >&2
    printf '%s\n' "$cyg_imports" >&2
    exit 1
fi

PACKAGE_DIR="dist/windows-$LABEL"
mkdir -p "$PACKAGE_DIR"
cp hans.exe /bin/cygwin1.dll "$PACKAGE_DIR/"

echo "Packaged Windows $LABEL files:"
ls -la "$PACKAGE_DIR/hans.exe" "$PACKAGE_DIR/cygwin1.dll"
echo "PE imports:"
objdump -p hans.exe | awk '/DLL Name:/ { print $3 }'
