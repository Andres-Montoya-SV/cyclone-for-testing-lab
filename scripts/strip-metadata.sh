#!/usr/bin/env bash
# Strip macOS extended attributes and junk metadata from the working tree.
# Note: recent macOS versions may re-apply com.apple.provenance locally;
# Git does not store xattrs, so commits pushed to GitHub stay clean.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

echo "Removing .DS_Store and AppleDouble files..."
find . -name '.DS_Store' -delete
find . -name '._*' -delete
if command -v dot_clean >/dev/null 2>&1; then
    dot_clean -m .
fi

echo "Clearing extended attributes..."
find . \( -type f -o -type d \) ! -path './.git/*' -print0 | while IFS= read -r -d '' path; do
    xattr -c "$path" 2>/dev/null || true
done

echo "Rewriting text files without xattrs (cp -X)..."
find . -type f \
    ! -path './.git/*' \
    \( -name '*.cpp' -o -name '*.h' -o -name '*.md' -o -name '*.yml' -o -name 'Makefile' \
       -o -name '.gitignore' -o -name '.gitattributes' -o -name '.gitkeep' -o -name 'LICENSE' \
       -o -name '*.txt' -o -name '*.sh' \) \
    -print0 | while IFS= read -r -d '' file; do
    tmp="${file}.__strip__"
    cp -X "$file" "$tmp"
    mv "$tmp" "$file"
done

echo "Done. Sample check:"
ls -la@ README.md 2>/dev/null || true
echo "If com.apple.provenance still appears, macOS re-added it locally; git commits ignore xattrs."
