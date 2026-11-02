#!/usr/bin/env bash
# Pull stored ciphertext from the server and decrypt it locally.
# Usage: tools/pull-and-decrypt.sh <ssh-host> <remote-data-dir> <local-dir>
set -euo pipefail
host="$1"; remote="$2"; local_dir="$3"
identity="${PLEKTRA_TRAINING_IDENTITY:-$HOME/.config/plektra-typing-training/identity.txt}"
mkdir -p "$local_dir/encrypted" "$local_dir/sessions"
rsync -a --include='*/' --include='*.age' --include='*.json' --exclude='*' "$host:$remote/sessions/" "$local_dir/encrypted/"
find "$local_dir/encrypted" -name '*.age' | while read -r file; do
  target="$local_dir/sessions/$(basename "${file%.age}").json"
  [ -e "$target" ] && continue
  age -d -i "$identity" "$file" | gunzip > "$target.tmp"
  # The id is the client's claimed SHA-256 of the plaintext; the server cannot check it.
  if [ "$(shasum -a 256 "$target.tmp" | cut -c1-64)" != "$(basename "${file%.age}")" ]; then
    echo "hash mismatch, kept aside: $target.mismatch" >&2
    mv "$target.tmp" "$target.mismatch"
    continue
  fi
  mv "$target.tmp" "$target"
done
echo "Decrypted sessions in $local_dir/sessions"
