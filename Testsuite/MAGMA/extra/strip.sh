#!/bin/bash

for dir in SSL0*/; do
  # Find all libcrypto.so.3 files in this folder
  mapfile -t files < <(find "$dir" -type f -name "libcrypto.so.3" 2>/dev/null)

  if [[ ${#files[@]} -eq 0 ]]; then
    echo "No libcrypto.so.3 found in $dir"
    continue
  fi

  for target in "${files[@]}"; do
    echo "Processing: $target"
    
    cp "$target.bak" "$target"
    # Make a backup
    cp "$target" "$target.bak"

    # Strip debug symbols
    arm-linux-gnueabihf-strip  --strip-debug "$target"

    echo "Stripped debug symbols from: $target"
  done
done

