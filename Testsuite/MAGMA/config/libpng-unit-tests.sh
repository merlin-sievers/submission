#!/bin/bash
echo "Start"




# Base directory paths
BASE_DIR="/home/jaenich/Magma/Patched/separate/Compiler"
DEST_DIR=".libs"

# List of optimization levels
LEVELS=("O1" "O2" "O3")
C=0
# Loop through each LEVEL
for LEVEL in "${LEVELS[@]}"; do

  # Find directories that match PNG* in the current LEVEL directory
  for DIR in "$BASE_DIR$LEVEL"/PNG*; do
    # Check if the directory exists
    C=$(($C + 1))
    if [ -d "$DIR" ]; then
      # Copy the file libpng16.so.16.38.0_patched to the destination directory
      cp "$DIR/libpng16_$LEVEL.so.16.38.0_patched" "$DEST_DIR/libpng16.so.16.38.0_patched"
    else
      echo "Directory $DIR does not exist."

    fi
   QEMU_LD_PREFIX=/usr/arm-linux-gnueabihf/ LD_LIBRARY_PATH=/usr/local/lib/zlib/lib make test
   cp test-suite.log test-suite-"$LEVEL"-"$C".log
   done
done
