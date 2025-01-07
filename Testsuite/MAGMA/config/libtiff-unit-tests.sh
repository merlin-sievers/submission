#!/bin/bash
echo "Start"




# Base directory paths
BASE_DIR="/home/jaenich/Magma/Patched/separate/Compiler"
DEST_DIR="libtiff/.libs"

# List of optimization levels
LEVELS=("O1"  "O3" "O2")
C=0
# Loop through each LEVEL
for LEVEL in "${LEVELS[@]}"; do

  # Find directories that match PNG* in the current LEVEL directory
  for DIR in "$BASE_DIR$LEVEL"/TIF*; do
    # Check if the directory exists
    C=$(($C + 1))
    HELP=$(basename $DIR)
    if [ -d "$DIR" ]; then
      # Copy the file libpng16.so.16.38.0_patched to the destination directory
      cp "$DIR"/TIF*"_${LEVEL}_libtiff.so.5.7.0_patched" "$DEST_DIR/libtiff.so.5.7.0"
    else
      echo "Directory $DIR does not exist."

    fi
   QEMU_LD_PREFIX=/usr/arm-linux-gnueabihf/ LD_LIBRARY_PATH=/usr/local/lib/zlib/lib/:/home/jaenich/Libraries/libjpeg-turbo-2.0.3/ make check
   cp test/test-suite.log test-suite-${LEVEL}-$HELP.log
   done
done