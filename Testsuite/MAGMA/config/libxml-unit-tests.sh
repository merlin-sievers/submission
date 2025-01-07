#!/bin/bash
echo "Start"




# Base directory paths
BASE_DIR="/home/jaenich/Magma/Patched/separate/Compiler"
DEST_DIR=".libs/"

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
      cp "$DIR"/XML*"_${LEVEL}_libxml2.so.2.9.12_patched" "$DEST_DIR/libxml2.so.2.9.12"
    else
      echo "Directory $DIR does not exist."

    fi
   QEMU_LD_PREFIX=/usr/arm-linux-gnueabihf/ LD_LIBRARY_PATH=/home/jaenich/Libraries/libjpeg-turbo-2.0.3:/usr/local/lib/zlib/lib/:/home/jaenich/Libraries/lib make check > test-suite-${LEVEL}-$HELP.log
   done
done