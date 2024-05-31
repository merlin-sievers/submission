#!/bin/bash

# Define the PATCH and TARGET directories
#PATCH="path/to/patch"
#TARGET="path/to/target"


# Change directory to the PATCH directory
cd "$PATCH" || { echo "Error: Unable to change directory to $PATCH"; exit 1; }

# Do something in the PATCH directory (e.g., apply patches)
# Example: apply all .patch files
find "$PATCH/bugs" "$PATCH/setup" -name "*.patch" | \
while read patch; do 
    echo "Applying $patch" 
    name=${patch##*/} 
    name=${name%.patch} 
    sed "s/%MAGMA_BUG%/$name/g" "$patch" | patch -p1 -d "$TARGET"
    
    echo "$patch apllied"

    # Create a new directory in the TARGET directory
    new_dir=$name
    mkdir -p "$TARGET$new_dir/fixed" || { echo "Error: Unable to create directory $TARGET/$new_dir/fixed"; exit 1; }

    mkdir -p "$TARGET$new_dir/vuln" || { echo "Error: Unable to create directory $TARGET/$new_dir/vuln"; exit 1; }


    # Change directory to the new directory in the TARGET directory
    cd "$TARGET" || { echo "Error: Unable to change directory to $TARGET"; exit 1; }
##
#    make clean > /dev/null
#    # Do something in the new directory (e.g., compile code)
#    # Example: compile source files
#    ./configure --host=arm-linux-gnueabihf CC=arm-linux-gnueabihf-gcc AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib CPPFLAGS='-I/usr/local/lib/zlib/include' LDFLAGS='-L/usr/local/lib/zlib/lib' CFLAGS='-DMAGMA_ENABLE_FIXES -g -O2' --prefix="$TARGET/$new_dir/fixed" --enable-shared > /dev/null
#    make > /dev/null
#
#    make install > /dev/null
#
    make clean > /dev/null
     
     ./configure --host=arm-linux-gnueabihf CC=arm-linux-gnueabihf-gcc AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib CPPFLAGS='-I/usr/local/lib/zlib/include' LDFLAGS='-L/usr/local/lib/zlib/lib -L/home/jaenich/Magma/magma/magma/src/' CFLAGS='--include /home/jaenich/Magma/magma/magma/src/canary_lar.h -DMAGMA_ENABLE_CANARIES -g -O2' LIBS='-l:magma.o' --prefix="$TARGET/$new_dir/vuln" --enable-shared > /dev/null

    make > /dev/null

    make install > /dev/null

    git reset --hard HEAD

    # Optionally, return to the original directory
    cd - > /dev/null

done


echo "Script completed successfully!"
