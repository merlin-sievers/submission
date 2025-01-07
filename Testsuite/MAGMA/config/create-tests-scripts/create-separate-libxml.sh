#!/bin/bash

# Define the PATCH and TARGET directories
#PATCH="path/to/patch"
#TARGET="path/to/target"


# Change directory to the PATCH directory
cd "$PATCH" || { echo "Error: Unable to change directory to $PATCH"; exit 1; }

# Do something in the PATCH directory (e.g., apply patches)
# Example: apply all .patch files
find -name "*.patch" | \
while read patch; do 
    echo "Applying $patch" 
    name=${patch##*/} 
    name=${name%.patch}    
    # Check if the patch name is one of the specified ones
        if [[ "$name" == "SSL002" || "$name" == "SSL003" || "$name" == "SSL004" || "$name" == "SSL005" || \
        "$name" == "SSL006" || "$name" == "SSL007" || "$name" == "SSL009" || "$name" == "SSL010" || \
        "$name" == "SSL013" || "$name" == "SSL014" || "$name" == "SSL016" || "$name" == "SSL018" || \
        "$name" == "SSL019" || "$name" == "SSL020" ]];  then
        echo "Applying $patch"

        # Apply the patch, replacing the %MAGMA_BUG% placeholder with the actual base name
        sed "s/%MAGMA_BUG%/$name/g" "$patch" | patch -p1 -d "$TARGET"

        echo "$patch applied"


    # Create a new directory in the TARGET directory
        new_dir=$name
        mkdir -p "$TARGET/$new_dir/fixed" || { echo "Error: Unable to create directory $TARGET/$new_dir/fixed"; exit 1; }

        mkdir -p "$TARGET/$new_dir/vuln_O1" || { echo "Error: Unable to create directory $TARGET/$new_dir/vuln"; exit 1; }


    # Change directory to the new directory in the TARGET directory

        cd "$TARGET" || { echo "Error: Unable to change directory to $TARGET"; exit 1; }

        make clean > /dev/null
        ./config linux-generic32 --cross-compile-prefix=/usr/bin/arm-linux-gnueabihf- --debug enable-fuzz-libfuzzer enable-fuzz-afl disable-tests -DPEDANTIC  -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-module enable-tls1_3 enable-rc5 enable-md2 enable-ssl3 enable-ssl3-method enable-nextprotoneg enable-weak-ssl-ciphers -include /home/jaenich/Magma/magma/magma/src/canary.h -L/home/jaenich/Magma/magma/magma/src/ -DMAGMA_ENABLE_CANARIES -O1 -fno-sanitize=alignment --prefix="$TARGET/$new_dir/vuln_O1" > 


        make > /dev/null

        make install

        git reset --hard HEAD

    # Optionally, return to the original directory
        cd - > /dev/null
    fi

done


echo "Script completed successfully!"