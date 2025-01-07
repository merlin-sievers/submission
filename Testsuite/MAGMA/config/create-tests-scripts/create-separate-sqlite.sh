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
        if [[ "$name" == "SQL001" || "$name" == "SQL002" || "$name" == "SQL003" || "$name" == "SQL005" || \
        "$name" == "SQL006" || "$name" == "SQL007" || "$name" == "SQL008" || "$name" == "SQL009" || \
        "$name" == "SQL010" || "$name" == "SQL011" || "$name" == "SQL012" || "$name" == "SQL013" || \
        "$name" == "SQL014" || "$name" == "SQL015" || "$name" == "SQL018" || "$name" == "SQL020" ]]; then
        echo "Applying $patch"

        # Apply the patch, replacing the %MAGMA_BUG% placeholder with the actual base name
        sed "s/%MAGMA_BUG%/$name/g" "$patch" | patch -p1 -d "$TARGET"

        echo "$patch applied"

    # Create a new directory in the TARGET directory
        new_dir=$name
        mkdir -p "$TARGET/$new_dir/fixed" || { echo "Error: Unable to create directory $TARGET/$new_dir/fixed"; exit 1; }

        mkdir -p "$TARGET/$new_dir/vuln_O3" || { echo "Error: Unable to create directory $TARGET/$new_dir/vuln"; exit 1; }


    # Change directory to the new directory in the TARGET directory

        cd "$TARGET" || { echo "Error: Unable to change directory to $TARGET"; exit 1; }

        make clean > /dev/null
            

        make > /dev/null

        make install

        git reset --hard HEAD

    # Optionally, return to the original directory
        cd - > /dev/null
    fi

done


echo "Script completed successfully!"