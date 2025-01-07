#!/bin/bash

# Set the input directory containing different input files
input_dir="/home/jaenich/Magma/Patched/Compiler"$LEVEL"/"$DIR"/"

# Set the AFL environment variables
export QEMU_LD_PREFIX=/usr/arm-linux-gnueabihf
export LD_LIBRARY_PATH=/home/jaenich/Libraries/libjpeg-turbo-2.0.3:/home/jaenich/Magma/magma/targets/libtiff/repo/vuln/lib/:/usr/local/lib/zlib/lib/:/home/jaenich/Libraries/lib

# Set the path to the fuzzer binary
fuzzer_binary="tools/.libs/tiffcp"

# Loop through all input files matching PNG00*
echo "Start Testing ..."
for input_file in "${input_dir}"*AH0*; do
    rm tmp.out
        # Check if the file exists and is readable
    if [ -r "$input_file" ]; then
        # Execute the fuzzer with the input file
        output=$("$fuzzer_binary" "$input_file" tmp.out 2>&1)
        # Check if the output contains "REACHED" and "PNG"
        echo "$output"
        if [[ $output == *"REACHED"* && $output == *"E"* ]]; then
            echo "Output contains 'REACHED' and 'TIF':"
            echo "$output"
            export LD_LIBRARY_PATH=/home/jaenich/Libraries/libjpeg-turbo-2.0.3:/home/jaenich/Magma/Patched/Compiler"$LEVEL"/"$DIR"/:/usr/local/lib/zlib/lib/:/home/jaenich/Libraries/lib
            output=$("$fuzzer_binary" "$input_file" tmp.out 2>&1)
            echo "Output of patched version"
            echo "$output"

            export LD_LIBRARY_PATH=/home/jaenich/Libraries/libjpeg-turbo-2.0.3:/home/jaenich/Magma/magma/targets/libtiff/repo/fixed/lib:/usr/local/lib/zlib/lib/:/home/jaenich/Libraries/lib
            output=$("$fuzzer_binary" "$input_file" tmp.out 2>&1)
            echo "Output of fixed version"
            echo "$output"
        fi
    else
        echo "Input file $input_file does not exist or is not readable"
    fi
done