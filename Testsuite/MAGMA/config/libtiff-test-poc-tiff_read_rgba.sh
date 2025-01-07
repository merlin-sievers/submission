#!/bin/bash

# Set the input directory containing different input files
input_dir="/home/jaenich/Magma/Patched/Compiler"$LEVEL"/"$DIR"/"

# Set the AFL environment variables
export AFL_QEMU_DRIVER_NO_HOOK=1
export QEMU_LD_PREFIX=/usr/arm-linux-gnueabihf
export LD_LIBRARY_PATH=/home/jaenich/Libraries/libjpeg-turbo-2.0.3:/home/jaenich/Magma/magma/targets/libtiff/repo/vuln_"$LEVEL"/lib/:/usr/local/lib/zlib/lib/:/home/jaenich/Libraries/lib

# Set the path to the fuzzer binary
fuzzer_binary="./tiff_read_rgba_fuzzer"

# Loop through all input files matching PNG00*
echo "Start Testing ..."
for input_file in "${input_dir}"*AH0*; do
    # Check if the file exists and is readable
    if [ -r "$input_file" ]; then
        # Execute the fuzzer with the input file
        output=$(qemu-arm "$fuzzer_binary" < "$input_file" 2>&1)
        echo "$output"
        # Check if the output contains "REACHED" and "PNG"
        if [[ $output == *"REACHED"* && $output == *"E"* ]]; then
            echo "Output contains 'REACHED' and 'TIF':"
            echo "$output"
            export LD_LIBRARY_PATH=/home/jaenich/Libraries/libjpeg-turbo-2.0.3:/home/jaenich/Magma/Patched/separate/Compiler"$LEVEL"/"$DIR"/:/usr/local/lib/zlib/lib/:/home/jaenich/Libraries/lib
            output=$(qemu-arm "$fuzzer_binary" < "$input_file" 2>&1)
            echo "Output of patched version"
            echo "$output"

            export LD_LIBRARY_PATH=/home/jaenich/Libraries/libjpeg-turbo-2.0.3:/home/jaenich/Magma/magma/targets/libtiff/repo/fixed/lib:/usr/local/lib/zlib/lib/:/home/jaenich/Libraries/lib
            output=$(qemu-arm "$fuzzer_binary" < "$input_file" 2>&1)
            echo "Output of fixed version"
            echo "$output"
        fi
    else
        echo "Input file $input_file does not exist or is not readable"
    fi
done