#!/bin/bash

# Set the input directory containing different input files
input_dir="/home/jaenich/Magma/Patched/separate/Compiler"$LEVEL"/"$DIR"/"

# Set the AFL environment variables
export AFL_QEMU_DRIVER_NO_HOOK=1
export QEMU_LD_PREFIX=/usr/arm-linux-gnueabihf
export LD_LIBRARY_PATH=/home/jaenich/Magma/magma/targets/libpng/libpng/repo/"$DIR"/vuln_"$LEVEL"/lib:/usr/local/lib/zlib/lib/

# Set the path to the fuzzer binary
fuzzer_binary="./libpng_read_fuzzer"

# Loop through all input files matching PNG00*
echo "Start Testing ..."
for input_file in "${input_dir}"*AH00*; do
    # Check if the file exists and is readable
    if [ -r "$input_file" ]; then
        # Execute the fuzzer with the input file
        export LD_LIBRARY_PATH=/home/jaenich/Magma/magma/targets/libpng/libpng/repo/vuln_O3/lib:/usr/local/lib/zlib/lib/
        output=$(qemu-arm "$fuzzer_binary" < "$input_file" 2>&1)
        # Check if the output contains "REACHED" and "PNG"
        echo "$output"
        if [[ $output == *"REACHED"* && $output == *"PNG0"* ]]; then
            echo "Output contains 'REACHED' and 'PNG':"
            echo "$output"
            export LD_LIBRARY_PATH=/home/jaenich/Magma/Patched/separate/Compiler"$LEVEL"/"$DIR"/:/usr/local/lib/zlib/lib/
            output=$(qemu-arm "$fuzzer_binary" < "$input_file" 2>&1)
            echo "Output of patched version"
            echo "$output"

            export LD_LIBRARY_PATH=/home/jaenich/Magma/magma/targets/libpng/libpng/repo/"$DIR"/fixed/lib:/usr/local/lib/zlib/lib/
            output=$(qemu-arm "$fuzzer_binary" < "$input_file" 2>&1)
            echo "Output of fixed version"
            echo "$output"
"test-patch.sh" 40L, 1715B                                  20,84-91   Anfang
# Set the input directory containing different input files
input_dir="/home/jaenich/Magma/Patched/separate/Compiler"$LEVEL"/"$DIR"/"

# Set the AFL environment variables
export AFL_QEMU_DRIVER_NO_HOOK=1
export QEMU_LD_PREFIX=/usr/arm-linux-gnueabihf
export LD_LIBRARY_PATH=/home/jaenich/Magma/magma/targets/libpng/libpng/repo/"$DIR"/vuln_"$LEVEL"/lib:/usr/local/lib/zlib/lib/

# Set the path to the fuzzer binary
fuzzer_binary="./libpng_read_fuzzer"

# Loop through all input files matching PNG00*
echo "Start Testing ..."
for input_file in "${input_dir}"*AH00*; do
    # Check if the file exists and is readable
    if [ -r "$input_file" ]; then
        # Execute the fuzzer with the input file
        export LD_LIBRARY_PATH=/home/jaenich/Magma/magma/targets/libpng/libpng/repo/vuln_O3/lib:/usr/local/lib/zlib/lib/
        output=$(qemu-arm "$fuzzer_binary" < "$input_file" 2>&1)
        # Check if the output contains "REACHED" and "PNG"
        echo "$output"
        if [[ $output == *"REACHED"* && $output == *"PNG0"* ]]; then
            echo "Output contains 'REACHED' and 'PNG':"
            echo "$output"
            export LD_LIBRARY_PATH=/home/jaenich/Magma/Patched/separate/Compiler"$LEVEL"/"$DIR"/:/usr/local/lib/zlib/lib/
            output=$(qemu-arm "$fuzzer_binary" < "$input_file" 2>&1)
            echo "Output of patched version"
            echo "$output"

            export LD_LIBRARY_PATH=/home/jaenich/Magma/magma/targets/libpng/libpng/repo/"$DIR"/fixed/lib:/usr/local/lib/zlib/lib/
            output=$(qemu-arm "$fuzzer_binary" < "$input_file" 2>&1)
            echo "Output of fixed version"
            echo "$output"
        fi
    else
        echo "Input file $input_file does not exist or is not readable"
    fi
done