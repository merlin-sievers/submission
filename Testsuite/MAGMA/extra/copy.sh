#!/bin/bash

# SSH details
USER="jaenich"
HOST="maewo.plai.ifi.lmu.de"
DEST_BASE="/home/jaenich/Magma/Patched/separate"

# Loop over SSL002 to SSL020
for SSL_NUM in $(seq -f "SSL%03g" 2 20); do
    # Loop over O1, O2, O3
    for OPT_LEVEL in O1 O2 O3; do
        # Loop over both libcrypto and libssl
        for LIB in libcrypto libssl; do
            FILE="${SSL_NUM}_${OPT_LEVEL}_${LIB}.so.3_patched"
            DEST_DIR="${DEST_BASE}/Compiler${OPT_LEVEL}/${SSL_NUM}"

            # Check if the file exists before uploading
            if [[ -f "$FILE" ]]; then
                echo "Uploading $FILE to $HOST:$DEST_DIR/"
                scp "$FILE" "${USER}@${HOST}:${DEST_DIR}/"
            else
                echo "Skipping $FILE (not found)"
            fi
        done
    done
done

echo "All files uploaded successfully!"

