#!/bin/bash

FILES_TO_CHECK="Dockerfile setup.py setup.cfg docker-compose.yml"
OUTPUT_TEMPLATE="files_checksum"
OUTPUT_FILE=${OUTPUT_TEMPLATE}.txt

echo -n > ${OUTPUT_FILE}
for file in ${FILES_TO_CHECK}; do
    SHA256=$(sha256sum ${file})
    echo ${SHA256} >> ${OUTPUT_FILE}
done
