#!/bin/bash

# Activate the virtual environment
source "$(dirname "$0")/myenv/bin/activate"

# Variables
OUTPUT_DIR="./sboms"
FILE_PATH="$1"
TIMESTAMP="$2"

if [[ -z "$TIMESTAMP" ]]; then
    TIMESTAMP=$(date +%Y%m%d%H%M%S)
fi

OUTPUT_FILE="$OUTPUT_DIR/sbom_$TIMESTAMP.json"

# Ensure the output directory exists
mkdir -p "$OUTPUT_DIR"

# Check if the input file is provided
if [[ -z "$FILE_PATH" ]]; then
    echo "No input file provided. Usage: $0 <path_to_requirements.txt> [timestamp]"
    exit 1
fi

# Check if the input file exists
if [[ ! -f "$FILE_PATH" ]]; then
    echo "Input file does not exist: $FILE_PATH"
    exit 1
fi

echo "Input file: $FILE_PATH"

# Generate the SBOM using CycloneDX
echo "Running: cyclonedx-py requirements -o \"$OUTPUT_FILE\" \"$FILE_PATH\""
cyclonedx-py requirements -o "$OUTPUT_FILE" "$FILE_PATH"

# Check if SBOM generation was successful
if [[ $? -ne 0 ]]; then
    echo "Failed to generate SBOM at $OUTPUT_FILE"
    exit 1
fi

# Change file permissions to make it readable for everyone
chmod 644 "$OUTPUT_FILE"  # Add this line to set read permissions for all

if [[ ! -f "$OUTPUT_FILE" ]]; then
    echo "SBOM file was not created: $OUTPUT_FILE"
    exit 1
fi

echo "SBOM generated at: $OUTPUT_FILE"