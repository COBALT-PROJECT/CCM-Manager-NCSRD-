#!/bin/bash

# Load environment variables safely
set -o allexport
source .env
set +o allexport

# Check if the correct number of arguments is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: ./create_project.sh <bom_file_path>"
    exit 1
fi

# Retrieve the BOM file path from the command-line argument
bom_file_path="$1"

# Define the URL and headers
url="$DEPENDENCY_TRACK_URL/api/v1/project"
api_key="$API_KEY"

# Generate a unique project name using the current timestamp
unique_project_name="test_$(date +%s)"

# Define the JSON payload with the unique project name
data=$(jq -n \
    --arg name "$unique_project_name" \
    --arg description "This is an example project." \
    --arg version "1.0" \
    '{name: $name, description: $description, version: $version, active: true, isLatest: true}')

# Log the request details
echo "Sending request to $url"
echo "Payload: $data"

# Perform the PUT request
response=$(curl -s -o response.json -w "%{http_code}" -X PUT "$url" \
    -H "accept: application/json" \
    -H "X-Api-Key: $api_key" \
    -H "Content-Type: application/json" \
    -d "$data")

# Check the status code and log details
if [ "$response" -eq 200 ] || [ "$response" -eq 201 ]; then
    project_uuid=$(jq -r '.uuid' response.json)
    project_name=$(jq -r '.name' response.json)
    project_version=$(jq -r '.version' response.json)

    echo "Project UUID: $project_uuid"
    echo "Project Name: $project_name"
    echo "Project Version: $project_version"

    # Call upload_sbom.sh with the extracted values and BOM file path
    ./upload_sbom.sh "$project_uuid" "$project_name" "$project_version" "$bom_file_path"
else
    echo "Status Code: $response" >&2
    if [ -f response.json ]; then
        cat response.json >&2
    else
        echo "response.json file was not created." >&2
    fi
    error_message=$(jq -r '.message // "Unknown error occurred."' response.json 2>/dev/null || echo "Unknown error occurred.")
    echo "Error: $error_message" >&2
    exit 1  # Explicitly exit with an error code
fi
