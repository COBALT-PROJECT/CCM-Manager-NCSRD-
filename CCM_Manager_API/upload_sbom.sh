#!/bin/bash

# Load environment variables
export $(grep -v '^#' .env | xargs)

# Check if the correct number of arguments is provided
if [ "$#" -ne 4 ]; then
    echo "Usage: ./upload_sbom.sh <project_uuid> <project_name> <project_version> <bom_file_path>"
    exit 1
fi

# Retrieve the command-line arguments
project_uuid="$1"
project_name="$2"
project_version="$3"
bom_file_path="$4"

# Define the API endpoint and headers for BOM upload
upload_url="$DEPENDENCY_TRACK_URL/api/v1/bom"
api_key="$API_KEY"

# Validate BOM file and ensure it's JSON
if ! jq empty "$bom_file_path" >/dev/null 2>&1; then
    echo "Error: $bom_file_path is not valid JSON."
    exit 1
fi

# Send the BOM file as a multipart/form-data request
response=$(curl -s -o response.json -w "%{http_code}" -X POST "$upload_url" \
    -H "accept: application/json" \
    -H "X-Api-Key: $api_key" \
    -F "bom=@$bom_file_path;type=application/json" \
    -F "projectName=$project_name" \
    -F "project=$project_uuid" \
    -F "projectVersion=$project_version")

# Output the response status code and content
echo "Response Status Code: $response"
cat response.json

# Check for errors
if [ "$response" -ne 200 ]; then
    echo "Error Response Content: $(cat response.json)"
    exit 1
fi

# Parse the response JSON to extract the token, if available
token=$(jq -r '.token // empty' response.json)

if [ -n "$token" ]; then
    echo "Received token: $token"
    # Call get_vulnerabilities.sh and pass the project_uuid as an argument
    ./get_vulnerabilities.sh "$project_uuid"
else
    echo "No token found in the response."
fi
