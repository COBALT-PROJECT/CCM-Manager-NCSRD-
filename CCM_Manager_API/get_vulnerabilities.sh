#!/bin/bash

# Load environment variables
export $(grep -v '^#' .env | xargs)

# Confirm that required variables are set
if [ -z "$DEPENDENCY_TRACK_URL" ] || [ -z "$API_KEY" ]; then
    echo "DEPENDENCY_TRACK_URL or API_KEY is not set. Check your .env file."
    exit 1
fi
echo "Dependency Track URL: $DEPENDENCY_TRACK_URL"

# Check if the correct number of arguments is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: ./get_vulnerabilities.sh <project_uuid>"
    exit 1
fi

# Retrieve the command-line argument
project_uuid="$1"
url="$DEPENDENCY_TRACK_URL/api/v1/bom/cyclonedx/project/$project_uuid"
params="?format=json&variant=withVulnerabilities&download=true"

# Send the GET request
response=$(curl -s -o response.json -w "%{http_code}" -X GET "$url$params" \
    -H "Accept: application/json, text/plain, */*" \
    -H "X-Api-Key: $API_KEY" \
    -H "Content-Type: application/json")

# Handle response codes
case "$response" in
    200)
        echo "Response data received successfully."
        
        # Create the sboms directory if it doesn't exist
        output_dir="./sboms"
        mkdir -p "$output_dir"

        # Generate the filename with a timestamp
        timestamp=$(date +%Y%m%d_%H%M%S)
        filename="vex_$timestamp.json"
        file_path="$output_dir/$filename"

        # Save the response data as a JSON file
        cp response.json "$file_path"
        echo "Data saved to $file_path"
        rm response.json  # Clean up the temporary file
        ;;
        
    404)
        echo "Error: Project not found (404). Check the project_uuid or server URL."
        rm response.json  # Clean up if it was created
        exit 1
        ;;
        
    401)
        echo "Error: Unauthorized (401). Check the API_KEY."
        rm response.json  # Clean up if it was created
        exit 1
        ;;
        
    *)
        echo "Error: Received unexpected status code $response"
        if [ -f response.json ]; then
            cat response.json
        fi
        rm response.json  # Clean up if it was created
        exit 1
        ;;
esac
