import requests
import json

def fetch_and_display(endpoint_name, url):
    print(f"\n--- Fetching {endpoint_name} ---")
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            print(f"Successfully retrieved {len(data)} items from {endpoint_name}.")
            # Print just the first item to show the structure
            if data:
                print(f"Example {endpoint_name[:-1]} structure:")
                print(json.dumps(data[0], indent=2))
        else:
            print(f"Failed to retrieve {endpoint_name}. Status: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error connecting to {endpoint_name} endpoint: {e}")

def main():
    base_url = "http://localhost:5001"
    
    # Check all four endpoints
    fetch_and_display("Metrics", f"{base_url}/metrics")
    fetch_and_display("Risks", f"{base_url}/risks")
    fetch_and_display("Threats", f"{base_url}/threats")
    fetch_and_display("Controls", f"{base_url}/controls")

if __name__ == "__main__":
    main()
