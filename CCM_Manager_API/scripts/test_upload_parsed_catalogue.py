import json
import os
import requests

def upload_catalogue():
    filename = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "data", "vm_risk_metrics.json")
    )
    url = "http://localhost:5001/upload_parsed_catalogue"
    
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            try:
                data = json.load(f)
                response = requests.post(url, json=data)
                print(f"Status Code: {response.status_code}")
                print(f"Response: {response.text}")
            except Exception as e:
                print(f"Error: {e}")
    else:
        print(f"Error: File not found: {filename}")

if __name__ == "__main__":
    upload_catalogue()
