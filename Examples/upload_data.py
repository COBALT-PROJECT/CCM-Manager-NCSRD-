import json
import os
from pymongo import MongoClient
from dotenv import load_dotenv

# 1. Setup Database Connection
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client.mydatabase
collection = db.mycollection

# 2. List of your files to ingest
files_to_ingest = [
    "edited-component-definition.json",
    "SBOM.json",
    "VEX.json",
    "algorithm_cbom.json",
    "certificate_cbom.json",
    "protocol_cbom.json",
    "BOMLink.json"
]

def load_and_insert():
    # Clear existing data to ensure a clean test (Optional)
    # collection.delete_many({}) 
    # print("Cleared existing collection data.")

    count = 0
    for filename in files_to_ingest:
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                try:
                    data = json.load(f)
                    
                    # Add a helper field to track source file (optional, helps debugging)
                    if isinstance(data, list):
                        # Handle array root (like BOMLink.json)
                        for item in data:
                            item['_source_file'] = filename
                            collection.insert_one(item)
                            count += 1
                    else:
                        data['_source_file'] = filename
                        collection.insert_one(data)
                        count += 1
                        
                    print(f"Successfully inserted: {filename}")
                except json.JSONDecodeError:
                    print(f"Error: Could not decode JSON from {filename}")
        else:
            print(f"Warning: File not found locally: {filename}")

    print(f"\nTotal documents inserted: {count}")

if __name__ == "__main__":
    load_and_insert()