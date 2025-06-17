import os
import json
import time
import requests
from pymongo.collection import Collection

class SdtSenderService:
    def __init__(self, collection: Collection, file_path: str, deploy_host: str):
        self.collection = collection
        self.file_path = file_path
        self.deploy_host = deploy_host

    def send(self, hash_value):
        if not os.path.exists(self.file_path):
            return {"error": f"{self.file_path} not found"}, 404

        # Step 1: Deploy
        deploy_resp = requests.post(f"{self.deploy_host}/deploy")
        deploy_resp.raise_for_status()

        # Step 2: Get deployments
        deployments_resp = requests.get(f"{self.deploy_host}/deployments")
        deployments_resp.raise_for_status()

        time.sleep(30)

        with open(self.file_path, "r") as f:
            content = json.load(f)

        create_url = (
            f"{self.deploy_host}/create"
            "?toeid=00000000-0000-0000-0000-000000000000"
            f"&payload_type=BOMS&hash_value={hash_value}"
        )

        try:
            create_resp = requests.post(create_url, json=content)
            create_resp.raise_for_status()
        except requests.RequestException as e:
            # Save fallback to MongoDB
            fallback_data = {
                "filename": os.path.basename(self.file_path),
                "hash": hash_value,
                "content": content,
                "timestamp": time.time(),
                "note": "Saved due to /create endpoint failure"
            }
            self.collection.insert_one(fallback_data)
            return {
                "status": "Fallback save to MongoDB",
                "error": str(e),
                "saved_file": fallback_data["filename"]
            }, 500

        return {
            "status": "Files sent successfully",
            "deploy_status": deploy_resp.status_code,
            "deployments_status": deployments_resp.status_code,
            "create_status": 200
        }, 200
