import os
import json
import time
import requests
from pymongo.collection import Collection

from auth import auth_context, authed_request
from config import DELETE_SDT_URL, DEPLOY_SDT_URL, DEPLOYMENTS_SDT_URL, CREATE_SDT_URL
from db import collection


def send_sdt(hash_value):
    print("\nStarting SBOM send workflow...\n")
    print(f"Received hash: {hash_value}")

    print("Step 1: Deploying environment...")
    deploy_resp = authed_request("POST", DEPLOY_SDT_URL, service="sdt")
    print(f"Deploy step completed (status {deploy_resp.status_code})")
    deploy_resp.raise_for_status()

    print("Step 2: Checking current deployments...")
    deployments_resp = authed_request("GET", DEPLOYMENTS_SDT_URL, service="sdt")
    print(f"Deployments fetched (status {deployments_resp.status_code})")
    deployments_resp.raise_for_status()

    time.sleep(30)

    first_record = collection.find_one()
    if first_record:
        files_to_send = [
            {
                "path": first_record.get("path"),
                "hash": first_record.get("hash"),
            }
        ]
    else:
        files_to_send = []

    for file_entry in files_to_send:
        if not os.path.exists(file_entry["path"]):
            print(f"File not found: {file_entry['path']}")
            return {"error": f"{file_entry['path']} not found"}, 404

        with open(file_entry["path"], "r") as bom_file:
            content = json.load(bom_file)

        create_url = (
            f"{CREATE_SDT_URL}?toeid=00000000-0000-0000-0000-000000000000"
            f"&payload_type=BOMS&hash_value={file_entry['hash']}"
        )

        try:
            resp = authed_request("POST", create_url, json=content, service="sdt")
            print(f"Sent to /create (status {resp.status_code})")
            resp.raise_for_status()
        except requests.RequestException as exc:
            print(f"Failed to send to /create: {exc}")
            fallback_data = {
                "filename": os.path.basename(file_entry["path"]),
                "hash": file_entry["hash"],
                "content": content,
                "timestamp": time.time(),
                "note": "Saved due to /create endpoint failure",
            }
            collection.insert_one(fallback_data)
            print("Saved SBOM file to MongoDB as fallback.")
            return {
                "status": "Fallback save to MongoDB",
                "error": str(exc),
                "saved_file": fallback_data["filename"],
                "outbound_auth": [auth_context("sdt")],
            }, 500

    print("\nAll files sent successfully!")

    return {
        "status": "Files sent successfully",
        "deploy_status": deploy_resp.status_code,
        "deployments_status": deployments_resp.status_code,
        "create_status": 200,
        "outbound_auth": [auth_context("sdt")],
    }, 200


def trigger_delete(identifier):
    if not DELETE_SDT_URL:
        return {
            "error": "DELETE_SDT environment variable not configured",
            "outbound_auth": [auth_context("sdt")],
        }, 500

    response = authed_request(
        "POST",
        DELETE_SDT_URL,
        json={"identifier": identifier},
        headers={"Content-Type": "application/json"},
        service="sdt",
    )

    return {
        "message": "Triggered delete request",
        "delete_response_status": response.status_code,
        "delete_response_body": response.json(),
        "outbound_auth": [auth_context("sdt")],
    }, response.status_code


def get_sdt_ids():
    if not DEPLOYMENTS_SDT_URL:
        return {
            "error": "DEPLOYMENTS_SDT environment variable not configured",
            "outbound_auth": [auth_context("sdt")],
        }, 500

    response = authed_request("GET", DEPLOYMENTS_SDT_URL, timeout=10, service="sdt")
    response.raise_for_status()
    data = response.json()

    sdt_ids = []
    if isinstance(data, list):
        sdt_ids = [item.get("id") or item.get("identifier") for item in data if isinstance(item, dict)]
        if not sdt_ids and all(isinstance(item, (str, int)) for item in data):
            sdt_ids = data
    elif isinstance(data, dict):
        for key in ["deployments", "sdts", "data", "items"]:
            if key in data and isinstance(data[key], list):
                sdt_ids = [
                    item.get("id") or item.get("identifier")
                    for item in data[key]
                    if isinstance(item, dict)
                ]
                if not sdt_ids and all(isinstance(item, (str, int)) for item in data[key]):
                    sdt_ids = data[key]
                break

        if not sdt_ids and ("identifier" in data or "id" in data):
            sdt_ids.append(data.get("identifier") or data.get("id"))

    return {
        "sdts": [str(item) for item in sdt_ids if item is not None],
        "outbound_auth": [auth_context("sdt")],
    }, 200


class SdtSenderService:
    def __init__(self, collection: Collection, file_path: str, deploy_host: str, auth_client=None):
        self.collection = collection
        self.file_path = file_path
        self.deploy_host = deploy_host
        self.auth_client = auth_client

    def _request(self, method, url, **kwargs):
        """Route through ComponentAuthClient when available, raw requests otherwise."""
        if self.auth_client is not None:
            return self.auth_client.authenticated_request(method, url, **kwargs)
        return requests.request(method, url, **kwargs)

    def send(self, hash_value):
        if not os.path.exists(self.file_path):
            return {"error": f"{self.file_path} not found"}, 404

        # Step 1: Deploy
        deploy_resp = self._request("POST", f"{self.deploy_host}/deploy")
        deploy_resp.raise_for_status()

        # Step 2: Get deployments
        deployments_resp = self._request("GET", f"{self.deploy_host}/deployments")
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
            create_resp = self._request("POST", create_url, json=content)
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
