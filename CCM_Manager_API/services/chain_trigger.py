import os
import json
import requests
import logging
from pymongo import ReturnDocument

class ChainTriggerService:
    def __init__(self, counters_collection, cyclonedx_path):
        self.counters = counters_collection
        self.cyclonedx_path = cyclonedx_path
        self.blockchain_url = 'http://10.160.101.94:3000/chain/json'
        self.hash_url = 'http://10.160.101.94:3000/chain/json/hash'
        self.sdt_url = 'http://localhost:5001/send_sdt'

    def _get_unique_key(self):
        counter_doc = self.counters.find_one_and_update(
            {"_id": "unique_key_counter"},
            {"$inc": {"seq": 1}},
            return_document=ReturnDocument.AFTER,
            upsert=True
        )
        return str(counter_doc["seq"])

    def _load_cyclonedx_file(self):
        if not os.path.exists(self.cyclonedx_path):
            raise FileNotFoundError("CycloneDX file not found")
        with open(self.cyclonedx_path, 'r') as file:
            return json.load(file)

    def _post_to_blockchain(self, key, data):
        payload = {
            "channel": "artifact",
            "smartContract": "artifactsc",
            "key": key,
            "data": data
        }
        headers = {'accept': '*/*', 'Content-Type': 'application/json'}
        response = requests.post(self.blockchain_url, headers=headers, json=payload)
        response.raise_for_status()

    def _get_hash(self, key):
        params = {"channel": "artifact", "smartContract": "artifactsc", "key": key}
        headers = {'accept': 'application/json'}
        response = requests.get(self.hash_url, headers=headers, params=params)
        response.raise_for_status()
        return response.json().get("hash")

    def _send_sdt(self, hash_value):
        response = requests.post(self.sdt_url, json={"hash": hash_value})
        response.raise_for_status()
        return response.json()

    def trigger(self):
        try:
            unique_key = self._get_unique_key()
            cyclonedx_data = self._load_cyclonedx_file()
            self._post_to_blockchain(unique_key, cyclonedx_data)
            hash_value = self._get_hash(unique_key)
            send_sdt_response = self._send_sdt(hash_value)

            return {
                "status": "success",
                "hash": hash_value,
                "send_sdt_response": send_sdt_response
            }

        except FileNotFoundError as e:
            return {"error": str(e)}, 404
        except requests.RequestException as e:
            return {"error": "Request failed", "details": str(e)}, 500
        except Exception as e:
            logging.exception("Unexpected error in ChainTriggerService")
            return {"error": "Internal server error", "details": str(e)}, 500
