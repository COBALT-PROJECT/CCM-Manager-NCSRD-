import os
import json
import requests
import logging
import xml.etree.ElementTree as ET
from pymongo import ReturnDocument

from auth import auth_context, authed_request
from config import LEDGER_BASE_URL, LEDGER_HASH_URL, SEND_SDT_URL


def xml_to_dict(elem):
    node = {elem.tag: {} if elem.attrib else None}
    children = list(elem)

    if children:
        child_data = {}
        for child in map(xml_to_dict, children):
            for key, value in child.items():
                if key in child_data:
                    if not isinstance(child_data[key], list):
                        child_data[key] = [child_data[key]]
                    child_data[key].append(value)
                else:
                    child_data[key] = value
        node = {elem.tag: child_data}

    if elem.attrib:
        node[elem.tag].update(('@' + key, value) for key, value in elem.attrib.items())

    if elem.text:
        text = elem.text.strip()
        if children or elem.attrib:
            if text:
                node[elem.tag]['#text'] = text
        else:
            node[elem.tag] = text

    return node


def load_bom_file(file_path):
    if not file_path:
        return {"error": "No BOM file path provided"}, 400

    if not os.path.exists(file_path):
        return {"error": "BOM file not found"}, 404

    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    try:
        if ext == ".json":
            with open(file_path, "r") as bom_file:
                return json.load(bom_file), 200

        if ext == ".xml":
            tree = ET.parse(file_path)
            return xml_to_dict(tree.getroot()), 200

        return {"error": f"Unsupported file extension: {ext}"}, 400
    except Exception as exc:
        return {"error": "Failed to parse BOM file", "details": str(exc)}, 500


def trigger_chain(request_data):
    bom_data, status_code = load_bom_file((request_data or {}).get("bom_path"))
    if status_code != 200:
        return bom_data, status_code

    unique_key = (request_data or {}).get("unique_key")
    if not unique_key:
        return {"error": "unique_key not provided"}, 400

    post_url = f"{LEDGER_BASE_URL}/api/ledger"
    outbound_auth = []
    payload = {
        "channel": "artifact",
        "smartContract": "artifactsc",
        "key": unique_key,
        "data": bom_data,
    }

    try:
        post_response = authed_request(
            "POST",
            post_url,
            headers={"accept": "*/*", "Content-Type": "application/json"},
            json=payload,
            service="ledger",
        )
        outbound_auth.append(auth_context("ledger"))
        post_response.raise_for_status()
    except requests.RequestException as exc:
        if not outbound_auth:
            outbound_auth.append(auth_context("ledger"))
        return {
            "error": "POST to blockchain failed",
            "details": str(exc),
            "outbound_auth": outbound_auth,
        }, 500

    get_params = {
        "channel": "artifact",
        "smartContract": "artifactsc",
        "key": unique_key,
    }

    try:
        get_response = authed_request(
            "GET",
            LEDGER_HASH_URL,
            headers={"accept": "application/json"},
            params=get_params,
            service="ledger",
        )
        if not any(item["service"] == "ledger" for item in outbound_auth):
            outbound_auth.append(auth_context("ledger"))
        get_response.raise_for_status()
        hash_value = get_response.json().get("hash")
    except requests.RequestException as exc:
        if not any(item["service"] == "ledger" for item in outbound_auth):
            outbound_auth.append(auth_context("ledger"))
        return {
            "error": "GET hash failed",
            "details": str(exc),
            "outbound_auth": outbound_auth,
        }, 500

    try:
        send_sdt_resp = authed_request(
            "POST",
            SEND_SDT_URL,
            json={
                "hash": hash_value,
                "bom_path": (request_data or {}).get("bom_path"),
                "toe_id": (request_data or {}).get("toe_id"),
                "category": (request_data or {}).get("category"),
            },
            service="sdt",
        )
        outbound_auth.append(auth_context("sdt"))
        send_sdt_resp.raise_for_status()
        send_sdt_result = send_sdt_resp.json()
    except requests.RequestException as exc:
        if not any(item["service"] == "sdt" for item in outbound_auth):
            outbound_auth.append(auth_context("sdt"))
        return {
            "error": "Failed to call /send_sdt",
            "details": str(exc),
            "outbound_auth": outbound_auth,
        }, 500

    return {
        "status": "success",
        "hash": hash_value,
        "send_sdt_response": send_sdt_result,
        "outbound_auth": outbound_auth,
    }, 200


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
