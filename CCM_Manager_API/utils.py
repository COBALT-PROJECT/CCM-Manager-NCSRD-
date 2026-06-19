import hashlib
import json
import uuid


ALLOWED_EXTENSIONS = {"json", "txt", "xml"}


def generate_json_hash(data):
    normalized = json.dumps(data, sort_keys=True)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def mongo_safe_document(value):
    if isinstance(value, dict):
        safe = {}
        for key, nested_value in value.items():
            safe_key = str(key)
            if safe_key.startswith("$"):
                safe_key = f"_{safe_key[1:]}"
            safe_key = safe_key.replace(".", "_")
            safe[safe_key] = mongo_safe_document(nested_value)
        return safe

    if isinstance(value, list):
        return [mongo_safe_document(item) for item in value]

    return value


def hash_ip(ip):
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()


def is_valid_urn_uuid(value):
    if not isinstance(value, str) or not value.startswith("urn:uuid:"):
        return False
    try:
        uuid.UUID(value.replace("urn:uuid:", ""))
        return True
    except ValueError:
        return False


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
