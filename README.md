# CCM Ledger and SBOM Management API

This Flask-based API provides endpoints to manage Component Compliance and Certification Materials (CCM), Software Bill of Materials (SBOM), and related artifacts. It supports storing, updating, forwarding ledger entries, and integrating with external services for SDT and chain triggers.

---

## Table of Contents

- [Features](#features)  
- [Setup](#setup)  
- [API Endpoints](#api-endpoints)  
- [Usage](#usage)  
- [Contributing](#contributing)  
- [License](#license)  

---

## Features

- Upload, store, and update CCM ledger entries with content hashing and timestamps  
- Generate and upload SBOM, CBOM, SaaSBOM, and related certification scheme data  
- Forward ledger records to multiple endpoints asynchronously  
- Trigger chain processes and SDT (Software Delivery Token) sending  
- Interact with external services for OSCAL profiles and delete triggers  
- Basic error handling and validation with JSON responses  

---

## Setup

### Prerequisites

- Python 3.8+  
- MongoDB instance accessible by the app  
- Required Python packages (see `requirements.txt`)

### Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/yourusername/ccm-ledger-api.git
   cd ccm-ledger-api

2. (Optional) Create and activate a virtual environment:
	 ```bash
	python3 -m venv venv
	source venv/bin/activate

3. Install dependencies:
	 ```bash
	 pip install -r requirements.txt

4. Configure your MongoDB connection and other environment variables in your config or `.env` file.
5. Run the Flask app:
	```bash
	flask run


---

##  Endpoints

### 1. `POST /generate_sbom`

**Description:** Generate an SBOM from a given folder containing a dependency file.

#### Request

**Content-Type:** `application/x-www-form-urlencoded`

**Body:** `folder=/path/to/your/project`

#### Response (200 OK)

```json
{
  "message": "SBOM generated, project created, and vulnerabilities saved successfully",
  "sbom_file": "/path/to/generated/SBOM.json"
}
```

### 2. `GET /show_vulnerabilities`

**Description:** Retrieve all stored vulnerabilities from the MongoDB database.

**Response (200 OK)**

```json
[
  {
    "vulnerability": "CVE-2023-1234",
    "severity": "High"
  }
]
```

---

### 3. `POST /generate_cbom`

**Description:** Generate CBOMs from uploaded cipher/certificate JSON.

**Request**

- **Content-Type:** `multipart/form-data`
- **Body:**
  - `file`: JSON file
  - `hashed_ip`: Optional string

**Response (200 OK)**

```json
{
  "message": "SBOMs generated successfully",
  "algorithm_sbom": "algorithm_sbom_<timestamp>.json",
  "certificate_sbom": "certificate_sbom_<timestamp>.json",
  "protocol_sbom": "protocol_sbom_<timestamp>.json"
}
```

---

### 4. `POST /receive_output`

**Description:** Accepts JSON file or body, hashes client IP, and triggers CBOM generation.

**Request (Option 1 - Form File Upload)**

- **Content-Type:** `multipart/form-data`
- **Body:** `file=<file.json>`

**Request (Option 2 - JSON Body)**

```json
{
  "ciphers": {
    "TLS_RSA_WITH_AES_128_CBC_SHA": {
      "TLS_version": "1.2",
      "encryption_algorithm": "AES"
    }
  }
}
```

**Response (200 OK)**

```json
{
  "message": "SBOMs generated successfully",
  "algorithm_sbom": "algorithm_sbom_<timestamp>.json",
  "certificate_sbom": "certificate_sbom_<timestamp>.json",
  "protocol_sbom": "protocol_sbom_<timestamp>.json"
}
```

---

### 5. `POST /upload_oscal`

**Description:** Upload an OSCAL (JSON) document.

**Request**

```json
{
  "catalog": {
    "uuid": "123e4567-e89b-12d3-a456-426614174000",
    "metadata": {
      "title": "Example Catalog",
      "version": "1.0.0"
    }
  }
}
```

**Response (200 OK)**

```json
{
  "message": "catalog document saved successfully.",
  "uuid": "123e4567-e89b-12d3-a456-426614174000"
}
```

---

### 6. `GET /oscal_ids/{doc_uuid}`

**Description:** Get control IDs from an OSCAL document by UUID.

**Response (200 OK)**

```json
{
  "control_ids": ["AC-1", "AC-2", "CM-2"]
}
```

---

### 7. `POST /upload_saasbom`

**Description:** Upload and validate a SaaSBOM (CycloneDX format).

**Request**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": { "component": {} },
  "services": []
}
```

**Response (200 OK)**

```json
{
  "message": "SaaSBOM saved successfully.",
  "serialNumber": "urn:uuid:123e4567-e89b-12d3-a456-426614174000"
}
```

---

### 8. `POST /upload_toe_descriptor`

**Description:** Upload a TOE descriptor and associated materials.

**Request**

```json
{
  "component": {
    "component-definition": {
      "components": [
        {
          "uuid": "123e4567-e89b-12d3-a456-426614174000",
          "title": "Example TOE Component"
        }
      ]
    }
  }
}
```

**Response (200 OK)**

```json
{
  "status": "Descriptor received and forwarded successfully",
  "forward_status": 200
}
```

---

### 9. `POST /upload_certification_scheme`

**Description:** Upload a certification scheme document.

**Request**

```json
{
  "certificationScheme": {
    "id": "scheme-123",
    "complianceMetrics": {},
    "controls": [],
    "boundaryConditions": [],
    "productProfile": {}
  }
}
```

**Response (200 OK)**

```json
{
  "message": "Certification Scheme and related documents updated successfully.",
  "uuid": "scheme-123"
}
```

---

### 10. `POST /store-ledger`

**Description:** Store a component-definition from an OSCAL JSON document.

**Request**

```json
{
  "component-definition": {
    "components": []
  }
}
```

**Response (201 Created)**

```json
{
  "message": "Stored",
  "uuid": "123e4567-e89b-12d3-a456-426614174000",
  "hash": "fa5c89f3...d4e829f1"
}
```

---

### 11. `PUT /update-ledger/{uuid}`

**Description:** Update a ledger entry by UUID.

**Request**

```json
{
  "component-definition": {
    ...
  }
}
```

**Response (200 OK)**

```json
{
  "message": "Ledger updated",
  "uuid": "123e4567-e89b-12d3-a456-426614174000",
  "hash": "newhashvalue..."
}
```

---

### 12. `POST /send_std`

**Description:** Upload and forward a CycloneDX SBOM.

**Request**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "components": [
    {
      "name": "component-name",
      "version": "1.0.0",
      "type": "library"
    }
  ]
}
```

**Response (200 OK)**

```json
{
  "status": "CycloneDX SBOM received and forwarded successfully",
  "forward_status": 200
}
```
---

