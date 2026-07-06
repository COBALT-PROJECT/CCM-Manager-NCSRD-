import json
import os
import requests


def control_statement(control):
    for part in control.get("parts", []) or []:
        if part.get("name") == "statement" and part.get("prose"):
            return part["prose"]
    for part in control.get("parts", []) or []:
        if part.get("prose"):
            return part["prose"]
    return ""


def flatten_oscal_controls(catalogue):
    catalog = catalogue.get("catalog", catalogue)
    controls = []

    def walk(node, parent_groups=None):
        parent_groups = parent_groups or []

        for control in node.get("controls", []) or []:
            control_id = control.get("id")
            if not control_id:
                continue

            statement = control_statement(control)
            controls.append({
                "control_id": control_id,
                "oscal_id": control_id,
                "title": control.get("title", ""),
                "class": control.get("class", ""),
                "description": statement,
                "prose": statement,
                "parts": control.get("parts", []),
                "groups": parent_groups,
            })

        for group in node.get("groups", []) or []:
            group_ref = {
                "id": group.get("id", ""),
                "title": group.get("title", ""),
                "class": group.get("class", ""),
            }
            walk(group, parent_groups + [group_ref])

    walk(catalog)
    return controls


def default_source_paths():
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
    return [
        (
            os.path.abspath(
                os.getenv(
                    "AI_CATALOGUE_PATH",
                    os.path.join(data_dir, "eucs", "global_certification_scheme_fully_mapped.json"),
                )
            ),
            os.path.abspath(
                os.getenv(
                    "EUCS_CONTROLS_CATALOGUE_PATH",
                    os.path.join(data_dir, "eucs", "EUCS_controls_version_1.1_catalog_master.json"),
                )
            ),
        ),
        (
            os.path.abspath(
                os.getenv(
                    "QUANTUM_CATALOGUE_PATH",
                    os.path.join(data_dir, "Quantum", "global_certification_scheme_quantum_fully_mapped.json"),
                )
            ),
            os.path.abspath(
                os.getenv(
                    "QUANTUM_CONTROLS_CATALOGUE_PATH",
                    os.path.join(data_dir, "Quantum", "Quantum_controls_version_1.0_catalog_master.json"),
                )
            ),
        ),
    ]


def upload_catalogue_source(filename, controls_filename, endpoints, headers):
    if not os.path.exists(filename):
        print(f"Error: File not found: {filename}")
        return

    with open(filename, 'r') as f:
        try:
            data = json.load(f)
            data = data.get("certificationScheme", data)

            # 1. Post Metrics
            metrics = data.get("compliance_metrics", [])
            if metrics:
                print(f"Uploading {len(metrics)} metrics from {filename}...")
                res = requests.post(endpoints["metrics"], json=metrics, headers=headers)
                print(f"Metrics Response ({res.status_code}): {res.text}")

            # 2. Post Controls
            controls = []
            if os.path.exists(controls_filename):
                with open(controls_filename, 'r') as controls_file:
                    controls = flatten_oscal_controls(json.load(controls_file))
            if not controls:
                controls = data.get("certifiable_standards_mapping", [])
            if controls:
                print(f"Uploading {len(controls)} controls from {controls_filename}...")
                res = requests.post(endpoints["controls"], json=controls, headers=headers)
                print(f"Controls Response ({res.status_code}): {res.text}")

            # 3. Process Risks and Threats
            risks = data.get("risk_catalogue", [])
            threats = []

            for risk in risks:
                mapped_threats = risk.get("mapped_threats", []) or []
                for threat in mapped_threats:
                    threat_doc = {**threat, "associated_risk_id": risk["risk_id"]}
                    threats.append(threat_doc)

            if risks:
                print(f"Uploading {len(risks)} risks from {filename}...")
                res = requests.post(endpoints["risks"], json=risks, headers=headers)
                print(f"Risks Response ({res.status_code}): {res.text}")

            if threats:
                print(f"Uploading {len(threats)} threats from {filename}...")
                res = requests.post(endpoints["threats"], json=threats, headers=headers)
                print(f"Threats Response ({res.status_code}): {res.text}")

        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")
        except requests.RequestException as e:
            print(f"Error communicating with API: {e}")


def init_catalogue():
    headers = {'Content-Type': 'application/json'}

    # Define our endpoints
    base_url = "http://localhost:5001"
    endpoints = {
        "metrics": f"{base_url}/metrics",
        "controls": f"{base_url}/controls",
        "risks": f"{base_url}/risks",
        "threats": f"{base_url}/threats",
    }

    for filename, controls_filename in default_source_paths():
        upload_catalogue_source(filename, controls_filename, endpoints, headers)

if __name__ == "__main__":
    init_catalogue()
