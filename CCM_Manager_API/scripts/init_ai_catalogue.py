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


def init_catalogue():
    filename = os.path.abspath(
        os.getenv(
            "AI_CATALOGUE_PATH",
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "data",
                "eucs",
                "global_certification_scheme_fully_mapped.json",
            ),
        )
    )
    controls_filename = os.path.abspath(
        os.getenv(
            "EUCS_CONTROLS_CATALOGUE_PATH",
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "data",
                "eucs",
                "EUCS_controls_version_1.1_catalog_master.json",
            ),
        )
    )
    headers = {'Content-Type': 'application/json'}
    
    # Define our endpoints
    base_url = "http://localhost:5001"
    metrics_url = f"{base_url}/metrics"
    controls_url = f"{base_url}/controls"
    risks_url = f"{base_url}/risks"
    threats_url = f"{base_url}/threats"
    
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
                print(f"Uploading {len(metrics)} metrics...")
                res = requests.post(metrics_url, json=metrics, headers=headers)
                print(f"Metrics Response ({res.status_code}): {res.text}")
                
            # 2. Post Controls
            controls = []
            if os.path.exists(controls_filename):
                with open(controls_filename, 'r') as controls_file:
                    controls = flatten_oscal_controls(json.load(controls_file))
            if not controls:
                controls = data.get("certifiable_standards_mapping", [])
            if controls:
                print(f"Uploading {len(controls)} controls...")
                res = requests.post(controls_url, json=controls, headers=headers)
                print(f"Controls Response ({res.status_code}): {res.text}")
                
            # 3. Process Risks and Threats
            risks = data.get("risk_catalogue", [])
            threats = []
            
            for risk in risks:
                # Extract threats
                mapped_threats = risk.get("mapped_threats", []) or []
                for threat in mapped_threats:
                    threat_doc = {**threat, "associated_risk_id": risk["risk_id"]}
                    threats.append(threat_doc)
            
            if risks:
                print(f"Uploading {len(risks)} risks...")
                res = requests.post(risks_url, json=risks, headers=headers)
                print(f"Risks Response ({res.status_code}): {res.text}")
                
            if threats:
                print(f"Uploading {len(threats)} threats...")
                res = requests.post(threats_url, json=threats, headers=headers)
                print(f"Threats Response ({res.status_code}): {res.text}")
                
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")
        except requests.RequestException as e:
            print(f"Error communicating with API: {e}")

if __name__ == "__main__":
    init_catalogue()
