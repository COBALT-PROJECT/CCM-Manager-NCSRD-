import json
import logging
import os
import subprocess
from datetime import datetime

from config import Config
from db import collection


def _detect_dependency_file(folder_path):
    for root, _, files in os.walk(folder_path):
        logging.debug("Checking directory: %s", root)
        if "pom.xml" in files:
            return os.path.join(root, "pom.xml"), "java"
        if "requirements.txt" in files:
            return os.path.join(root, "requirements.txt"), "python"
        if "package.json" in files:
            return os.path.join(root, "package.json"), "nodejs"

    return None, None


def generate_sbom_for_folder(folder_path):
    try:
        if not folder_path:
            return {"error": "No folder path provided"}, 400

        if not os.path.isdir(folder_path):
            return {"error": f"The provided folder path does not exist: {folder_path}"}, 400

        logging.debug("Searching for dependency files in the provided path: %s", folder_path)
        requirements_file, language = _detect_dependency_file(folder_path)

        if not requirements_file:
            return {
                "error": "No recognized dependency file found in the provided folder or subdirectories."
            }, 400

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        sbom_filepath = os.path.abspath(
            os.path.join(Config.UPLOAD_FOLDER, f"sbom_{timestamp}.json")
        )

        if language == "python":
            subprocess.run(["./generate_sbom.sh", requirements_file, timestamp], check=True)
        elif language in ("nodejs", "java"):
            result = subprocess.run(
                ["cdxgen", "-f", requirements_file, "-o", sbom_filepath],
                cwd=os.path.dirname(requirements_file),
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                logging.error("Error generating SBOM with cdxgen: %s", result.stderr)
                return {
                    "error": "Failed to generate SBOM",
                    "details": result.stderr,
                    "stdout": result.stdout,
                }, 500

        if not os.path.exists(sbom_filepath):
            return {"error": "Failed to generate SBOM"}, 500

        logging.debug("SBOM generated at: %s", sbom_filepath)
        result = subprocess.run(
            ["./create_project.sh", sbom_filepath],
            capture_output=True,
            text=True,
            env={**os.environ},
        )

        logging.debug("Create project script return code: %s", result.returncode)
        logging.debug("Create project script output: %s", result.stdout)
        logging.error("Create project script stderr: %s", result.stderr)

        if result.returncode != 0:
            return {
                "error": "Failed to create project",
                "details": result.stderr,
                "stdout": result.stdout,
            }, 500

        vex_files = sorted(
            [
                filename
                for filename in os.listdir(Config.UPLOAD_FOLDER)
                if filename.startswith("vex_") and filename.endswith(".json")
            ],
            reverse=True,
        )
        if not vex_files:
            return {"error": "Failed to retrieve vulnerabilities"}, 500

        vex_filepath = os.path.join(Config.UPLOAD_FOLDER, vex_files[0])
        with open(vex_filepath, "r") as vex_file:
            vex_data = json.load(vex_file)

        collection.insert_one({
            "sbom_filepath": sbom_filepath,
            "vulnerabilities": vex_data,
        })

        return {
            "message": "SBOM generated, project created, and vulnerabilities saved successfully",
            "sbom_file": sbom_filepath,
        }, 200

    except Exception as exc:
        logging.error("An error occurred: %s", exc)
        return {"error": "Internal server error"}, 500
