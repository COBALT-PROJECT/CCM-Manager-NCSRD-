import os
import json
import subprocess
from datetime import datetime
from config import Config
from pymongo import MongoClient
#import logging

class SBOMGenerator:
    def __init__(self, folder_path):
        self.folder_path = folder_path
        self.language = None
        self.requirements_file = None
        self.sbom_filepath = None
        self.timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        self.client = MongoClient(os.getenv("MONGO_URI"))
        self.db = self.client[os.getenv("MONGO_DB", "sbom_db")]
        self.collection = self.db[os.getenv("MONGO_COLLECTION", "vex_entries")]

    def validate_folder(self):
        if not os.path.isdir(self.folder_path):
            raise ValueError(f"Provided folder path does not exist: {self.folder_path}")

    def detect_language(self):
        for root, _, files in os.walk(self.folder_path):
            if 'pom.xml' in files:
                self.language = 'java'
                self.requirements_file = os.path.join(root, 'pom.xml')
                break
            elif 'requirements.txt' in files:
                self.language = 'python'
                self.requirements_file = os.path.join(root, 'requirements.txt')
                break
            elif 'package.json' in files:
                self.language = 'nodejs'
                self.requirements_file = os.path.join(root, 'package.json')
                break
        if not self.requirements_file:
            raise FileNotFoundError("No supported dependency file found.")

    def generate_sbom(self):
        self.sbom_filepath = os.path.abspath(
            os.path.join(Config.UPLOAD_FOLDER, f'sbom_{self.timestamp}.json')
        )

        if self.language == 'python':
            subprocess.run(['helpers/create_project.sh', self.requirements_file, self.timestamp], check=True)
        elif self.language in ('java', 'nodejs'):
            cwd = os.path.dirname(self.requirements_file)
            result = subprocess.run(
                ['cdxgen', '-f', self.requirements_file, '-o', self.sbom_filepath],
                cwd=cwd,
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                raise RuntimeError(f"cdxgen failed: {result.stderr}")

    def create_project(self):
        result = subprocess.run(
            ['helpers/create_project.sh', self.sbom_filepath],
            capture_output=True,
            text=True,
            env={**os.environ}
        )
        if result.returncode != 0:
            raise RuntimeError(f"create_project.sh failed: {result.stderr}")

    def get_vex_and_save(self):
        files = sorted([f for f in os.listdir(Config.UPLOAD_FOLDER) if f.startswith('vex_') and f.endswith('.json')], reverse=True)
        if not files:
            raise FileNotFoundError("VEX file not found.")
        vex_file_path = os.path.join(Config.UPLOAD_FOLDER, files[0])
        with open(vex_file_path, 'r') as f:
            vex_data = json.load(f)
        self.collection.insert_one({
            "sbom_filepath": self.sbom_filepath,
            "vulnerabilities": vex_data
        })
        return self.sbom_filepath

    def run(self):
        self.validate_folder()
        self.detect_language()
        self.generate_sbom()
        self.create_project()
        return self.get_vex_and_save()
