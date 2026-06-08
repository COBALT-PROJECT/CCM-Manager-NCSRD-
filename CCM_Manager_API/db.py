import logging

from pymongo import MongoClient

from config import MONGO_DB_NAME, MONGO_URI


client = MongoClient(MONGO_URI)
db = client[MONGO_DB_NAME]

collection = db.mycollection
certificates_col = db.certificates
schemes_col = db.schemes
toes_col = db.toes
risks_col = db.risks
threats_col = db.threats
metrics_col = db.metrics
controls_col = db.controls
rtc_col = db.risk_threat_control
cm_col = db.control_metric

logging.info("Configured MongoDB client for %s/%s", MONGO_URI, MONGO_DB_NAME)
