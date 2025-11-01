# config.py
import os

# JWT / app
JWT_SECRET = os.getenv("JWT_SECRET", "cambia-esto")
JWT_ISS = os.getenv("JWT_ISS", "ransomproof")

# AWS
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# DynamoDB table names
DDB_TENANTS_TABLE    = os.getenv("DDB_TENANTS_TABLE",    "VigiaTenants")
DDB_USERS_TABLE      = os.getenv("DDB_USERS_TABLE",      "VigiaUsers")
DDB_DETECTIONS_TABLE = os.getenv("DDB_DETECTIONS_TABLE", "VigiaDetections")
DDB_ENIS_TABLE       = os.getenv("DDB_ENIS_TABLE",       "VigiaTenantEnis")