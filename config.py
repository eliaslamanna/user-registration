# config.py
import os
DB_URL = os.getenv("DB_URL", "postgresql://user:pass@localhost:5432/ransomproof")
# para demo: DB_URL = "sqlite:///./ransomproof.db"
JWT_SECRET = os.getenv("JWT_SECRET", "cambia-esto")
JWT_ISS = "ransomproof"
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")