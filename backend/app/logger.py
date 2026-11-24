import logging
import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_FILE_PATH = os.path.join(BASE_DIR, "auditoria.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] AUDITORIA: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE_PATH, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger("undersound_audit")