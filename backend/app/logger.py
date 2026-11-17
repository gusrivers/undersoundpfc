import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] AUDITORIA: %(message)s",
    handlers=[
        logging.FileHandler("auditoria.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("undersound_audit")