
import logging
import sys
import os

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Ensure batch-layer directory is importable regardless of CWD
_BATCH_DIR = os.path.dirname(os.path.abspath(__file__))
if _BATCH_DIR not in sys.path:
    sys.path.insert(0, _BATCH_DIR)


def main():
    logger.info("╔══════════════════════════════════════════════╗")
    logger.info("║     CyberSec Batch Layer — All Jobs          ║")
    logger.info("╚══════════════════════════════════════════════╝")

    jobs = [
        ("Job #1 - Top Malicious IPs",  "job_top_malicious_ips",  "run"),
        ("Job #2 - Port Scan Detection","job_port_scan",           "run"),
        ("Job #3 - Attack Patterns",    "job_attack_patterns",     "run"),
        ("Job #4 - Volume Analysis",    "job_volume_analysis",     "run"),
    ]

    for name, module, func in jobs:
        logger.info("─── Starting: %s ───", name)
        try:
            mod = __import__(module)
            getattr(mod, func)()
            logger.info("✅ Completed: %s", name)
        except Exception as e:
            logger.error("❌ Failed: %s — %s", name, e, exc_info=True)
            # Continue with remaining jobs

    logger.info("╔══════════════════════════════════════════════╗")
    logger.info("║     All batch jobs finished                  ║")
    logger.info("╚══════════════════════════════════════════════╝")


if __name__ == "__main__":
    main()
