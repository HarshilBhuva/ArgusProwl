import logging
import time

logger = logging.getLogger(__name__)


def preflight_check(client, target_ip, timeout=30):
    logger.info("Running pre-flight check to verify ClickHouse ingestion for %s...", target_ip)
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            res = client.query(
                f"SELECT count() as c FROM argusprowl.raw_zeek_ssl WHERE id_resp_h = '{target_ip}'"
            )
            if res and int(res[0].get("c", 0)) > 0:
                logger.info(
                    "Pre-flight check passed: Found %s records for %s in ClickHouse.",
                    res[0]["c"],
                    target_ip,
                )
                return True
        except Exception as e:
            logger.warning("Pre-flight query failed: %s", e)

        time.sleep(2)

    logger.error(
        "Pre-flight check failed: No records found for %s in ClickHouse after %d seconds.",
        target_ip,
        timeout,
    )
    return False
