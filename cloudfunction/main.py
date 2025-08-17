"""
Entry point for the Kevlar Cloud Function.

This module glues together the ingestion, correlation and alerting components
defined in the `ingest`, `correlate` and `alert` packages.  It relies on
environment variables for configuration and uses Google BigQuery to store KEV
data and fetch inventory data.

The function supports two modes of operation:

* **Normal mode** – Ingest the latest KEV data from CISA, enrich it with
  additional MITRE details, load it into BigQuery, run correlation against
  inventory data, and create a Jira ticket for each match.
* **Health mode** – Skip ingestion, run correlation against existing KEV data,
  and create a single summary ticket reporting whether any matches were found.

Health mode can be triggered by setting the `HEALTH_MODE` environment variable
to `true` or by passing `?health=true` as a query parameter when invoking the
function.

Note: The implementations of `fetch_cisa_kev`, `fetch_mitre_details`,
`correlate_kev_inventory`, `create_jira_ticket` and `create_health_ticket` are
defined in their respective modules.  They should be imported here to keep the
handler function lightweight.
"""

import os
import logging
import time
from datetime import datetime
from google.cloud import bigquery
import functions_framework

from .ingest.cisa import fetch_cisa_kev
from .ingest.mitre import fetch_mitre_details
from .correlate.correlate import correlate_kev_inventory
from .alert.jira import create_jira_ticket, create_health_ticket

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kevlar")

# Initialize a BigQuery client.  In Cloud Functions, this will use the
# function's service account credentials.
bq_client = bigquery.Client()

from .ingest.loader import load_to_bigquery
from .utils.utils import create_session

#

def ingest_and_load(session):
    """
    Ingest the CISA KEV feed, enrich with MITRE details,
    and load processed entries into BigQuery. Returns the list of processed records.
    """
    cisa_entries = fetch_cisa_kev(session)
    processed = []
    for entry in cisa_entries:
        try:
            enriched = fetch_mitre_details(session, entry["cve_id"])
            processed.append(enriched)
        except Exception as err:
            logger.error(f"Failed to enrich {entry['cve_id']}: {err}")
    if processed:
        load_to_bigquery(processed)
        wait_time = int(os.environ.get("BQ_WAIT_TIME", "10"))
        time.sleep(wait_time)
    return processed


def correlate_inventory():
    """
    Run correlation across KEVs and inventory. Returns a DataFrame of matches.
    """
    return correlate_key_inventory()


def notify_matches(matches):
    """
    Create a Jira ticket for each match and return the total number created.
    """
    tickets = 0
    if matches is not None and not matches.empty:
        for _, row in matches.iterrows():
            if create_jira_ticket(row):
                tickets += 1
    return tickets


def run_health_mode():
    """
    Run correlation and create a single weekly health ticket.
    Returns (issue_key, match_count).
    """
    df = correlate_key_inventory()
    issue_key = create_health_ticket(df)
    match_count = 0 if df is None else len(df)
    return issue_key, match_count

 Environment configuration
PROJECT_ID = os.environ.get("PROJECT_ID")
DATASET_ID = os.environ.get("DATASET_ID")
TABLE_ID = os.environ.get("TABLE_ID")

@functions_framework.http
def kev_pipeline(request):
    """HTTP Cloud Function entry point for the Kevlar pipeline."""
        try:
        # Determine health mode
                # NEW modular pipeline
        request_args = request.args if request and hasattr(request, "args") else {}
        health_mode_env_mod = os.environ.get("HEALTH_MODE", "false").lower() == "true"
        health_mode_arg_mod = str(request_args.get("health", "false")).lower() == "true"
        health_mode_mod = health_mode_env_mod or health_mode_arg_mod

        if health_mode_mod:
            logger.info("Running Kevlar in health mode")
            issue_key, count = run_health_mode()
            return (
                f"Health run complete. Ticket: {issue_key if issue_key else 'FAILED'}; matches={count}",
                200 if issue_key else 500,
            )

        logger.info("Running Kevlar in normal mode")
        session = create_session()
        valid_records = ingest_and_load(session)
        matches = correlate_inventory()
        tickets = notify_matches(matches)
        return (
            f"Run complete. Ingested={len(valid_records)}; match_tickets={tickets}",
            200,
        )
        # END modular pipeline
args = request.args if request and hasattr(request, "args") else {}
        health_mode_env = os.environ.get("HEALTH_MODE", "false").lower() == "true"
        health_mode_arg = str(args.get("health", "false")).lower() == "true"
        health_mode = health_mode_env or health_mode_arg

        if health_mode:
            logger.info("Running Kevlar in health mode")
            issue_key, count = run_health_mode()
            return (
                f"Health run complete. Ticket: {issue_key if issue_key else 'FAILED'}; matches={count}",
                200 if issue_key else 500,
            )

        logger.info("Running Kevlar in normal mode")
        session = create_session()
        valid_records = ingest_and_load(session)
        matches = correlate_inventory()
        tickets = notify_matches(matches)
        return (
            f"Run complete. Ingested={len(valid_records)}; match_tickets={tickets}",
            200,
        )
    except Exception as exc:
        logger.error(f"Kevlar pipeline failed: {exc}\n{traceback.format_exc()}")
        return f"Kevlar pipeline failed: {exc}", 500f issue_key else 500

        logger.info("Running Kevlar in normal mode")
        # Ingest CISA feed and enrich with MITRE details
        session = None  # placeholder for HTTP session if needed
        cisa_entries = fetch_cisa_kev(session)
        processed = []
        for entry in cisa_entries:
            try:
                enriched = fetch_mitre_details(session, entry["cve_id"])
                processed.append(enriched)
            except Exception as err:
                logger.error(f"Failed to enrich {entry['cve_id']}: {err}")
        # Load processed entries into BigQuery (implementation inside ingest)
        if processed:
            # The ingest module should implement load_to_bigquery
            from .ingest.loader import load_to_bigquery
            load_to_bigquery(processed)
            # Wait briefly for BigQuery to become consistent
            wait_time = int(os.environ.get("BQ_WAIT_TIME", "10"))
            time.sleep(wait_time)

        # Correlate KEVs to inventory
        matches = correlate_kev_inventory()
        ticket_count = 0
        if not matches.empty:
            for _, row in matches.iterrows():
                if create_jira_ticket(row):
                    ticket_count += 1
        return (
            f"Run complete. Ingested={len(processed)}; match_tickets={ticket_count}",
            200,
        )

    except Exception as exc:
        logger.exception("Kevlar pipeline failed")
        return f"Kevlar pipeline failed: {exc}", 500
