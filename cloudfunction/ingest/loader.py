"""BigQuery loader for KEV records.

This module defines a function for inserting processed KEV records into a
BigQuery table.  The exact table schema is defined externally (see
README.md for details).  Records should match the schema expected by the
`TABLE_ID` environment variable.
"""

from typing import List, Dict, Any
from google.cloud import bigquery
import os
import logging

logger = logging.getLogger("kevlar.loader")

PROJECT_ID = os.environ.get("PROJECT_ID")
DATASET_ID = os.environ.get("DATASET_ID")
TABLE_ID   = os.environ.get("TABLE_ID")


def load_to_bigquery(records: List[Dict[str, Any]]) -> None:
    """Load a list of KEV records into BigQuery.

    Args:
        records: List of dictionaries representing normalized KEV entries.
    """
    if not records:
        logger.info("No records to load into BigQuery")
        return
    client = bigquery.Client()
    table_ref = f"{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}"
    errors = client.insert_rows_json(table_ref, records)
    if errors:
        logger.error(f"Failed to insert some rows into {table_ref}: {errors}")
    else:
        logger.info(f"Inserted {len(records)} rows into {table_ref}")
