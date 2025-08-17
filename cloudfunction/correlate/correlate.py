"""Correlation logic to match KEV entries with application inventory."""
import os
import pandas as pd
from google.cloud import bigquery

# BigQuery client
bq_client = bigquery.Client()

PROJECT_ID = os.environ.get('PROJECT_ID')
DATASET_ID = os.environ.get('DATASET_ID')
TABLE_ID = os.environ.get('TABLE_ID')

def correlate_kev_inventory(app_table: str = 'jamf-os-app_copy') -> pd.DataFrame:
    """
    Join KEV table with JAMF/Intune app inventory table based on normalized product names and version comparison.
    Returns a Pandas DataFrame of matches sorted by device and application.
    """
    query = f"""
    WITH kev_versions AS (
        SELECT DISTINCT
            cve_id,
            product,
            description AS kev_description,
            cvss_score,
            v.version      AS affected_version,
            v.less_than    AS patched_version
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`,
             UNNEST(affected_products) AS ap,
             UNNEST(ap.versions)       AS v
    )
    SELECT
        j.Computer_Name,
        j.Application_Title,
        j._Application_Version,
        k.cve_id,
        k.kev_description,
        k.patched_version,
        k.cvss_score,
        k.affected_version
    FROM `{PROJECT_ID}.{DATASET_ID}.{app_table}` j
    JOIN `{PROJECT_ID}.{DATASET_ID}.app_mapping` m
      ON LOWER(REPLACE(j.Application_Title, '.app','')) = LOWER(REPLACE(m.jamf_app_title, '.app',''))
    JOIN kev_versions k
      ON LOWER(m.kev_product) = LOWER(k.product)
     AND SAFE_CAST(j._Application_Version AS FLOAT64) < SAFE_CAST(k.patched_version AS FLOAT64)
    ORDER BY j.Computer_Name, j.Application_Title
    """
    df = bq_client.query(query).to_dataframe()
    if not df.empty:
        df = df.drop_duplicates(
            subset=['Computer_Name', 'Application_Title', '_Application_Version', 'cve_id']
        )
    return df
