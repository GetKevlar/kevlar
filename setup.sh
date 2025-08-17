#!/bin/bash
#
# Setup script for deploying Kevlar to Google Cloud.  This script creates the
# required BigQuery dataset and deploys the Cloud Function that runs the
# ingestion and correlation pipeline.
#
# Usage:
#   source .env  # or export the necessary variables
#   ./setup.sh

set -euo pipefail

PROJECT_ID=${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}
REGION=${REGION:-us-central1}
FUNCTION_NAME=${FUNCTION_NAME:-kevlar-pipeline}
DATASET_ID=${DATASET_ID:-kevlar_dataset}
TABLE_ID=${TABLE_ID:-kevs}

if [[ -z "$PROJECT_ID" ]]; then
  echo "Error: PROJECT_ID environment variable is not set and could not be determined from gcloud config." >&2
  exit 1
fi

echo "Creating BigQuery dataset ${DATASET_ID} in project ${PROJECT_ID}..."
bq --location=US mk -d --description "Kevlar vulnerability dataset" "${PROJECT_ID}:${DATASET_ID}" || true

echo "Deploying Cloud Function ${FUNCTION_NAME} to region ${REGION}..."
gcloud functions deploy "${FUNCTION_NAME}" \
  --entry-point kev_pipeline \
  --runtime python310 \
  --trigger-http \
  --allow-unauthenticated \
  --set-env-vars "PROJECT_ID=${PROJECT_ID},DATASET_ID=${DATASET_ID},TABLE_ID=${TABLE_ID}" \
  --source ./cloudfunction \
  --region "${REGION}"

echo "Kevlar deployment complete.  You can invoke the function via its HTTP trigger or
configure a Cloud Scheduler job to call it on a schedule."
