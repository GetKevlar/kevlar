# Kevlar

Kevlar is a vulnerability intelligence engine that ingests Known Exploited Vulnerabilities (KEVs), normalizes version data, correlates it against endpoint inventory (for example, Jamf‑managed Macs or Intune‑managed devices), and surfaces actionable results via Jira or Slack.

The objective is to answer:

**Which KEV‑listed vulnerabilities affect my endpoints right now—down to the exact version running?**

Unlike many scanners and EDR reports that flag CVEs generically, Kevlar focuses on version‑aware normalization and correlation so you see only confirmed, endpoint‑specific risk.

## Why Kevlar

- **Version‑aware correlation**: Kevlar normalizes version strings from KEV data and from your inventory, enabling exact version‑to‑endpoint matches (not just "potentially affected").
- **Low overhead**: Deployed as a lightweight Cloud Function with modular connectors; no full scanner or agent required.
- **Actionable outputs**: Opens targeted Jira tickets and Slack summaries; optional weekly health status.
- **Extensible**: Connector pattern makes it straightforward to add other inventory sources.

## Features

- **Normalization engine**: Aligns and cleans version data across feeds and endpoint inventories.
- **CISA and MITRE ingestion**: Fetches KEV/CVE data and loads it into BigQuery.
- **Correlation engine**: Joins KEV entries with endpoint data to identify devices running vulnerable versions.
- **Alerting**: Jira ticket creation (per match) and Slack notifications; a weekly health report mode.
- **Modular connectors**: Reference connectors for Jamf and Intune; additional collectors can follow the pattern in `cloudfunction/correlate`.

## Getting Started

### Clone
```bash
git clone https://github.com/GetKevlar/kevlar.git
cd kevlar
```

### Configure environment
Copy and edit:
```bash
cp .env.sample .env
```
Required values:
- `PROJECT_ID` – Google Cloud project ID
- `DATASET_ID` – BigQuery dataset (for KEVs and inventory)
- `TABLE_ID` – BigQuery table for KEVs
- `JIRA_URL`, `JIRA_USER`, `JIRA_TOKEN` – for Jira integration
- Optional: `SLACK_WEBHOOK_URL`
- Optional: `BQ_WAIT_TIME` (seconds to wait for BQ consistency before correlation)

## Secure Deployment (GCP)

Deploy authenticated‑only (recommended). Gen2 shown:

```bash
gcloud functions deploy kev_pipeline \
  --gen2 --runtime=python310 \
  --trigger-http \
  --no-allow-unauthenticated \
  --ingress-settings=internal-and-gclb
```

Grant a scheduler service account permission to invoke the function:

```bash
gcloud functions add-iam-policy-binding kev_pipeline \
  --member=serviceAccount:kevlar-scheduler@PROJECT_ID.iam.gserviceaccount.com \
  --role=roles/run.invoker
```

Schedule a weekly health run with Cloud Scheduler (OIDC):

```bash
gcloud scheduler jobs create http kevlar-health \
  --schedule="0 8 * * MON" \
  --http-method=GET \
  --uri="https://REGION-PROJECT.cloudfunctions.net/kev_pipeline?health=true" \
  --oidc-service-account-email=kevlar-scheduler@PROJECT_ID.iam.gserviceaccount.com \
  --oidc-token-audience="https://REGION-PROJECT.cloudfunctions.net/kev_pipeline"
```

> Note: Store secrets in Secret Manager and map them to environment variables at deploy time. Do not enable unauthenticated access.

## Dashboards and Examples

- Looker Studio template: `dashboard/`
- Example inventory data: `examples/`

## Architecture

The architecture diagram is in `diagrams/kevlar_architecture.png`.  
Mermaid source (`diagrams/kevlar_architecture.mmd`) can be rendered with Mermaid CLI:
```bash
mmdc -i diagrams/kevlar_architecture.mmd -o diagrams/kevlar_architecture.png
```

## Roadmap

- Deduplication of per‑match alerts (sent‑alert hash).
- Additional connectors (SentinelOne, CrowdStrike, Tanium).
- Slack bot for natural‑language KEV queries.
- Integration with ExploitIQ for executive summarization.

## ExploitIQ

ExploitIQ is a proprietary add‑on for Kevlar providing natural‑language summaries and executive reporting from correlation results. See `exploit-iq/README.md` for details.

## License

Kevlar is source‑available under the Business Source License v1.1. See `LICENSE`.
