# Kevlar

Kevlar is a vulnerability intelligence engine that ingests Known Exploited Vulnerabilities (KEVs),
correlates them against endpoint inventory data (for example Jamf‑managed Macs or Intune‑managed
devices), and surfaces actionable alerts via Jira or Slack.  This repository contains the
open‑source core of Kevlar.  The goal of the project is to give organizations a lightweight way
to answer a critical question:

> **Which of the vulnerabilities on the CISA Known Exploited Vulnerability list affect my
> endpoints right now?**

By leveraging BigQuery and modular connectors, Kevlar can ingest the public CISA and MITRE
feeds, normalize their output, and cross‑reference the results against your device inventory.

## Features

* **CISA/MITRE ingestion** – fetches CVE data from the public feeds and loads it into BigQuery.
* **Modular inventory connectors** – includes reference connectors for Jamf and Intune; you can
  implement additional collectors by following the patterns in `cloudfunction/correlate`.
* **Correlation engine** – joins KEV entries with your endpoint data to determine which devices
  are running vulnerable versions of software.
* **Alerting integrations** – integrates with Jira and Slack to create per‑match tickets or
  weekly health reports.
* **Health mode** – runs a weekly summary without ingesting new KEVs and creates a single
  status ticket.

## Getting Started

1. **Clone the repository**.  Clone this repo into your own GitHub organization or fork it to
   begin development.
2. **Configure the environment**.  Copy `.env.sample` to `.env` and set your Google Cloud
   project ID, BigQuery dataset, Jira credentials, and other settings as needed.
3. **Deploy the Cloud Function**.  Use the provided `setup.sh` script (or write your own
   Terraform) to create the BigQuery dataset and deploy the Cloud Function.  The function
   entry point is `kev_pipeline` in `cloudfunction/main.py`.
4. **Set up scheduled runs**.  Use Cloud Scheduler or your preferred scheduler to invoke the
   function regularly.  You can enable health mode via an environment variable or URL
   parameter.

See the `dashboard/` directory for a Looker Studio dashboard template and the `examples/`
directory for sample inventory data.

An architecture diagram is provided in `diagrams/kevlar_architecture.mmd` and
`diagrams/kevlar_architecture.png`.  The Mermaid source can be rendered using the
Mermaid CLI (`mmdc`), and the PNG file is a conceptual flow chart generated
for quick reference.

## Roadmap

This is a work in progress.  Planned enhancements include:

* Deduplication of per‑match alerts via a sent‑alert hash table.
* Additional inventory connectors (e.g. SentinelOne, CrowdStrike, Tanium).
* A simple Slackbot for natural‑language queries about KEVs.
* Integration with ExploitIQ (our LLM‑powered summarization engine).

## ExploitIQ

ExploitIQ is a proprietary add‑on for Kevlar that brings natural‑language AI
into your vulnerability workflow.  As our tagline says, it's so easy even
your CISO can use it.  See `exploit-iq/README.md` for more details.

## License

Kevlar is source‑available under the Business Source License v1.1.  See the `LICENSE` file for
details.
