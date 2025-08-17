"""Ingestion subpackage for Kevlar.

This package contains modules for retrieving vulnerability data from external
sources (such as the CISA Known Exploited Vulnerabilities catalog and the
MITRE CVE database) and loading it into BigQuery.  Each ingest module
implements a function that returns a list of records ready for insertion.
"""
