"""Correlation subpackage for Kevlar.

Modules in this package are responsible for retrieving endpoint inventory
information and matching it against KEV entries loaded into BigQuery.  Each
connector should return a Pandas DataFrame with at least the following
columns: Computer_Name, Application_Title, _Application_Version, and any
other metadata needed for matching.
"""
