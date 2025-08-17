"""Jira ticket creation helpers for Kevlar alerts."""
import os
import logging
from datetime import datetime
import pandas as pd
from jira import JIRA

logger = logging.getLogger('kev-pipeline')

def _df_to_markdown(df: pd.DataFrame, max_rows: int = 25) -> str:
    """Render a small, readable Markdown table for Jira."""
    view = df[['Computer_Name','Application_Title','_Application_Version','cve_id','patched_version']].head(max_rows)
    headers = ["Endpoint","App","Version","CVE","Required"]
    lines = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join(["---"] * len(headers)) + " |"]
    for _, r in view.iterrows():
        lines.append(f"| {r['Computer_Name']} | {r['Application_Title']} | {r['_Application_Version']} | {r['cve_id']} | {r['patched_version']} |")
    if len(df) > max_rows:
        lines.append(f"\n_Showing first {max_rows} of {len(df)} matches._")
    return "\n".join(lines)

def create_jira_ticket(row: pd.Series) -> str | None:
    """
    Create a Jira ticket for a single correlation match.
    Returns issue key or None on failure.
    """
    try:
        jira = JIRA(
            server=os.environ['JIRA_URL'],
            basic_auth=(os.environ['JIRA_USER'], os.environ['JIRA_TOKEN']),
            options={'verify': True}
        )
        summary = f"[KEV] {row['cve_id']} – {row['Application_Title']} on {row['Computer_Name']}"
        description = (
            f"*Endpoint:* {row['Computer_Name']}\n"
            f"*App:* {row['Application_Title']}\n"
            f"*Version:* {row['_Application_Version']}\n"
            f"*CVE:* {row['cve_id']}\n"
            f"*Patched:* {row['patched_version']}\n"
        )
        issue_fields = {
            'project': {'key': os.environ.get('JIRA_PROJECT_KEY', 'ITSEC')},
            'summary': summary,
            'description': description,
            'issuetype': {'name': 'Task'},
            'labels': ['kev', 'vulnerability']
        }
        issue = jira.create_issue(fields=issue_fields)
        logger.info(f"Ticket created: {issue.key}")
        return issue.key
    except Exception as e:
        logger.error(f"Failed to create ticket: {e}")
        return None

def create_health_ticket(df: pd.DataFrame) -> str | None:
    """
    Create a single weekly health/status ticket.
    If df is empty -> 'No KEVs found' message.
    Otherwise -> include a summary + small table; optionally attach CSV.
    """
    try:
        jira = JIRA(
            server=os.environ['JIRA_URL'],
            basic_auth=(os.environ['JIRA_USER'], os.environ['JIRA_TOKEN']),
            options={'verify': True}
        )

        found = not df.empty
        summary = "[HEALTH] KEV Pipeline Weekly Status – KEVs FOUND" if found else "[HEALTH] KEV Pipeline Weekly Status – No KEVs Found"

        if found:
            body_top = (
                f"*Status:* :warning: KEV matches detected\n"
                f"*Total endpoints impacted:* {len(df)}\n"
                f"*Generated:* {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')}\n\n"
                f"*Top matches:*\n"
            )
            body_table = _df_to_markdown(df, max_rows=25)
            description = body_top + body_table
        else:
            description = (
                "*Status:* ✅ No KEV matches across JAMF-managed apps\n"
                f"*Generated:* {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')}\n"
            )

        issue_fields = {
            'project': {'key': os.environ.get('JIRA_PROJECT_KEY', 'ITSEC')},
            'summary': summary,
            'description': description,
            'issuetype': {'name': 'Task'},
            'labels': ['kev', 'vulnerability', 'healthcheck']
        }
        issue = jira.create_issue(fields=issue_fields)
        logger.info(f"Health ticket created: {issue.key}")

        if found and os.environ.get('ATTACH_CSV', 'false').lower() == 'true':
            csv_path = '/tmp/kev_health_matches.csv'
            df.to_csv(csv_path, index=False)
            jira.add_attachment(issue=issue, attachment=csv_path)
            logger.info("Attached full CSV to health ticket")
        return issue.key

    except Exception as e:
        logger.error(f"Failed to create health ticket: {e}")
        return None
