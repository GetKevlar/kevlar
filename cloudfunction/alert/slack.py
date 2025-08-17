"""Slack alerting helpers for Kevlar."""
import os
import logging
import requests
import pandas as pd

logger = logging.getLogger('kev-pipeline')

def send_slack_notification(message: str) -> bool:
    """
    Send a simple Slack message via webhook.
    Returns True on success, False otherwise.
    """
    try:
        webhook_url = os.environ['SLACK_WEBHOOK_URL']
        resp = requests.post(webhook_url, json={'text': message})
        resp.raise_for_status()
        logger.info("Slack notification sent")
        return True
    except Exception as e:
        logger.error(f"Failed to send Slack notification: {e}")
        return False

def notify_health_summary(df: pd.DataFrame) -> bool:
    """
    Send a summary of KEV matches to Slack.
    Includes total impacted endpoints and top matches in a table-like format.
    """
    try:
        found = not df.empty
        if found:
            title = f":warning: KEV matches detected – {len(df)} endpoints impacted"
        else:
            title = ":white_check_mark: No KEV matches across managed endpoints"

        if found:
            top = df[['Computer_Name','Application_Title','_Application_Version','cve_id','patched_version']].head(10)
            rows = ["Endpoint | App | Version | CVE | Required", "---|---|---|---|---"]
            for _, r in top.iterrows():
                rows.append(f"{r['Computer_Name']} | {r['Application_Title']} | {r['_Application_Version']} | {r['cve_id']} | {r['patched_version']}")
            body = "\n".join(rows)
            text = f"{title}\n```{body}```"
        else:
            text = f"{title}"

        return send_slack_notification(text)
    except Exception as e:
        logger.error(f"Failed to send Slack health summary: {e}")
        return False
