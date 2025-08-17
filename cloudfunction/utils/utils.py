"""General utility functions for Kevlar."""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def create_session() -> requests.Session:
    """
    Create a requests Session configured with retry logic.
    Retries on common transient HTTP errors with exponential backoff.
    """
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session
