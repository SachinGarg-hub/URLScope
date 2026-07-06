import re
from urllib.parse import urlparse

def validate_url(user_input):
    url = user_input.strip()

    if not url:
        return False, "Please enter a URL."

    if " " in url:
        return False, "Invalid URL: spaces are not allowed."

    if re.fullmatch(r"[A-Za-z]+", url):
        return False, "Invalid URL: please enter a full domain like google.com."

    if "." not in url:
        return False, "Invalid URL: domain extension is missing, e.g., .com, .org, .in."

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if not domain:
        return False, "Invalid URL format."

    if domain.startswith((".", "-")) or domain.endswith((".", "-")):
        return False, "Invalid domain: domain cannot start or end with '.' or '-'."

    if ".." in domain:
        return False, "Invalid domain: consecutive dots are not allowed."

    # Reject IP addresses
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain):
        return False, "Invalid URL: IP addresses are not supported."

    # Check valid domain format
    domain_pattern = r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
    if not re.fullmatch(domain_pattern, domain):
        return False, "Invalid domain format."

    return True, url