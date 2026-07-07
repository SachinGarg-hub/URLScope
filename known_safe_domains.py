"""
Shared allowlist of well-known, established domains.

Used in two places:
  1. train_model.py — added as extra root-domain safe training examples.
  2. app.py — as a runtime dampening/override so that subdomains and paths
     of these domains (e.g. netbanking.hdfcbank.com/login) aren't flagged
     purely because they contain generic security keywords like "login"
     or "secure", which legitimate banking/portal pages use just as much
     as phishing pages do. Pure lexical ML can't reliably tell these apart;
     a domain-reputation allowlist is the standard mitigation used by real
     phishing-detection systems (e.g. Google Safe Browsing) alongside ML.

NOTE: this is not a substitute for a real threat-intel/reputation feed —
it's a small, explicit, auditable list for known institutions relevant to
this project (top global sites + Indian banks/education/government). Extend
it as needed; don't rely on it as the sole safety mechanism.
"""

KNOWN_SAFE_DOMAINS = {
    "google.com", "wikipedia.org", "youtube.com", "amazon.com", "microsoft.com",
    "apple.com", "facebook.com", "instagram.com", "linkedin.com", "github.com",
    "stackoverflow.com", "reddit.com", "netflix.com", "twitter.com", "x.com",
    "whatsapp.com", "amity.edu", "harvard.edu", "mit.edu", "stanford.edu",
    "iitb.ac.in", "iitd.ac.in", "du.ac.in", "ugc.ac.in", "aicte-india.org",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "rbi.org.in",
    "onlinesbi.sbi", "netbanking.hdfcbank.com", "pnbindia.in",
    "gov.in", "india.gov.in", "incometax.gov.in", "uidai.gov.in",
    "paypal.com", "adobe.com", "cloudflare.com", "mozilla.org",
}


def registrable_domain(hostname: str) -> str:
    """Best-effort eTLD+1 extraction consistent with features._host_parts.
    Good enough for allowlist matching against the curated list above
    (which only contains simple .com/.org/.edu/.co.in/.ac.in/.gov.in style
    domains, not domains needing full public-suffix-list handling)."""
    hostname = (hostname or "").lower().strip(".")
    if not hostname:
        return ""
    parts = hostname.split(".")
    if len(parts) < 2:
        return hostname
    # handle common compound TLDs used in KNOWN_SAFE_DOMAINS (co.in, ac.in, gov.in)
    compound = {"co.in", "ac.in", "gov.in", "org.in", "net.in", "com.au", "co.uk"}
    last_two = ".".join(parts[-2:])
    last_three = ".".join(parts[-3:]) if len(parts) >= 3 else last_two
    if last_two in compound and len(parts) >= 3:
        return last_three
    return last_two


def is_known_safe(hostname: str) -> bool:
    domain = registrable_domain(hostname)
    return domain in KNOWN_SAFE_DOMAINS or hostname.lower() in KNOWN_SAFE_DOMAINS
