"""
Shared allowlist of well-known, established domains.

The actual list lives in `known_safe_domains.txt` (plain text, one domain
per line) so it can be extended without touching any Python code — just
add a line to the .txt file. This module loads that file and exposes the
matching logic used in two places:

  1. train_model.py — added as extra root-domain safe training examples.
  2. app.py — as a runtime dampening/override so that subdomains and paths
     of these domains (e.g. netbanking.hdfcbank.com/login) aren't flagged
     purely because they contain generic security keywords like "login"
     or "secure", which legitimate banking/portal pages use just as much
     as phishing pages do. Pure lexical ML can't reliably tell these apart;
     a domain-reputation allowlist is the standard mitigation used by real
     phishing-detection systems (e.g. Google Safe Browsing) alongside ML.

NOTE: this is not a substitute for a real threat-intel/reputation feed —
it's a small, explicit, auditable, easily-extensible list. Extend
known_safe_domains.txt as needed; don't rely on it as the sole safety
mechanism, since it can never cover every legitimate domain that exists.
"""
from pathlib import Path

_LIST_PATH = Path(__file__).parent / "known_safe_domains.txt"

# Minimal fallback used only if the .txt file is missing (e.g. a stray
# environment), so the app doesn't crash outright.
_FALLBACK_DOMAINS = {"google.com", "wikipedia.org"}


def _load_domains() -> set:
    if not _LIST_PATH.exists():
        return set(_FALLBACK_DOMAINS)
    domains = set()
    for line in _LIST_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        domains.add(line)
    return domains or set(_FALLBACK_DOMAINS)


KNOWN_SAFE_DOMAINS = _load_domains()


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
    # handle common compound TLDs used in known_safe_domains.txt (co.in, ac.in, gov.in, etc.)
    compound = {"co.in", "ac.in", "gov.in", "org.in", "net.in", "nic.in", "com.au", "co.uk"}
    last_two = ".".join(parts[-2:])
    last_three = ".".join(parts[-3:]) if len(parts) >= 3 else last_two
    if last_two in compound and len(parts) >= 3:
        return last_three
    return last_two


def is_known_safe(hostname: str) -> bool:
    domain = registrable_domain(hostname)
    return domain in KNOWN_SAFE_DOMAINS or hostname.lower() in KNOWN_SAFE_DOMAINS
