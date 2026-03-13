# =============================================================================
# classifier.py — Asset Type Classification
# =============================================================================
# Classifies discovered assets based on subdomain keywords and open ports.
# Uses ONLY the first label of the hostname (subdomain).
# Prevents false positives from substring matches.
# =============================================================================

import logging
from typing import List, Dict

logger = logging.getLogger("discovery")

# ---------------------------------------------------------------------------
# Keyword → Asset Type mapping
# Exact match or prefix match only.
# ---------------------------------------------------------------------------
_KEYWORD_MAP: List[tuple[List[str], str]] = [

    # API services
    (["api", "rest", "graphql"], "API"),

    # VPN / remote access
    (["vpn", "remote", "access", "connect", "ras"], "VPN"),

    # Mail services
    (["mail", "smtp", "imap", "pop", "pop3", "mx", "exchange", "webmail", "email"], "MAIL"),

    # Documentation
    (["docs", "doc", "documentation", "wiki", "help", "kb", "faq"], "DOCUMENTATION"),

    # Monitoring
    (["monitor", "monitoring", "status", "health", "grafana",
      "prometheus", "nagios", "zabbix", "kibana"], "MONITORING"),

    # CI / build systems
    (["repo", "repository", "svn", "jenkins", "ci", "cd", "build", "deploy", "sonar"], "CI_CD"),

    # Authentication
    (["auth", "oauth", "sso", "login", "signin", "identity"], "AUTH"),

    # Admin portals
    (["admin", "administrator", "manage", "management", "portal",
      "panel", "console", "cpanel", "dashboard", "control"], "ADMIN"),

    # CDN / static content
    (["cdn", "static", "assets", "media", "images", "img", "files"], "CDN"),

    # Databases
    (["db", "database", "sql", "mysql", "postgres", "mongo",
      "redis", "elastic", "elasticsearch"], "DATABASE"),

    # Storage
    (["backup", "bak", "storage", "s3", "bucket", "ftp", "sftp"], "STORAGE"),

    # Container / infrastructure
    (["docker", "k8s", "kubernetes", "registry", "harbor", "rancher"], "INFRASTRUCTURE"),

    # Network infrastructure
    (["proxy", "gateway", "gw", "lb", "loadbalancer", "cache", "ns", "dns"], "NETWORK"),

    # Development environments
    (["dev", "test", "testing", "qa", "stage", "staging", "sandbox",
      "demo", "preview", "beta", "alpha", "uat", "canary"], "DEVELOPMENT"),

    # Commerce
    (["shop", "store", "ecommerce", "pay", "payment"], "ECOMMERCE"),
]

# ---------------------------------------------------------------------------
# Port based fallback classification
# ---------------------------------------------------------------------------
_PORT_TYPE_MAP: Dict[int, str] = {
    22: "INFRASTRUCTURE",
    465: "MAIL",
    993: "MAIL",
    995: "MAIL",
    636: "INFRASTRUCTURE",
    500: "VPN",
    1194: "VPN",
}


def classify_asset(host: str, services: List[Dict[str, object]]) -> str:
    """
    Classify an asset based on subdomain keyword and open ports.

    Priority:
        1. Subdomain keyword matching
        2. Port-based heuristic
        3. Default WEB

    Args:
        host: Fully qualified hostname
        services: list of open services

    Returns:
        Asset type string
    """

    parts = host.lower().split(".")

    # Root domain → always WEB
    if len(parts) <= 2:
        logger.debug("[Classifier] %s → WEB (root domain)", host)
        return "WEB"

    subdomain = parts[0]

    # ---------------------------------------------------------
    # Step 1 — Keyword classification
    # ---------------------------------------------------------
    for keywords, asset_type in _KEYWORD_MAP:
        for keyword in keywords:

            # exact match OR prefix match
            if subdomain == keyword or subdomain.startswith(keyword + "-"):
                logger.debug(
                    "[Classifier] %s → %s (keyword match: %s)",
                    host,
                    asset_type,
                    keyword,
                )
                return asset_type

    # ---------------------------------------------------------
    # Step 2 — Port fallback
    # ---------------------------------------------------------
    open_ports = {svc.get("port") for svc in services}

    for port, asset_type in _PORT_TYPE_MAP.items():
        if port in open_ports:
            logger.debug(
                "[Classifier] %s → %s (port match: %d)",
                host,
                asset_type,
                port,
            )
            return asset_type

    # ---------------------------------------------------------
    # Step 3 — Default
    # ---------------------------------------------------------
    logger.debug("[Classifier] %s → WEB (default)", host)
    return "WEB"