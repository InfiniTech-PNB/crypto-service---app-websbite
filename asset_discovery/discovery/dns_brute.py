# =============================================================================
# dns_brute.py — Active Subdomain Discovery via DNS Brute Force
# =============================================================================
# Brute-forces subdomains using a comprehensive list of 80+ common prefixes.
# Uses socket.gethostbyname_ex() for fast resolution.
# Runs concurrently with ThreadPoolExecutor for high throughput.
# =============================================================================

import socket
import logging
from typing import Set
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger("discovery")

# ---------------------------------------------------------------------------
# 80+ common subdomain prefixes for comprehensive coverage
# Covers: infrastructure, dev/staging, mail, security, CI/CD, monitoring, etc.
# ---------------------------------------------------------------------------
DNS_PREFIXES: list[str] = [
    # --- Standard web & infrastructure ---
    "www", "www2", "www3",
    "api", "api2", "api-v2", "rest", "graphql",
    "app", "apps", "web", "webapp",

    # --- Mail & messaging ---
    "mail", "mail2", "smtp", "imap", "pop", "pop3", "mx", "exchange",
    "webmail", "email",

    # --- VPN & remote access ---
    "vpn", "vpn2", "remote", "access", "connect", "ras", "gateway", "gw",

    # --- Development & staging ---
    "dev", "dev2", "development",
    "test", "testing", "qa",
    "stage", "staging", "stg",
    "sandbox", "demo", "preview",
    "beta", "alpha", "canary",
    "uat",

    # --- Administration ---
    "admin", "administrator", "manage", "management",
    "portal", "panel", "console", "cpanel",
    "dashboard", "control",

    # --- Documentation & knowledge ---
    "docs", "doc", "documentation",
    "wiki", "help", "support", "kb", "faq",
    "blog",

    # --- Source code & CI/CD ---
    "git", "gitlab", "github", "bitbucket",
    "repo", "repository", "svn",
    "jenkins", "ci", "cd", "build", "deploy",
    "artifactory", "nexus", "sonar",

    # --- CDN & static assets ---
    "cdn", "cdn2", "static", "assets", "media", "images", "img",
    "files", "download", "downloads",

    # --- Authentication & security ---
    "auth", "oauth", "sso", "login", "signin", "id", "identity",
    "secure", "ssl", "cert", "certs",

    # --- Monitoring & status ---
    "monitor", "monitoring", "status",
    "health", "metrics", "grafana", "prometheus",
    "nagios", "zabbix", "elk", "kibana",
    "logs", "log", "syslog",

    # --- Databases & data ---
    "db", "database", "sql", "mysql", "postgres", "mongo", "redis",
    "data", "analytics", "warehouse",
    "elastic", "elasticsearch",

    # --- Infrastructure ---
    "proxy", "reverse", "lb", "loadbalancer",
    "cache", "memcached", "varnish",
    "ns", "ns1", "ns2", "dns",
    "ftp", "sftp",
    "backup", "bak",

    # --- Containers & orchestration ---
    "docker", "k8s", "kubernetes",
    "registry", "harbor", "rancher",

    # --- Cloud & services ---
    "cloud", "aws", "azure", "gcp",
    "s3", "storage", "bucket",
    "internal", "intranet", "extranet",
    "shop", "store", "ecommerce", "pay", "payment",
    "crm", "erp", "jira", "confluence",
]


def _try_resolve(host: str) -> str | None:
    """
    Attempt to resolve a hostname using socket.gethostbyname_ex().

    Fast and lightweight — used during brute force to confirm existence.
    Does NOT validate the IP (that happens in resolver.py later).

    Args:
        host: Fully qualified hostname to resolve.

    Returns:
        The hostname if it resolves, None otherwise.
    """
    try:
        socket.gethostbyname_ex(host)
        return host
    except (socket.gaierror, socket.herror, socket.timeout, OSError):
        return None


def discover_from_dns(domain: str, max_workers: int = 20) -> Set[str]:
    """
    Brute-force subdomain discovery using common prefixes.

    Generates candidate hostnames by prepending each prefix to the domain,
    then resolves them concurrently using socket.gethostbyname_ex().
    Only hostnames that actually resolve are returned.

    Args:
        domain: Root domain (e.g. "github.com").
        max_workers: Number of concurrent threads for DNS resolution.

    Returns:
        Set of hostnames that successfully resolved.
    """
    domain = domain.lower().strip(".")
    candidates: list[str] = []

    # Generate candidate hostnames from prefix list
    for prefix in DNS_PREFIXES:
        candidate = f"{prefix}.{domain}"
        candidates.append(candidate)

    logger.info(
        "[Discovery] DNS brute force: testing %d candidates for %s",
        len(candidates),
        domain,
    )

    discovered: Set[str] = set()

    # Resolve all candidates concurrently
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {
            executor.submit(_try_resolve, host): host for host in candidates
        }

        for future in as_completed(future_to_host):
            try:
                result = future.result()
                if result:
                    discovered.add(result)
            except Exception as e:
                host = future_to_host[future]
                logger.debug("[Discovery] DNS brute error for %s: %s", host, e)

    logger.info("[Discovery] DNS brute found %d hosts", len(discovered))
    return discovered
