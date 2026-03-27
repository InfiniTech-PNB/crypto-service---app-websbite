# =============================================================================
# dns_brute.py — Enhanced Active Subdomain Discovery via DNS Brute Force
# =============================================================================

import socket
import logging
from typing import Set
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger("discovery")

# -----------------------------------------------------------------------------
# YOUR ORIGINAL 80+ PREFIXES (UNCHANGED ✅)
# -----------------------------------------------------------------------------
DNS_PREFIXES: list[str] = [
    "www", "www2", "www3",
    "api", "api2", "api-v2", "rest", "graphql",
    "app", "apps", "web", "webapp",

    "mail", "mail2", "smtp", "imap", "pop", "pop3", "mx", "exchange",
    "webmail", "email",

    "vpn", "vpn2", "remote", "access", "connect", "ras", "gateway", "gw",

    "dev", "dev2", "development",
    "test", "testing", "qa",
    "stage", "staging", "stg",
    "sandbox", "demo", "preview",
    "beta", "alpha", "canary",
    "uat",

    "admin", "administrator", "manage", "management",
    "portal", "panel", "console", "cpanel",
    "dashboard", "control",

    "docs", "doc", "documentation",
    "wiki", "help", "support", "kb", "faq",
    "blog",

    "git", "gitlab", "github", "bitbucket",
    "repo", "repository", "svn",
    "jenkins", "ci", "cd", "build", "deploy",
    "artifactory", "nexus", "sonar",

    "cdn", "cdn2", "static", "assets", "media", "images", "img",
    "files", "download", "downloads",

    "auth", "oauth", "sso", "login", "signin", "id", "identity",
    "secure", "ssl", "cert", "certs",

    "monitor", "monitoring", "status",
    "health", "metrics", "grafana", "prometheus",
    "nagios", "zabbix", "elk", "kibana",
    "logs", "log", "syslog",

    "db", "database", "sql", "mysql", "postgres", "mongo", "redis",
    "data", "analytics", "warehouse",
    "elastic", "elasticsearch",

    "proxy", "reverse", "lb", "loadbalancer",
    "cache", "memcached", "varnish",
    "ns", "ns1", "ns2", "dns",
    "ftp", "sftp",
    "backup", "bak",

    "docker", "k8s", "kubernetes",
    "registry", "harbor", "rancher",

    "cloud", "aws", "azure", "gcp",
    "s3", "storage", "bucket",
    "internal", "intranet", "extranet",
    "shop", "store", "ecommerce", "pay", "payment",
    "crm", "erp", "jira", "confluence",
]

# -----------------------------------------------------------------------------
# NEW: Smart expansions (HIGH IMPACT 🔥)
# -----------------------------------------------------------------------------
COMMON_SUFFIXES = ["-dev", "-test", "-prod", "-stage", "-internal"]
COMMON_PREFIXES = ["dev", "test", "prod", "stage", "internal"]


def _try_resolve(host: str) -> str | None:
    try:
        socket.gethostbyname_ex(host)
        return host
    except (socket.gaierror, socket.herror, socket.timeout, OSError):
        return None


# -----------------------------------------------------------------------------
# NEW: Generate smarter candidates
# -----------------------------------------------------------------------------
def _generate_candidates(domain: str) -> Set[str]:
    candidates: Set[str] = set()

    # 1. Original prefixes (KEEP)
    for prefix in DNS_PREFIXES:
        candidates.add(f"{prefix}.{domain}")

    # 2. Prefix + suffix combos
    for prefix in DNS_PREFIXES:
        for suffix in COMMON_SUFFIXES:
            candidates.add(f"{prefix}{suffix}.{domain}")

    # 3. Nested subdomains (VERY IMPORTANT)
    for p1 in COMMON_PREFIXES:
        for p2 in DNS_PREFIXES:
            candidates.add(f"{p1}.{p2}.{domain}")

    return candidates


# -----------------------------------------------------------------------------
# MAIN FUNCTION
# -----------------------------------------------------------------------------
def discover_from_dns(domain: str, max_workers: int = 20) -> Set[str]:
    domain = domain.lower().strip(".")

    candidates = list(_generate_candidates(domain))

    logger.info(
        "[Discovery] DNS brute force: testing %d candidates for %s",
        len(candidates),
        domain,
    )

    discovered: Set[str] = set()

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