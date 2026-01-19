"""
DNS Enumeration Module
Queries DNS records (A, AAAA, MX, TXT, NS, SOA) for a target domain
"""

import dns.resolver
import logging

logger = logging.getLogger(__name__)


def normalize_domain(domain: str) -> str:
    """
    Normalize domain input to avoid resolver issues
    """
    domain = domain.lower()
    domain = domain.replace("http://", "").replace("https://", "")
    domain = domain.split("/")[0].split(":")[0]
    return domain.rstrip(".")


def enumerate(domain: str) -> dict:
    """
    Enumerate DNS records for a domain

    Args:
        domain (str): Target domain name

    Returns:
        dict: DNS records by type
    """

    domain = normalize_domain(domain)

    results = {
        "domain": domain,
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "SOA": []
    }

    # Explicit resolver configuration (DO NOT trust system DNS)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [
        "8.8.8.8",   # Google
        "1.1.1.1",   # Cloudflare
        "9.9.9.9"    # Quad9
    ]
    resolver.timeout = 3
    resolver.lifetime = 5

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]

    for record_type in record_types:
        try:
            logger.debug(f"Querying {record_type} records for {domain}")
            answers = resolver.resolve(domain, record_type)

            for rdata in answers:
                if record_type == "MX":
                    results["MX"].append({
                        "priority": rdata.preference,
                        "server": str(rdata.exchange)
                    })

                elif record_type == "SOA":
                    results["SOA"].append({
                        "mname": str(rdata.mname),
                        "rname": str(rdata.rname),
                        "serial": rdata.serial
                    })

                else:
                    results[record_type].append(str(rdata))

            logger.info(
                f"Found {len(results[record_type])} "
                f"{record_type} record(s) for {domain}"
            )

        except dns.resolver.NoAnswer:
            logger.debug(f"No {record_type} records found for {domain}")

        except dns.resolver.NXDOMAIN:
            logger.error(f"Domain does not exist: {domain}")
            results["error"] = "Domain does not exist"
            return results

        except Exception as e:
            logger.warning(
                f"Failed {record_type} lookup for {domain} "
                f"using resolvers {resolver.nameservers}: {e}"
            )

    total = sum(len(v) for v in results.values() if isinstance(v, list))
    print(f"    [+] Found {total} DNS records")

    return results
