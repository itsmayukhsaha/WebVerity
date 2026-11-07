"""DNS resolver wrapper using dnspython."""

import dns.exception
import dns.resolver
from backend.app.core.config import settings
from backend.app.core.logging import logger

RECORD_TYPES = ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]


class DNSResolutionResult:
    """Container for DNS query outcomes."""

    def __init__(
        self,
        domain: str,
        records: dict[str, list[str]],
        status: str,
        error_detail: str | None = None,
    ):
        self.domain = domain
        self.records = records
        self.status = status
        self.error_detail = error_detail


def query_dns(
    domain: str,
    timeout: float | None = None,
    lifetime: float | None = None,
) -> DNSResolutionResult:
    """Query DNS records for a given domain across standard record types.

    Args:
        domain: Target domain name to query.
        timeout: Query timeout in seconds.
        lifetime: Total query lifetime across retries.

    Returns:
        DNSResolutionResult containing resolved records and resolution status.
    """
    effective_timeout = timeout if timeout is not None else settings.DNS_TIMEOUT
    effective_lifetime = lifetime if lifetime is not None else (effective_timeout * 2)

    resolver = dns.resolver.Resolver()
    resolver.timeout = effective_timeout
    resolver.lifetime = effective_lifetime

    records: dict[str, list[str]] = {rtype: [] for rtype in RECORD_TYPES}
    status = "RESOLVED"
    error_detail = None
    has_any_records = False
    is_nxdomain = False

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                if rtype == "A" or rtype == "AAAA":
                    records[rtype].append(str(rdata.address))
                elif rtype == "MX":
                    records[rtype].append(
                        f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}"
                    )
                elif rtype == "TXT":
                    # Concatenate TXT strings
                    txt_strings = [part.decode("utf-8", errors="replace") for part in rdata.strings]
                    records[rtype].append("".join(txt_strings))
                elif rtype in ("CNAME", "NS"):
                    records[rtype].append(rdata.target.to_text().rstrip("."))
                else:
                    records[rtype].append(str(rdata))
                has_any_records = True
        except dns.resolver.NXDOMAIN:
            is_nxdomain = True
            break
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except dns.exception.Timeout:
            logger.warning(f"DNS query timed out for {domain} (type {rtype})")
            status = "TIMEOUT"
            error_detail = f"DNS query timed out for record {rtype}"
        except Exception as e:
            logger.debug(f"DNS query error for {domain} (type {rtype}): {e}")
            if status != "TIMEOUT":
                status = "ERROR"
                error_detail = str(e)

    if is_nxdomain:
        return DNSResolutionResult(
            domain=domain,
            records=records,
            status="NXDOMAIN",
            error_detail="Domain does not exist (NXDOMAIN)",
        )

    if not has_any_records and status == "RESOLVED":
        status = "NO_RECORDS"

    return DNSResolutionResult(
        domain=domain,
        records=records,
        status=status,
        error_detail=error_detail,
    )
