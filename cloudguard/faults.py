"""Deterministic collector fault injection used to demonstrate UNKNOWN results."""
from dataclasses import dataclass

from botocore.exceptions import ClientError


@dataclass
class FaultInjector:
    kind: str | None = None
    service: str | None = None
    # Three failures exhaust the collector's two bounded retries.
    remaining: int = 3

    def check(self, service: str):
        if self.kind and (self.service is None or self.service == service) and self.remaining > 0:
            self.remaining -= 1
            code = {
                "access_denied": "AccessDenied",
                "throttle": "Throttling",
                "timeout": "RequestTimeout",
            }.get(self.kind, "InternalError")
            raise ClientError({"Error": {"Code": code, "Message": "injected demo fault"}}, "CloudGuard")
