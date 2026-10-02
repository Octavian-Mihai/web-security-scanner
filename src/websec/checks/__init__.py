from __future__ import annotations

from ..scanner import Check
from .cookies import check_cookies
from .cors import check_cors
from .exposure import check_exposure
from .headers import check_headers
from .tls import check_tls

# Order is the order checks run in. "exposure" is the only group that makes
# additional requests beyond a CORS probe, so it is documented as "light probing".
CHECKS: dict[str, Check] = {
    "headers": check_headers,
    "cookies": check_cookies,
    "cors": check_cors,
    "tls": check_tls,
    "exposure": check_exposure,
}
