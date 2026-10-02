from __future__ import annotations

from ..scanner import CheckSpec
from .content import check_content
from .cookies import check_cookies
from .cors import check_cors
from .exposure import check_exposure
from .headers import check_headers
from .tls import check_tls

# Order is the order checks run in. `per_page` checks also run on every crawled page;
# the rest run once per origin. "exposure" is the only group that makes a meaningful
# number of extra requests (light probing).
CHECKS: dict[str, CheckSpec] = {
    "headers": CheckSpec(check_headers, per_page=True),
    "cookies": CheckSpec(check_cookies, per_page=True),
    "content": CheckSpec(check_content, per_page=True),
    "cors": CheckSpec(check_cors, per_page=False),
    "tls": CheckSpec(check_tls, per_page=False),
    "exposure": CheckSpec(check_exposure, per_page=False),
}
