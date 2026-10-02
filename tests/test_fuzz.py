"""Parsers read attacker-controlled data (response headers and bodies): they must never raise."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from websec.checks.content import _redact
from websec.checks.cookies import parse_set_cookie
from websec.checks.headers import _hsts_max_age, csp_weaknesses, parse_csp
from websec.htmlinfo import parse_html

text = st.text(max_size=400)


@given(text)
def test_csp_parsing_never_raises(value):
    csp_weaknesses(parse_csp(value))


@given(text)
def test_set_cookie_parsing_never_raises(value):
    cookie = parse_set_cookie(value)
    if cookie is not None:
        assert isinstance(cookie.secure, bool) and isinstance(cookie.httponly, bool)
        cookie.samesite  # noqa: B018 - property must not raise


@given(text)
def test_hsts_parsing_never_raises(value):
    age = _hsts_max_age(value)
    assert age is None or age >= 0


@settings(max_examples=150)
@given(st.text(max_size=600) | st.from_regex(r"<(a|script|link|img|form)[^>]{0,80}>", fullmatch=False))
def test_html_parsing_never_raises(value):
    info = parse_html(value)
    assert isinstance(info.links, list)


@given(st.text(min_size=1))
def test_redaction_never_returns_full_long_token(token):
    assert len(_redact(token)) <= 15
