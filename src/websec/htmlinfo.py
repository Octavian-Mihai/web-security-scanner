"""Extract the security-relevant parts of an HTML document."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser

# <link rel=...> values that make the browser fetch a subresource (mixed-content relevant).
_FETCHING_RELS = {"stylesheet", "icon", "shortcut", "preload", "modulepreload", "manifest"}
_SRC_TAGS = {"img", "iframe", "embed", "source", "audio", "video", "track", "frame"}


@dataclass(frozen=True)
class Resource:
    tag: str  # "script" | "link"
    url: str
    integrity: str | None


@dataclass(frozen=True)
class Ref:
    tag: str
    attr: str
    url: str


@dataclass
class PageInfo:
    resources: list[Resource] = field(default_factory=list)  # scripts and stylesheets
    refs: list[Ref] = field(default_factory=list)  # anything the browser loads/submits to
    links: list[str] = field(default_factory=list)  # <a href>, for crawling


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.info = PageInfo()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.info.resources.append(Resource("script", a["src"], a.get("integrity") or None))
            self.info.refs.append(Ref("script", "src", a["src"]))
        elif tag == "link" and a.get("href"):
            rels = set(a.get("rel", "").lower().split())
            if "stylesheet" in rels:
                self.info.resources.append(Resource("link", a["href"], a.get("integrity") or None))
            if rels & _FETCHING_RELS:
                self.info.refs.append(Ref("link", "href", a["href"]))
        elif tag in _SRC_TAGS and a.get("src"):
            self.info.refs.append(Ref(tag, "src", a["src"]))
        elif tag == "form" and a.get("action"):
            self.info.refs.append(Ref("form", "action", a["action"]))
        elif tag == "a" and a.get("href"):
            self.info.links.append(a["href"])


def parse_html(text: str) -> PageInfo:
    collector = _Collector()
    collector.feed(text)
    collector.close()
    return collector.info
