"""URL extraction and domain helpers."""
from __future__ import annotations

import html
import ipaddress
import re
from html.parser import HTMLParser
from typing import List
from urllib.parse import urlparse

from .models import Link

URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'\)\]\}]+""")

SECOND_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.in", "net.in",
                "org.in", "ac.in", "gov.in", "co.jp", "com.br", "co.nz", "co.za"}
FILE_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "png", "jpg", "jpeg",
             "gif", "txt", "zip", "html", "htm", "csv", "exe"}


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[Link] = []
        self._href = None
        self._text: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(Link(self._href.strip(), " ".join("".join(self._text).split())))
            self._href = None


def _is_web(url: str) -> bool:
    return url.lower().startswith(("http://", "https://", "www."))


def extract_links(body: str) -> List[Link]:
    """Find <a href> links (with display text) and bare URLs in the email body."""
    parser = _AnchorParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:  # malformed HTML should never crash the detector
        pass
    links = [l for l in parser.links if _is_web(l.url)]
    seen = {l.url for l in links}
    for m in URL_RE.finditer(html.unescape(body)):
        url = m.group(0).rstrip(".,;:!?'\"")
        if url not in seen:
            links.append(Link(url))
            seen.add(url)
    return links


def get_host(url: str) -> str:
    u = url.strip()
    if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", u):
        u = "http://" + u
    try:
        return (urlparse(u).hostname or "").lower()
    except ValueError:
        return ""


def registered_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def looks_like_domain(text: str) -> bool:
    """True if the visible link text itself looks like a URL/domain (not a filename)."""
    t = text.strip()
    if not t or " " in t:
        return False
    if re.match(r"(?i)^(https?://|www\.)\S+$", t):
        return True
    m = re.match(r"(?i)^[\w-]+(\.[\w-]+)*\.([a-z]{2,24})(/\S*)?$", t)
    return bool(m) and m.group(2).lower() not in FILE_EXTS
