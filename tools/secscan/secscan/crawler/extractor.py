"""HTML and JavaScript extraction helpers."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup, Tag

from secscan.utils.models import Endpoint, FormDescriptor, FormInput

_SKIP_SCHEMES = ("mailto:", "javascript:", "tel:")
_API_PATTERN = re.compile(r"['\"](/(?:api|rest|graphql|v\d+)[^'\"\s<>]*)['\"]", re.IGNORECASE)
_ENDPOINT_PATTERN = re.compile(r"['\"](/[^'\"\s<>]*(?:api|auth|user|admin|search)[^'\"\s<>]*)['\"]", re.IGNORECASE)


def extract_links(html: str, base_url: str) -> list[str]:
    """Extract absolute links from anchor tags."""
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []

    for tag in soup.find_all("a", href=True):
        if not isinstance(tag, Tag):
            continue
        href = str(tag.get("href", "")).strip()
        if not href or href.startswith("#") or href.lower().startswith(_SKIP_SCHEMES):
            continue
        links.append(urljoin(base_url, href))

    return links


def extract_query_endpoints(url: str) -> list[Endpoint]:
    """Extract query parameters from URL as endpoint surfaces."""
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if not query:
        return []

    return [
        Endpoint(
            url=url,
            method="GET",
            params=tuple(query.keys()),
            source="link-query",
            content_type="query",
        )
    ]


def extract_forms(html: str, source_url: str) -> tuple[list[FormDescriptor], list[Endpoint]]:
    """Extract forms and convert to endpoint surfaces."""
    soup = BeautifulSoup(html, "html.parser")
    forms: list[FormDescriptor] = []
    endpoints: list[Endpoint] = []

    for form in soup.find_all("form"):
        if not isinstance(form, Tag):
            continue

        action = str(form.get("action", "")).strip()
        method = str(form.get("method", "GET")).upper()
        if method not in {"GET", "POST"}:
            method = "POST"

        target = urljoin(source_url, action) if action else source_url
        inputs: list[FormInput] = []

        for field in form.find_all(["input", "textarea", "select"]):
            if not isinstance(field, Tag):
                continue
            name = str(field.get("name", "")).strip()
            if not name:
                continue
            field_type = str(field.get("type", "text"))
            inputs.append(
                FormInput(
                    name=name,
                    input_type=field_type,
                    required=field.has_attr("required"),
                )
            )

        if not inputs:
            continue

        forms.append(
            FormDescriptor(
                source_url=source_url,
                action=target,
                method=method,
                inputs=inputs,
            )
        )

        endpoints.append(
            Endpoint(
                url=target,
                method=method,
                params=tuple(dict.fromkeys(inp.name for inp in inputs)),
                source="html-form",
                content_type="form",
            )
        )

    return forms, endpoints


def extract_js_files(html: str, base_url: str) -> list[str]:
    """Extract external JavaScript file URLs."""
    soup = BeautifulSoup(html, "html.parser")
    js_files: list[str] = []

    for script in soup.find_all("script", src=True):
        if not isinstance(script, Tag):
            continue
        src = str(script.get("src", "")).strip()
        if not src:
            continue
        js_files.append(urljoin(base_url, src))

    return js_files


def extract_api_paths_from_text(content: str) -> set[str]:
    """Extract API-like endpoint paths from inline JavaScript/HTML."""
    paths = {match.group(1).strip() for match in _API_PATTERN.finditer(content)}
    paths.update(match.group(1).strip() for match in _ENDPOINT_PATTERN.finditer(content))
    return {path for path in paths if path.startswith("/")}
