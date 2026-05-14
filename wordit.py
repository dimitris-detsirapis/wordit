#!/usr/bin/env python3
"""w0rd!t: an interactive wordlist builder for authorized security work."""

from __future__ import annotations

import argparse
import cmd
import getpass
import glob
import itertools
import json
import os
import random
import re
import shlex
import string
import sys
import textwrap
import time
import unicodedata
import zlib
from collections import Counter, OrderedDict
from dataclasses import dataclass, replace
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable, Iterator, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

try:
    import readline
except ImportError:  # pragma: no cover - Unix shells normally provide this.
    readline = None  # type: ignore[assignment]


APP_NAME = "w0rd!t"
VERSION = "1.2.0"
CREATOR_NAME = "Dimitris Detsirapis"
DEFAULT_MAX_CANDIDATES = 100_000
DEFAULT_MIN_LEN = 4
DEFAULT_MAX_LEN = 32
DEFAULT_SYMBOLS = ("!", "@", "#", "$", "_")
DEFAULT_SEPARATORS = ("", "_", "-", ".")
DEFAULT_NUMBERS = tuple(str(item) for item in range(10)) + ("12", "23", "69", "123", "1234", "007")
DEFAULT_CRAWL_USER_AGENT = f"{APP_NAME}/{VERSION} authorized-wordlist-builder"
WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9'_.-]{0,63}")
UNICODE_WORD_RE = re.compile(r"\w[\w'_.-]{0,63}", re.UNICODE)
DATE_SPLIT_RE = re.compile(r"[-_./\\\s]+")
URLISH_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(/.*)?$")
AI_CODE_FENCE_RE = re.compile(r"```(?:[A-Za-z0-9_-]+)?\s*(.*?)```", re.DOTALL)
URL_HOST_STOPWORDS = {
    "ai",
    "app",
    "co",
    "com",
    "dev",
    "edu",
    "gov",
    "http",
    "https",
    "in",
    "io",
    "linkedin",
    "net",
    "org",
    "www",
}
URL_PATH_STOPWORDS = {
    "in",
    "profile",
    "profiles",
    "user",
    "users",
}
META_TEXT_KEYS = {
    "application-name",
    "article:author",
    "article:section",
    "author",
    "description",
    "keywords",
    "name",
    "og:description",
    "og:site_name",
    "og:title",
    "profile:first_name",
    "profile:last_name",
    "profile:username",
    "title",
    "twitter:description",
    "twitter:site",
    "twitter:title",
}
CRAWL_SKIP_EXTENSIONS = {
    ".7z",
    ".avi",
    ".bmp",
    ".css",
    ".dmg",
    ".doc",
    ".docx",
    ".eot",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".iso",
    ".jar",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".mp3",
    ".mp4",
    ".ogg",
    ".otf",
    ".pdf",
    ".png",
    ".ppt",
    ".pptx",
    ".rar",
    ".svg",
    ".tar",
    ".tgz",
    ".ttf",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
    ".xls",
    ".xlsx",
    ".zip",
}
GITHUB_RESERVED_PATHS = {
    "about",
    "collections",
    "customer-stories",
    "enterprise",
    "events",
    "explore",
    "features",
    "github-copilot",
    "login",
    "marketplace",
    "new",
    "organizations",
    "orgs",
    "pricing",
    "readme",
    "search",
    "settings",
    "showcases",
    "sponsors",
    "topics",
}

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "cyan": "\033[36m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "magenta": "\033[35m",
    "red": "\033[31m",
}

STYLE_ALIASES = {
    "": "focused",
    "best": "focused",
    "default": "focused",
    "normal": "focused",
    "smart": "focused",
    "useful": "focused",
    "number": "numbers",
    "digit": "numbers",
    "digits": "numbers",
    "special": "symbols",
    "specials": "symbols",
    "symbol": "symbols",
    "symbols": "symbols",
    "numsym": "both",
    "mixed": "both",
    "capital": "caps",
    "capitalize": "caps",
    "capitalise": "caps",
    "case": "caps",
    "advanced": "wide",
}

MUTATION_STYLES = ("focused", "numbers", "symbols", "both", "caps", "quick", "wide")
TARGET_WORDLIST_TYPES = ("password-base", "subdomain", "directory", "cloud-resource")
TARGET_WORDLIST_ALIASES = {
    "cloud": "cloud-resource",
    "cloud_resource": "cloud-resource",
    "cloudresource": "cloud-resource",
    "dir": "directory",
    "dirs": "directory",
    "file": "directory",
    "files": "directory",
    "path": "directory",
    "paths": "directory",
    "password": "password-base",
    "passwords": "password-base",
    "sub": "subdomain",
    "subs": "subdomain",
    "dns": "subdomain",
}
WORDLIST_SIZE_CAPS = {
    "small": 25_000,
    "medium": 100_000,
    "large": 500_000,
}
AI_CONFIG_KEYS = (
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "W0RDIT_OPENAI_MODEL",
    "W0RDIT_GEMINI_MODEL",
)

LEET_MAP: dict[str, tuple[str, ...]] = {
    "a": ("4", "@"),
    "b": ("8",),
    "e": ("3",),
    "g": ("9",),
    "i": ("1", "!"),
    "l": ("1",),
    "o": ("0",),
    "s": ("5", "$"),
    "t": ("7",),
    "z": ("2",),
}

BUILTIN_MASK_CHARSETS: dict[str, str] = {
    "l": string.ascii_lowercase,
    "u": string.ascii_uppercase,
    "d": string.digits,
    "h": string.digits + "abcdef",
    "H": string.digits + "ABCDEF",
    "s": r"""!"#$%&'()*+,-./:;<=>@[]^_`{|}~""",
}
BUILTIN_MASK_CHARSETS["a"] = (
    BUILTIN_MASK_CHARSETS["l"]
    + BUILTIN_MASK_CHARSETS["u"]
    + BUILTIN_MASK_CHARSETS["d"]
    + BUILTIN_MASK_CHARSETS["s"]
)

INFRA_WORDS = (
    "api",
    "app",
    "admin",
    "auth",
    "cdn",
    "dev",
    "demo",
    "edge",
    "internal",
    "legacy",
    "mail",
    "mgmt",
    "mobile",
    "portal",
    "prod",
    "qa",
    "stage",
    "staging",
    "status",
    "test",
    "uat",
    "vpn",
    "www",
)
ENVIRONMENT_WORDS = ("dev", "test", "stage", "staging", "uat", "qa", "prod", "demo", "old", "new", "legacy")
DIRECTORY_BASE_PATHS = (
    "admin",
    "api",
    "api/v1",
    "api/v2",
    "assets",
    "backup",
    "backups",
    "config",
    "debug",
    "docs",
    "download",
    "files",
    ".env",
    ".env.local",
    ".env.prod",
    ".git/HEAD",
    ".git/config",
    "graphql",
    "health",
    "logs",
    "old",
    "portal",
    "private",
    "public",
    "static",
    "status",
    "test",
    "tmp",
    "upload",
    "uploads",
)
DIRECTORY_EXTENSIONS = ("bak", "old", "zip", "tar.gz", "sql", "log", "txt", "json", "yml", "conf", "php")
CLOUD_RESOURCE_WORDS = (
    "assets",
    "archive",
    "backup",
    "builds",
    "cache",
    "data",
    "exports",
    "files",
    "images",
    "internal",
    "logs",
    "prod",
    "public",
    "reports",
    "shared",
    "state",
    "staging",
    "test",
    "uploads",
)


def color_enabled() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def color(text: str, *styles: str) -> str:
    if not color_enabled():
        return text
    prefix = "".join(ANSI[style] for style in styles if style in ANSI)
    return f"{prefix}{text}{ANSI['reset']}" if prefix else text


def normalize_style(name: str) -> str:
    normalized = (name or "focused").strip().lower()
    return STYLE_ALIASES.get(normalized, normalized)


def default_ai_config_path() -> Path:
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return Path(os.environ.get("W0RDIT_AI_CONFIG", config_home / "w0rdit" / "ai.env"))


def mask_secret(value: str) -> str:
    if not value:
        return "not set"
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def ai_provider_label(provider: str) -> str:
    return "OpenAI" if provider == "openai" else "Gemini"


def read_ai_config(path: str | Path | None = None) -> dict[str, str]:
    config_path = Path(path) if path is not None else default_ai_config_path()
    if not config_path.exists():
        return {}
    values: dict[str, str] = {}
    for line in config_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in AI_CONFIG_KEYS:
            continue
        value = value.strip()
        if value.startswith('"') and value.endswith('"'):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = value[1:-1]
        values[key] = value
    return values


def write_ai_config(values: dict[str, str], path: str | Path | None = None) -> Path:
    config_path = Path(path) if path is not None else default_ai_config_path()
    current = read_ai_config(config_path)
    for key, value in values.items():
        if key not in AI_CONFIG_KEYS:
            continue
        if value:
            current[key] = value
        else:
            current.pop(key, None)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# w0rd!t AI API configuration", "# Keep this file private."]
    for key in AI_CONFIG_KEYS:
        if key in current:
            lines.append(f"{key}={json.dumps(current[key])}")
    config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(config_path, 0o600)
    return config_path


def load_ai_config(path: str | Path | None = None, overwrite: bool = False) -> list[str]:
    loaded: list[str] = []
    for key, value in read_ai_config(path).items():
        if overwrite or not os.environ.get(key):
            os.environ[key] = value
            loaded.append(key)
    return loaded


@dataclass(frozen=True)
class BuildOptions:
    min_len: int = DEFAULT_MIN_LEN
    max_len: int = DEFAULT_MAX_LEN
    max_candidates: int = DEFAULT_MAX_CANDIDATES
    preserve_unicode: bool = False
    case_modes: tuple[str, ...] = ("raw", "lower", "title")
    separators: tuple[str, ...] = DEFAULT_SEPARATORS
    years: tuple[str, ...] = ()
    numbers: tuple[str, ...] = DEFAULT_NUMBERS
    symbols: tuple[str, ...] = DEFAULT_SYMBOLS
    leet_depth: int = 1
    pair_limit: int = 40
    include_pairs: bool = True
    include_reverse: bool = True
    include_sandwich: bool = True


class WordBank:
    """Ordered, deduplicated word storage with light source tracking."""

    def __init__(self, preserve_unicode: bool = False) -> None:
        self._words: OrderedDict[str, str] = OrderedDict()
        self.preserve_unicode = preserve_unicode

    def __len__(self) -> int:
        return len(self._words)

    def __bool__(self) -> bool:
        return bool(self._words)

    def __iter__(self) -> Iterator[str]:
        return iter(self._words)

    def words(self) -> list[str]:
        return list(self._words)

    def clear(self) -> None:
        self._words.clear()

    def add(self, word: str, source: str = "manual", preserve_unicode: bool | None = None) -> bool:
        keep_unicode = self.preserve_unicode if preserve_unicode is None else preserve_unicode
        candidate = clean_candidate(word, preserve_unicode=keep_unicode)
        if not candidate:
            return False
        if candidate in self._words:
            return False
        self._words[candidate] = source
        return True

    def add_many(
        self,
        words: Iterable[str],
        source: str = "generated",
        preserve_unicode: bool | None = None,
    ) -> int:
        added = 0
        for word in words:
            if self.add(word, source=source, preserve_unicode=preserve_unicode):
                added += 1
        return added

    def stats(self) -> dict[str, object]:
        lengths = [len(word) for word in self._words]
        sources = Counter(self._words.values())
        return {
            "count": len(self._words),
            "min": min(lengths) if lengths else 0,
            "max": max(lengths) if lengths else 0,
            "avg": (sum(lengths) / len(lengths)) if lengths else 0.0,
            "sources": sources,
        }


class TextExtractor(HTMLParser):
    """Tiny HTML to text extractor for one-page harvesting."""

    def __init__(self) -> None:
        super().__init__()
        self._skip_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = tag.lower()
        attr_map = {name.lower(): value for name, value in attrs if value}
        if tag_name in {"script", "style", "noscript", "svg"}:
            self._skip_depth += 1
            return
        if tag_name == "meta":
            content = attr_map.get("content")
            key = attr_map.get("name") or attr_map.get("property") or attr_map.get("itemprop") or ""
            if content and key.lower() in META_TEXT_KEYS:
                self.parts.append(content)
        for attr_name in ("title", "alt", "aria-label"):
            value = attr_map.get(attr_name)
            if value:
                self.parts.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript", "svg"} and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.parts.append(data)

    def text(self) -> str:
        return " ".join(self.parts)


class LinkExtractor(HTMLParser):
    """Extract same-page links for bounded, authorized crawling."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                url = urljoin(self.base_url, value)
                parsed = urlparse(url)
                if parsed.scheme in {"http", "https"}:
                    normalized = parsed._replace(fragment="").geturl()
                    if any(parsed.path.lower().endswith(ext) for ext in CRAWL_SKIP_EXTENSIONS):
                        continue
                    self.links.append(normalized)


def current_year() -> int:
    return datetime.now().year


def recent_years(depth: int = 5) -> tuple[str, ...]:
    year = current_year()
    values: list[str] = []
    for item in range(year, year - depth, -1):
        values.append(str(item))
        values.append(str(item)[2:])
    return tuple(ordered_unique(values))


def ascii_fold(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return normalized.encode("ascii", "ignore").decode("ascii")


def clean_candidate(value: str, preserve_unicode: bool = False) -> str:
    value = str(value)
    value = unicodedata.normalize("NFKC", value) if preserve_unicode else ascii_fold(value)
    value = value.strip()
    value = re.sub(r"\s+", "", value)
    value = value.strip("\x00\r\n\t")
    return value


def ordered_unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def path_completions(text: str, include_files: bool = True, include_dirs: bool = True) -> list[str]:
    """Return readline-friendly path matches, adding a slash for directories."""
    raw = text or ""
    if raw.startswith(("http://", "https://")):
        return []
    expanded = os.path.expanduser(raw)
    pattern = expanded + "*" if expanded else "*"
    home = str(Path.home())
    matches: list[str] = []
    for match in sorted(glob.glob(pattern)):
        is_dir = os.path.isdir(match)
        if is_dir and not include_dirs:
            continue
        if not is_dir and not include_files:
            continue
        display = match
        if raw.startswith("~") and display.startswith(home):
            display = "~" + display[len(home) :]
        if is_dir:
            display += os.sep
        matches.append(display)
    return matches


def normalize_harvest_target(target: str) -> str:
    target = target.strip()
    if not target:
        return target
    if target.startswith(("http://", "https://")):
        return target
    if URLISH_RE.match(target) and not Path(target).expanduser().exists():
        return "https://" + target
    return target


def url_hint_text(url: str) -> str:
    parsed = urlparse(url)
    pieces: list[str] = []

    def add_piece_variants(value: str, stopwords: set[str]) -> None:
        value = value.strip()
        if not value:
            return
        split_parts = [
            part
            for part in re.split(r"[-_.~]+", value)
            if part and part.lower() not in stopwords
        ]
        if value.lower() not in stopwords:
            pieces.append(value)
        pieces.extend(split_parts)
        if len(split_parts) > 1:
            pieces.append("".join(split_parts))

    host = parsed.netloc.split("@")[-1].split(":")[0]
    if host:
        for label in host.split("."):
            add_piece_variants(label, URL_HOST_STOPWORDS)
    for segment in parsed.path.split("/"):
        add_piece_variants(segment, URL_PATH_STOPWORDS)
    return " ".join(ordered_unique(pieces))


def github_profile_name(url: str) -> str | None:
    parsed = urlparse(url)
    host = parsed.netloc.lower().split("@")[-1].split(":")[0]
    if host != "github.com":
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 1:
        return None
    username = parts[0]
    if username.lower() in GITHUB_RESERVED_PATHS:
        return None
    return username


def crawl_request_headers() -> dict[str, str]:
    user_agent = os.environ.get("W0RDIT_USER_AGENT", DEFAULT_CRAWL_USER_AGENT)
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,text/plain;q=0.7,*/*;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": user_agent,
    }


def is_harvestable_content_type(content_type: str) -> bool:
    media_type = content_type.split(";", 1)[0].strip().lower()
    if not media_type:
        return True
    if media_type.startswith("text/"):
        return True
    return media_type in {
        "application/json",
        "application/ld+json",
        "application/rss+xml",
        "application/xhtml+xml",
        "application/xml",
        "image/svg+xml",
    }


def decompress_http_payload(payload: bytes, content_encoding: str, max_bytes: int) -> bytes:
    decoded = payload
    encodings = [item.strip().lower() for item in content_encoding.split(",") if item.strip()]
    for encoding in reversed(encodings):
        if encoding in {"identity", "none"}:
            continue
        if encoding == "gzip":
            decoded = decompress_limited(decoded, 16 + zlib.MAX_WBITS, max_bytes)
            continue
        if encoding == "deflate":
            try:
                decoded = decompress_limited(decoded, zlib.MAX_WBITS, max_bytes)
            except zlib.error:
                decoded = decompress_limited(decoded, -zlib.MAX_WBITS, max_bytes)
            continue
        raise ValueError(f"Unsupported content encoding: {encoding}.")
    if len(decoded) > max_bytes:
        raise ValueError(f"Decoded response was larger than {max_bytes:,} bytes.")
    return decoded


def decompress_limited(payload: bytes, wbits: int, max_bytes: int) -> bytes:
    decompressor = zlib.decompressobj(wbits)
    decoded = decompressor.decompress(payload, max_bytes + 1)
    if len(decoded) > max_bytes or decompressor.unconsumed_tail:
        raise ValueError(f"Decoded response was larger than {max_bytes:,} bytes.")
    decoded += decompressor.flush(max_bytes + 1 - len(decoded))
    if len(decoded) > max_bytes:
        raise ValueError(f"Decoded response was larger than {max_bytes:,} bytes.")
    return decoded


def fetch_url_text(url: str, max_bytes: int = 2_000_000, timeout: int = 10) -> tuple[str, str]:
    request = Request(
        url,
        headers=crawl_request_headers(),
    )
    with urlopen(request, timeout=timeout) as response:
        payload = response.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise ValueError(f"Response was larger than {max_bytes:,} bytes.")
        content_type = response.headers.get("content-type", "")
        content_encoding = response.headers.get("content-encoding", "")
    if not is_harvestable_content_type(content_type):
        raise ValueError(f"Unsupported content type: {content_type}.")
    payload = decompress_http_payload(payload, content_encoding, max_bytes)
    charset = "utf-8"
    match = re.search(r"charset=([A-Za-z0-9_.-]+)", content_type)
    if match:
        charset = match.group(1)
    return payload.decode(charset, errors="ignore"), content_type


def json_to_harvest_text(value: object) -> str:
    parts: list[str] = []
    if isinstance(value, dict):
        for item in value.values():
            parts.append(json_to_harvest_text(item))
    elif isinstance(value, list):
        for item in value:
            parts.append(json_to_harvest_text(item))
    elif isinstance(value, (str, int, float)):
        text = str(value).strip()
        if text:
            parts.append(text)
    return " ".join(part for part in parts if part)


def github_profile_to_harvest_text(profile: object) -> str:
    if not isinstance(profile, dict):
        return ""
    fields = ("login", "name", "company", "blog", "location", "bio", "twitter_username")
    parts = [str(profile[field]) for field in fields if profile.get(field)]
    return " ".join(parts)


def harvest_github_profile(url: str, max_bytes: int = 2_000_000, timeout: int = 10) -> str | None:
    username = github_profile_name(url)
    if not username:
        return None
    api_base = f"https://api.github.com/users/{username}"
    request_headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"{APP_NAME}/{VERSION} authorized-wordlist-builder",
    }

    def fetch_json(api_url: str) -> object:
        request = Request(api_url, headers=request_headers)
        with urlopen(request, timeout=timeout) as response:
            payload = response.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise ValueError(f"Response was larger than {max_bytes:,} bytes.")
        return json.loads(payload.decode("utf-8", errors="ignore"))

    try:
        profile = fetch_json(api_base)
    except HTTPError:
        return None
    except (URLError, json.JSONDecodeError):
        return None

    parts = [username, url_hint_text(url), github_profile_to_harvest_text(profile)]
    try:
        repos = fetch_json(f"{api_base}/repos?per_page=100&sort=updated")
    except (HTTPError, URLError, json.JSONDecodeError, ValueError):
        repos = []
    if isinstance(repos, list):
        for repo in repos[:100]:
            if isinstance(repo, dict):
                for key in ("name", "full_name", "description", "language", "homepage"):
                    value = repo.get(key)
                    if value:
                        parts.append(str(value))
                topics = repo.get("topics")
                if isinstance(topics, list):
                    parts.extend(str(topic) for topic in topics)
    return " ".join(parts)


def extract_page_text_and_links(url: str, max_bytes: int = 2_000_000, timeout: int = 10) -> tuple[str, list[str]]:
    decoded, content_type = fetch_url_text(url, max_bytes=max_bytes, timeout=timeout)
    if "html" in content_type.lower() or "<html" in decoded[:500].lower():
        parser = TextExtractor()
        parser.feed(decoded)
        links = LinkExtractor(url)
        links.feed(decoded)
        return parser.text() + " " + url_hint_text(url), ordered_unique(links.links)
    if "json" in content_type.lower():
        try:
            return json_to_harvest_text(json.loads(decoded)) + " " + url_hint_text(url), []
        except json.JSONDecodeError:
            pass
    return decoded + " " + url_hint_text(url), []


def crawl_url_text(
    start_url: str,
    max_pages: int = 3,
    max_depth: int = 1,
    same_host_only: bool = True,
    timeout: int = 10,
    delay_range: tuple[float, float] = (0.5, 1.5),
) -> tuple[str, list[str], list[str]]:
    start_url = normalize_harvest_target(start_url)
    parsed_start = urlparse(start_url)
    queue: list[tuple[str, int]] = [(start_url, 0)]
    visited: set[str] = set()
    fetched: list[str] = []
    errors: list[str] = []
    text_parts: list[str] = []
    attempted = 0
    min_delay, max_delay = delay_range
    while queue and len(fetched) < max_pages:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        if attempted and max_delay > 0:
            time.sleep(random.uniform(max(0.0, min_delay), max(min_delay, max_delay)))
        attempted += 1
        try:
            github_text = harvest_github_profile(url, timeout=timeout)
            if github_text is not None:
                text = github_text
                links: list[str] = []
            else:
                text, links = extract_page_text_and_links(url, timeout=timeout)
        except HTTPError as exc:
            hint_text = url_hint_text(url)
            if hint_text:
                text_parts.append(hint_text)
            errors.append(f"{url}: HTTP {exc.code} {exc.reason}")
            continue
        except (URLError, ValueError) as exc:
            hint_text = url_hint_text(url)
            if hint_text:
                text_parts.append(hint_text)
            errors.append(f"{url}: {exc}")
            continue
        text_parts.append(text)
        fetched.append(url)
        if depth >= max_depth:
            continue
        for link in links:
            parsed_link = urlparse(link)
            if same_host_only and parsed_link.netloc != parsed_start.netloc:
                continue
            if link not in visited and len(queue) + len(fetched) < max_pages * 3:
                queue.append((link, depth + 1))
    return " ".join(text_parts), fetched, errors


def parse_ai_keywords(payload: str, preserve_unicode: bool = False) -> list[str]:
    payload = payload.strip()
    if not payload:
        return []
    for candidate in ai_json_payload_candidates(payload):
        try:
            decoded = json.loads(candidate)
            if isinstance(decoded, dict):
                values = decoded.get("keywords", [])
            else:
                values = decoded
            if isinstance(values, list):
                return ordered_unique(str(item) for item in values if str(item).strip())
        except json.JSONDecodeError:
            continue
    return extract_words(payload, min_len=2, max_len=32, lowercase=False, preserve_unicode=preserve_unicode)


def ai_json_payload_candidates(payload: str) -> list[str]:
    variants: list[str] = []

    def add(value: str) -> None:
        value = value.strip()
        if value and value not in variants:
            variants.append(value)

    add(payload)
    for match in AI_CODE_FENCE_RE.finditer(payload):
        add(match.group(1))
    for value in list(variants):
        for opener, closer in (("{", "}"), ("[", "]")):
            start = value.find(opener)
            end = value.rfind(closer)
            if start >= 0 and end > start:
                add(value[start : end + 1])
    return variants


def extract_openai_response_text(data: dict[str, object]) -> str:
    output_text = data.get("output_text")
    if isinstance(output_text, str):
        return output_text
    parts: list[str] = []
    output = data.get("output")
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if isinstance(content, list):
                for content_item in content:
                    if isinstance(content_item, dict):
                        text = content_item.get("text")
                        if isinstance(text, str):
                            parts.append(text)
    return "\n".join(parts)


def ai_keyword_prompt(text: str, max_keywords: int) -> str:
    clipped = text[:18_000]
    return textwrap.dedent(
        f"""
        You are helping with authorized password recovery and security training.
        Extract up to {max_keywords} useful seed words from the public/profile text below.
        Return only JSON in this exact shape: {{"keywords":["word","two word phrase"]}}.
        Prefer names, handles, projects, brands, teams, locations, repo names, interests,
        dates/years, short phrases, and distinctive terms. Do not invent private facts.

        TEXT:
        {clipped}
        """
    ).strip()


def ai_extract_keywords(
    provider: str,
    text: str,
    max_keywords: int = 80,
    model: str = "",
    preserve_unicode: bool = False,
) -> list[str]:
    provider = provider.strip().lower()
    prompt = ai_keyword_prompt(text, max_keywords)
    if provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set.")
        selected_model = model or os.environ.get("W0RDIT_OPENAI_MODEL", "gpt-4.1-mini")
        body = {
            "model": selected_model,
            "input": prompt,
            "instructions": "Return compact JSON only. No markdown.",
        }
        request = Request(
            "https://api.openai.com/v1/responses",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=45) as response:
                data = json.loads(response.read().decode("utf-8", errors="ignore"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")[:300]
            raise ValueError(f"OpenAI API error HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise ValueError(f"OpenAI API connection failed: {exc.reason}") from exc
        return parse_ai_keywords(extract_openai_response_text(data), preserve_unicode=preserve_unicode)

    if provider == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY is not set.")
        selected_model = model or os.environ.get("W0RDIT_GEMINI_MODEL", "gemini-2.5-flash")
        body = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt},
                    ],
                }
            ]
        }
        request = Request(
            f"https://generativelanguage.googleapis.com/v1beta/models/{selected_model}:generateContent",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=45) as response:
                data = json.loads(response.read().decode("utf-8", errors="ignore"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")[:300]
            raise ValueError(f"Gemini API error HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise ValueError(f"Gemini API connection failed: {exc.reason}") from exc
        parts: list[str] = []
        candidates = data.get("candidates")
        if isinstance(candidates, list):
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                content = candidate.get("content")
                if not isinstance(content, dict):
                    continue
                for part in content.get("parts", []):
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        parts.append(part["text"])
        return parse_ai_keywords("\n".join(parts), preserve_unicode=preserve_unicode)

    raise ValueError("Choose provider openai or gemini.")


def parse_human_list(value: str) -> list[str]:
    if not value:
        return []
    lexer = shlex.shlex(value, posix=True)
    lexer.whitespace += ",;"
    lexer.whitespace_split = True
    lexer.commenters = ""
    return [item.strip() for item in lexer if item.strip()]


def extract_words(
    text: str,
    min_len: int = 3,
    max_len: int = 32,
    lowercase: bool = True,
    include_numbers: bool = True,
    preserve_unicode: bool = False,
) -> list[str]:
    if preserve_unicode:
        text = unicodedata.normalize("NFKC", text)
        word_re = UNICODE_WORD_RE
    else:
        text = ascii_fold(text)
        word_re = WORD_RE
    words: list[str] = []
    for match in word_re.finditer(text):
        token = match.group(0).strip("'_.-")
        if not token:
            continue
        if not include_numbers and token.isdigit():
            continue
        if len(token) < min_len or len(token) > max_len:
            continue
        words.append(token.lower() if lowercase else token)
    return ordered_unique(words)


def normalize_target_wordlist_type(name: str) -> str:
    normalized = (name or "").strip().lower().replace("_", "-")
    normalized = TARGET_WORDLIST_ALIASES.get(normalized, normalized)
    if normalized not in TARGET_WORDLIST_TYPES:
        raise ValueError(f"Choose one of: {', '.join(TARGET_WORDLIST_TYPES)}.")
    return normalized


def seed_words_from_values(values: Iterable[str], preserve_unicode: bool = False) -> list[str]:
    seeds: list[str] = []
    for raw in values:
        raw_tokens = extract_words(
            str(raw),
            min_len=1,
            max_len=64,
            lowercase=True,
            preserve_unicode=preserve_unicode,
        )
        if len(raw_tokens) > 1:
            seeds.extend(raw_tokens)
            seeds.append("".join(raw_tokens))
            acronym = "".join(token[0] for token in raw_tokens if token)
            if acronym:
                seeds.append(acronym)
        for item in parse_human_list(str(raw)):
            tokens = extract_words(
                item,
                min_len=1,
                max_len=64,
                lowercase=True,
                preserve_unicode=preserve_unicode,
            )
            if len(tokens) > 1:
                seeds.append("".join(tokens))
                acronym = "".join(token[0] for token in tokens if token)
                if acronym:
                    seeds.append(acronym)
            seeds.extend(tokens)
    return ordered_unique(seeds)


def _lower_ascii(value: str) -> str:
    return ascii_fold(value).lower()


def _alnum_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", _lower_ascii(value))


def _hyphen_slug(value: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", _lower_ascii(value))).strip("-")


def _underscore_slug(value: str) -> str:
    return re.sub(r"_+", "_", re.sub(r"[^a-z0-9]+", "_", _lower_ascii(value))).strip("_")


def validate_typed_candidate(kind: str, value: str, preserve_unicode: bool = False) -> bool:
    kind = normalize_target_wordlist_type(kind)
    candidate = str(value)
    candidate = unicodedata.normalize("NFKC", candidate) if preserve_unicode else ascii_fold(candidate)
    candidate = candidate.strip()
    strip_chars = ",;:'\"`[]{}()" if kind == "directory" else ".,;:'\"`[]{}()"
    candidate = candidate.strip(strip_chars)
    if kind in {"subdomain", "cloud-resource"}:
        candidate = _lower_ascii(candidate)
    elif kind == "password-base" and not preserve_unicode:
        candidate = ascii_fold(candidate)
    if not candidate:
        return False
    if kind == "password-base":
        return 3 <= len(candidate) <= 30 and bool(re.fullmatch(r"[A-Za-z0-9]+", candidate))
    if kind == "subdomain":
        if not 1 <= len(candidate) <= 63 or "--" in candidate:
            return False
        return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", candidate))
    if kind == "directory":
        if not 1 <= len(candidate) <= 255:
            return False
        if candidate == ".":
            return False
        if candidate.startswith(("/", "\\")) or candidate.endswith(("/", "\\")):
            return False
        if ".." in candidate or "//" in candidate or "\\" in candidate:
            return False
        if "://" in candidate or "?" in candidate or "#" in candidate:
            return False
        return bool(re.fullmatch(r"[A-Za-z0-9\-_.~/]+", candidate))
    if kind == "cloud-resource":
        if not 3 <= len(candidate) <= 63:
            return False
        if any(bad in candidate for bad in ("--", "__", "-_", "_-")):
            return False
        return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?", candidate))
    return False


def clean_typed_candidate(kind: str, value: str, preserve_unicode: bool = False) -> str:
    kind = normalize_target_wordlist_type(kind)
    candidate = clean_candidate(value, preserve_unicode=preserve_unicode)
    strip_chars = ",;:'\"`[]{}()" if kind == "directory" else ".,;:'\"`[]{}()"
    candidate = candidate.strip(strip_chars)
    if kind in {"subdomain", "cloud-resource"}:
        candidate = _lower_ascii(candidate)
    if kind == "subdomain":
        candidate = _hyphen_slug(candidate)
    elif kind == "cloud-resource":
        candidate = re.sub(r"[^a-z0-9_-]+", "-", _lower_ascii(candidate)).strip("-_")
    elif kind == "password-base" and not preserve_unicode:
        candidate = ascii_fold(candidate)
    return candidate


def process_typed_candidates(
    kind: str,
    candidates: Iterable[str],
    limit: int = DEFAULT_MAX_CANDIDATES,
    preserve_unicode: bool = False,
) -> list[str]:
    kind = normalize_target_wordlist_type(kind)
    cleaned: list[str] = []
    for raw in candidates:
        candidate = clean_typed_candidate(kind, raw, preserve_unicode=preserve_unicode)
        if validate_typed_candidate(kind, candidate, preserve_unicode=preserve_unicode):
            cleaned.append(candidate)
        if len(cleaned) >= limit * 3:
            break
    return ordered_unique(cleaned)[:limit]


def _password_base_stream(seeds: Sequence[str]) -> Iterator[str]:
    bases = [_alnum_slug(seed) for seed in seeds]
    bases = [base for base in ordered_unique(bases) if base]
    for base in bases:
        yield base
        yield base.capitalize()
        yield base.upper()
        if base.endswith("s") and len(base) > 4:
            yield base[:-1]
        elif len(base) > 3:
            yield base + "s"
        if len(base) > 5:
            yield base[:4]
            yield base[:6]
    for left, right in itertools.permutations(bases[:16], 2):
        yield left + right
        if len(left) <= 8 and len(right) <= 8:
            yield left.capitalize() + right.capitalize()


def _subdomain_stream(seeds: Sequence[str]) -> Iterator[str]:
    bases = [_hyphen_slug(seed) for seed in seeds]
    bases = [base for base in ordered_unique(bases) if base]
    for base in bases:
        yield base
        for word in INFRA_WORDS:
            yield f"{base}-{word}"
            yield f"{word}-{base}"
        for env in ENVIRONMENT_WORDS:
            yield f"{base}-{env}"
            yield f"{env}-{base}"
        if len(base) <= 20:
            yield f"{base}api"
            yield f"{base}app"
    for left, right in itertools.permutations(bases[:12], 2):
        yield f"{left}-{right}"
        if len(left + right) <= 63:
            yield left + right
    for word in INFRA_WORDS:
        yield word
    for service in ("api", "app", "admin", "portal", "auth", "cdn", "vpn", "mail"):
        for env in ENVIRONMENT_WORDS[:8]:
            yield f"{service}-{env}"
            yield f"{env}-{service}"


def _directory_stream(seeds: Sequence[str]) -> Iterator[str]:
    bases = [_hyphen_slug(seed) for seed in seeds]
    bases = [base for base in ordered_unique(bases) if base]
    yield from DIRECTORY_BASE_PATHS
    for base in bases:
        yield base
        for ext in DIRECTORY_EXTENSIONS:
            yield f"{base}.{ext}"
        for env in ENVIRONMENT_WORDS:
            yield f"{base}-{env}"
            yield f"{base}_{env}"
            yield f"{env}-{base}"
            yield f"{env}_{base}"
        for folder in ("admin", "api", "assets", "backup", "backups", "config", "docs", "files", "logs", "static", "uploads"):
            yield f"{folder}/{base}"
            yield f"{base}/{folder}"
        yield f"api/{base}"
        yield f"api/v1/{base}"
        yield f"api/v2/{base}"
        yield f"uploads/{base}.zip"
        yield f"backups/{base}.tar.gz"
        yield f"config/{base}.yml"
        yield f"logs/{base}.log"
    for left, right in itertools.permutations(bases[:8], 2):
        yield f"{left}-{right}"
        yield f"{left}_{right}"
        yield f"{left}/{right}"


def _cloud_resource_stream(seeds: Sequence[str]) -> Iterator[str]:
    bases = [_hyphen_slug(seed) for seed in seeds]
    bases.extend(_underscore_slug(seed) for seed in seeds)
    bases = [base for base in ordered_unique(bases) if base]
    for base in bases:
        yield base
        for word in CLOUD_RESOURCE_WORDS:
            yield f"{base}-{word}"
            yield f"{word}-{base}"
        for env in ENVIRONMENT_WORDS:
            yield f"{base}-{env}"
            yield f"{env}-{base}"
        for word in ("data", "backup", "logs", "assets", "uploads", "archive"):
            for env in ("dev", "test", "prod", "stage"):
                yield f"{base}-{word}-{env}"
                yield f"{base}-{env}-{word}"
        yield f"{base}-tf-state"
        yield f"{base}-terraform-state"
        yield f"{base}-jenkins-artifacts"
        yield f"{base}-vendor-uploads"
    for left, right in itertools.permutations(bases[:10], 2):
        yield f"{left}-{right}"
        yield f"{left}-{right}-prod"
        yield f"{left}-{right}-backup"


def generate_typed_wordlist(
    kind: str,
    seeds: Sequence[str],
    limit: int = DEFAULT_MAX_CANDIDATES,
    preserve_unicode: bool = False,
) -> list[str]:
    kind = normalize_target_wordlist_type(kind)
    seed_words = seed_words_from_values(seeds, preserve_unicode=preserve_unicode)
    if not seed_words:
        return []
    if kind == "password-base":
        stream = _password_base_stream(seed_words)
    elif kind == "subdomain":
        stream = _subdomain_stream(seed_words)
    elif kind == "directory":
        stream = _directory_stream(seed_words)
    else:
        stream = _cloud_resource_stream(seed_words)
    return process_typed_candidates(kind, stream, limit=limit, preserve_unicode=preserve_unicode)


def typed_wordlist_seed_hints(kind: str) -> str:
    kind = normalize_target_wordlist_type(kind)
    if kind == "password-base":
        return "names, handles, pets, teams, cities, projects, products, hobbies, and memorable terms"
    if kind == "subdomain":
        return "company names, abbreviations, products, departments, locations, cloud providers, and technologies"
    if kind == "directory":
        return "frameworks, languages, server software, app purpose, product names, and known paths"
    return "company names, stock tickers, products, teams, projects, cloud provider, regions, and internal terms"


def typed_wordlist_usage(kind: str, output_name: str = "wordlist.txt") -> str:
    kind = normalize_target_wordlist_type(kind)
    if kind == "password-base":
        return f"Use with hashcat rules, for example: hashcat -a 0 -m <hash_type> hashes.txt {output_name} -r rules/best64.rule"
    if kind == "subdomain":
        return f"Use with DNS enumeration, for example: gobuster dns -d target.com -w {output_name}"
    if kind == "directory":
        return f"Use with web fuzzing, for example: ffuf -u https://target.com/FUZZ -w {output_name}"
    return f"Use with cloud enumeration tools, for example: cloud_enum -k {output_name} or provider-specific bucket checks"


def ai_wordlist_prompt(kind: str, seeds: Sequence[str], max_words: int, instructions: str = "") -> str:
    kind = normalize_target_wordlist_type(kind)
    seed_text = ", ".join(seed_words_from_values(seeds) or [str(seed) for seed in seeds])
    usage_focus = {
        "password-base": (
            "Generate clean alphanumeric base words for password auditing. "
            "Hashcat or w0rd!t will handle numbers, symbols, case, and leetspeak later."
        ),
        "subdomain": (
            "Generate DNS label candidates for subdomain enumeration. Include realistic "
            "service, environment, regional, legacy, and shadow-IT names."
        ),
        "directory": (
            "Generate URL path candidates for web directory/file fuzzing. Include "
            "framework paths, backups, configs, logs, API routes, and developer artifacts."
        ),
        "cloud-resource": (
            "Generate realistic cloud resource names. Include buckets/storage accounts, "
            "logs, backups, data exports, Terraform state, migration artifacts, and team names."
        ),
    }[kind]
    validation = {
        "password-base": "Only A-Z, a-z, and digits. Length 3-30. No spaces or symbols.",
        "subdomain": "Lowercase DNS labels only. Use a-z, 0-9, and hyphens. No leading/trailing hyphens. Max 63 chars.",
        "directory": "Relative paths only. No leading slash, full URLs, query strings, fragments, or path traversal. URL-safe path chars only.",
        "cloud-resource": "Lowercase names only. Use a-z, 0-9, hyphens, or underscores. Length 3-63. No leading/trailing separators.",
    }[kind]
    extra = f"\nAdditional operator instructions: {instructions.strip()}" if instructions.strip() else ""
    return textwrap.dedent(
        f"""
        You are helping with authorized security testing and training.

        Task: create a {kind} wordlist from the provided context.
        Context seeds: {seed_text}
        Target count: {max_words}

        Focus:
        {usage_focus}

        Output rules:
        - Return exactly {max_words} candidates if possible.
        - One candidate per line.
        - No markdown, numbering, categories, explanations, or comments.
        - No duplicates.
        - {validation}
        - Prefer candidates connected to the provided context; avoid generic filler.
        - Include a mix of obvious, realistic, legacy, temporary, and developer-shortcut patterns.{extra}
        """
    ).strip()


def parse_ai_wordlist_candidates(payload: str) -> list[str]:
    payload = payload.strip()
    if not payload:
        return []
    for candidate in ai_json_payload_candidates(payload):
        try:
            decoded = json.loads(candidate)
            values: object
            if isinstance(decoded, dict):
                values = (
                    decoded.get("candidates")
                    or decoded.get("words")
                    or decoded.get("wordlist")
                    or decoded.get("items")
                    or decoded.get("keywords")
                    or []
                )
            else:
                values = decoded
            if isinstance(values, list):
                return [str(item).strip() for item in values if str(item).strip()]
        except json.JSONDecodeError:
            continue

    candidates: list[str] = []
    for line in payload.splitlines():
        line = line.strip()
        if not line or line.startswith("```"):
            continue
        line = re.sub(r"^(?:[-*]|\d+[.)])\s*", "", line)
        line = line.strip("`'\" ")
        if not line or ":" in line:
            continue
        candidates.append(line)
    return candidates


def select_default_ai_provider() -> str:
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    return "openai"


def ai_generate_wordlist(
    provider: str,
    kind: str,
    seeds: Sequence[str],
    max_words: int = 100,
    model: str = "",
    instructions: str = "",
    preserve_unicode: bool = False,
) -> list[str]:
    provider = provider.strip().lower()
    kind = normalize_target_wordlist_type(kind)
    prompt = ai_wordlist_prompt(kind, seeds, max_words, instructions=instructions)
    if provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set.")
        selected_model = model or os.environ.get("W0RDIT_OPENAI_MODEL", "gpt-4.1-mini")
        body = {
            "model": selected_model,
            "input": prompt,
            "instructions": "Return plain text only, one candidate per line. No markdown.",
        }
        request = Request(
            "https://api.openai.com/v1/responses",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=60) as response:
                data = json.loads(response.read().decode("utf-8", errors="ignore"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")[:300]
            raise ValueError(f"OpenAI API error HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise ValueError(f"OpenAI API connection failed: {exc.reason}") from exc
        raw_candidates = parse_ai_wordlist_candidates(extract_openai_response_text(data))
        return process_typed_candidates(kind, raw_candidates, limit=max_words, preserve_unicode=preserve_unicode)

    if provider == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY is not set.")
        selected_model = model or os.environ.get("W0RDIT_GEMINI_MODEL", "gemini-2.5-flash")
        body = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt},
                    ],
                }
            ]
        }
        request = Request(
            f"https://generativelanguage.googleapis.com/v1beta/models/{selected_model}:generateContent",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=60) as response:
                data = json.loads(response.read().decode("utf-8", errors="ignore"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")[:300]
            raise ValueError(f"Gemini API error HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise ValueError(f"Gemini API connection failed: {exc.reason}") from exc
        parts: list[str] = []
        candidates = data.get("candidates")
        if isinstance(candidates, list):
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                content = candidate.get("content")
                if not isinstance(content, dict):
                    continue
                for part in content.get("parts", []):
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        parts.append(part["text"])
        raw_candidates = parse_ai_wordlist_candidates("\n".join(parts))
        return process_typed_candidates(kind, raw_candidates, limit=max_words, preserve_unicode=preserve_unicode)

    raise ValueError("Choose provider openai or gemini.")


def read_batch_seed_groups(path: str | Path, preserve_unicode: bool = False) -> list[list[str]]:
    seed_groups: list[list[str]] = []
    for line in Path(path).expanduser().read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        seeds = seed_words_from_values([line], preserve_unicode=preserve_unicode)
        if seeds:
            seed_groups.append(seeds)
    return seed_groups


def generate_batch_typed_wordlist(
    kind: str,
    seed_groups: Sequence[Sequence[str]],
    batch_size: int = 5,
    limit: int = DEFAULT_MAX_CANDIDATES,
    base_context: Sequence[str] = (),
    preserve_unicode: bool = False,
    ai_provider: str = "",
    ai_model: str = "",
    ai_instructions: str = "",
) -> list[str]:
    kind = normalize_target_wordlist_type(kind)
    if batch_size < 1:
        raise ValueError("Batch size must be 1 or higher.")
    chunks = [
        seed_groups[index : index + batch_size]
        for index in range(0, len(seed_groups), batch_size)
    ]
    if not chunks:
        return []
    per_batch_limit = max(1, min(limit, (limit + len(chunks) - 1) // len(chunks)))
    candidates: list[str] = []
    base = list(base_context)
    for chunk in chunks:
        seeds = ordered_unique([*base, *(seed for group in chunk for seed in group)])
        if ai_provider:
            generated = ai_generate_wordlist(
                ai_provider,
                kind,
                seeds,
                max_words=per_batch_limit,
                model=ai_model,
                instructions=ai_instructions,
                preserve_unicode=preserve_unicode,
            )
        else:
            generated = generate_typed_wordlist(
                kind,
                seeds,
                limit=per_batch_limit,
                preserve_unicode=preserve_unicode,
            )
        candidates.extend(generated)
        candidates = process_typed_candidates(kind, candidates, limit=limit, preserve_unicode=preserve_unicode)
        if len(candidates) >= limit:
            break
    return candidates


def parse_date_fragments(values: Iterable[str]) -> list[str]:
    fragments: list[str] = []
    for value in values:
        value = ascii_fold(value).strip()
        if not value:
            continue
        pieces = [piece for piece in DATE_SPLIT_RE.split(value) if piece]
        if len(pieces) == 3 and all(piece.isdigit() for piece in pieces):
            a, b, c = pieces
            year = ""
            month = ""
            day = ""
            if len(a) == 4:
                year, month, day = a, b, c
            elif len(c) == 4:
                month, day, year = a, b, c
            elif len(c) == 2:
                month, day, year = a, b, c
            if year:
                month = month.zfill(2)
                day = day.zfill(2)
                fragments.extend(
                    [
                        year,
                        year[-2:],
                        month + day,
                        day + month,
                        month + day + year,
                        day + month + year,
                    ]
                )
                continue
        digits = re.sub(r"\D+", "", value)
        if digits:
            fragments.append(digits)
            if len(digits) == 4:
                fragments.append(digits[-2:])
    return ordered_unique(fragments)


def in_length_bounds(value: str, options: BuildOptions) -> bool:
    return options.min_len <= len(value) <= options.max_len


def bounded_unique_candidates(
    stream: Iterable[str],
    options: BuildOptions,
) -> list[str]:
    seen: set[str] = set()
    candidates: list[str] = []
    for raw in stream:
        candidate = clean_candidate(raw, preserve_unicode=options.preserve_unicode)
        if not candidate or candidate in seen:
            continue
        if not in_length_bounds(candidate, options):
            continue
        seen.add(candidate)
        candidates.append(candidate)
        if len(candidates) >= options.max_candidates:
            break
    return candidates


def case_variants(word: str, modes: Sequence[str]) -> list[str]:
    variants: list[str] = []
    for mode in modes:
        if mode == "raw":
            variants.append(word)
        elif mode == "lower":
            variants.append(word.lower())
        elif mode == "upper":
            variants.append(word.upper())
        elif mode == "title":
            variants.append(word.title())
        elif mode == "capitalize":
            variants.append(word.capitalize())
        elif mode == "swap":
            variants.append(word.swapcase())
    return ordered_unique(variants)


def leet_variants(word: str, depth: int = 1, limit: int = 64) -> list[str]:
    if depth <= 0:
        return []
    positions = [
        (index, LEET_MAP[char.lower()])
        for index, char in enumerate(word)
        if char.lower() in LEET_MAP
    ]
    variants: list[str] = []
    for width in range(1, min(depth, len(positions)) + 1):
        for combo in itertools.combinations(positions, width):
            indexes = [item[0] for item in combo]
            replacement_sets = [item[1] for item in combo]
            for replacements in itertools.product(*replacement_sets):
                chars = list(word)
                for index, replacement in zip(indexes, replacements):
                    chars[index] = replacement
                variant = "".join(chars)
                if variant != word:
                    variants.append(variant)
                if len(variants) >= limit:
                    return ordered_unique(variants)
    return ordered_unique(variants)


def with_leet(stream: Iterable[str], depth: int) -> Iterator[str]:
    for candidate in stream:
        yield candidate
        yield from leet_variants(candidate, depth=depth, limit=24)


def profile_tokens(profile: dict[str, str], preserve_unicode: bool = False) -> tuple[list[str], list[str]]:
    token_values: list[str] = []
    date_values: list[str] = []
    for key, raw_value in profile.items():
        items = parse_human_list(raw_value)
        if key == "dates":
            date_values.extend(items)
            continue
        for item in items:
            extracted = extract_words(
                item,
                min_len=1,
                max_len=32,
                lowercase=True,
                preserve_unicode=preserve_unicode,
            )
            if len(extracted) > 1:
                token_values.append("".join(extracted))
            token_values.extend(extracted)
    return ordered_unique(token_values), parse_date_fragments(date_values)


def pair_joiners(options: BuildOptions) -> tuple[str, ...]:
    numeric_joiners = [
        value
        for value in [*options.numbers, *options.years]
        if value and value.isdigit() and len(value) <= 4
    ]
    return tuple(ordered_unique([*options.separators, *numeric_joiners[:40], *options.symbols[:8]]))


def build_profile_wordlist(profile: dict[str, str], options: BuildOptions) -> list[str]:
    tokens, dates = profile_tokens(profile, preserve_unicode=options.preserve_unicode)
    numeric_tokens = [token for token in tokens if token.isdigit()]
    base_tokens = [token for token in tokens if not token.isdigit()]
    if not base_tokens:
        base_tokens = tokens
    years = ordered_unique([*dates, *options.years])
    numbers = ordered_unique([*numeric_tokens, *options.numbers])
    options = replace(options, years=tuple(years), numbers=tuple(numbers))
    bases: list[str] = []
    for token in base_tokens:
        bases.extend(case_variants(token, options.case_modes))
    bases = ordered_unique(bases)
    joiners = pair_joiners(options)

    def stream() -> Iterator[str]:
        yield from bases
        if options.include_reverse:
            for base in bases:
                yield base[::-1]
        limited_bases = bases[: options.pair_limit]
        if options.include_pairs:
            for left, right in itertools.permutations(limited_bases, 2):
                for joiner in joiners:
                    yield left + joiner + right
        suffixes = ordered_unique([*options.years, *options.numbers, *options.symbols])
        for base in bases:
            for suffix in suffixes:
                yield base + suffix
                if suffix.isdigit():
                    yield suffix + base
            for year in options.years:
                for sep in options.separators:
                    if sep:
                        yield base + sep + year
                if options.include_sandwich:
                    for symbol in options.symbols:
                        yield base + year + symbol
                        yield base + symbol + year
        if options.include_pairs:
            for left, right in itertools.permutations(limited_bases, 2):
                for joiner in joiners:
                    pair = left + joiner + right
                    for suffix in options.years[:8]:
                        yield pair + suffix

    return bounded_unique_candidates(with_leet(stream(), options.leet_depth), options)


def mutate_wordlist(words: Sequence[str], options: BuildOptions) -> list[str]:
    source = ordered_unique(
        candidate
        for word in words
        if (candidate := clean_candidate(word, preserve_unicode=options.preserve_unicode))
    )
    numeric_source = [word for word in source if word.isdigit()]
    word_source = [word for word in source if not word.isdigit()]
    if word_source:
        source = word_source
        options = replace(options, numbers=tuple(ordered_unique([*numeric_source, *options.numbers])))
    suffixes = ordered_unique([*options.years, *options.numbers, *options.symbols])
    joiners = pair_joiners(options)

    def stream() -> Iterator[str]:
        for word in source:
            yield from case_variants(word, options.case_modes)
            if options.include_reverse:
                yield word[::-1]
            for suffix in suffixes:
                yield word + suffix
                if suffix.isdigit():
                    yield suffix + word
            for year in options.years:
                for symbol in options.symbols:
                    if options.include_sandwich:
                        yield word + year + symbol
                        yield word + symbol + year
        if options.include_pairs:
            limited = source[: options.pair_limit]
            for left, right in itertools.permutations(limited, 2):
                for joiner in joiners:
                    yield left + joiner + right

    return bounded_unique_candidates(with_leet(stream(), options.leet_depth), options)


def generate_passphrases(
    words: Sequence[str],
    word_count: int,
    separators: Sequence[str],
    options: BuildOptions,
    source_limit: int = 80,
) -> list[str]:
    base_words = [
        word.lower()
        for word in words
        if word.isalpha() and options.min_len <= len(word) <= min(options.max_len, 18)
    ]
    base_words = ordered_unique(base_words)[:source_limit]
    suffixes = ("", *options.years[:6], *options.symbols[:3])

    def stream() -> Iterator[str]:
        iterator: Iterable[tuple[str, ...]]
        if len(base_words) >= word_count:
            iterator = itertools.permutations(base_words, word_count)
        else:
            iterator = itertools.product(base_words, repeat=word_count)
        for combo in iterator:
            for sep in separators:
                phrase = sep.join(combo)
                yield phrase
                yield phrase.title()
                for suffix in suffixes:
                    if suffix:
                        yield phrase + suffix

    return bounded_unique_candidates(stream(), options)


def option_preset(name: str, max_candidates: int | None = None) -> BuildOptions:
    normalized = normalize_style(name)
    candidate_limit = max_candidates or DEFAULT_MAX_CANDIDATES
    if normalized == "focused":
        return BuildOptions(
            max_candidates=min(candidate_limit, 100_000),
            case_modes=("raw", "lower", "title", "capitalize"),
            years=recent_years(5),
            numbers=DEFAULT_NUMBERS,
            symbols=("!", "@", "#", "_"),
            leet_depth=1,
            pair_limit=50,
        )
    if normalized == "quick":
        return BuildOptions(
            max_candidates=min(candidate_limit, 25_000),
            case_modes=("raw", "lower", "title"),
            years=recent_years(2),
            numbers=("1", "4", "7", "123"),
            symbols=("!", "@"),
            leet_depth=0,
            pair_limit=25,
        )
    if normalized == "numbers":
        return BuildOptions(
            max_candidates=min(candidate_limit, 100_000),
            case_modes=("raw", "lower", "title", "capitalize"),
            separators=("",),
            years=recent_years(5),
            numbers=DEFAULT_NUMBERS,
            symbols=(),
            leet_depth=0,
            pair_limit=50,
        )
    if normalized == "symbols":
        return BuildOptions(
            max_candidates=min(candidate_limit, 100_000),
            case_modes=("raw", "lower", "title", "capitalize"),
            separators=("",),
            years=(),
            numbers=(),
            symbols=DEFAULT_SYMBOLS,
            leet_depth=0,
            pair_limit=50,
            include_sandwich=False,
        )
    if normalized == "both":
        return BuildOptions(
            max_candidates=min(candidate_limit, 150_000),
            case_modes=("raw", "lower", "title", "capitalize"),
            years=recent_years(5),
            numbers=DEFAULT_NUMBERS,
            symbols=DEFAULT_SYMBOLS,
            leet_depth=0,
            pair_limit=50,
        )
    if normalized == "caps":
        return BuildOptions(
            max_candidates=min(candidate_limit, 25_000),
            case_modes=("raw", "lower", "upper", "title", "capitalize"),
            separators=("",),
            years=(),
            numbers=(),
            symbols=(),
            leet_depth=0,
            pair_limit=20,
            include_pairs=False,
            include_reverse=False,
            include_sandwich=False,
        )
    if normalized == "wide":
        return BuildOptions(
            max_candidates=min(max(candidate_limit, 250_000), 500_000),
            case_modes=("raw", "lower", "upper", "title", "capitalize"),
            years=recent_years(10),
            numbers=tuple([str(item) for item in range(0, 100)] + ["123", "1234", "007"]),
            symbols=("!", "@", "#", "$", "_", "-", "."),
            leet_depth=2,
            pair_limit=60,
        )
    return BuildOptions(
        max_candidates=candidate_limit,
        case_modes=("raw", "lower", "title", "capitalize"),
        years=recent_years(5),
        numbers=DEFAULT_NUMBERS,
        symbols=DEFAULT_SYMBOLS,
        leet_depth=1,
        pair_limit=40,
    )


def read_word_file(path: str | Path, token_mode: bool = False, preserve_unicode: bool = False) -> list[str]:
    file_path = Path(path).expanduser()
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    if token_mode:
        return extract_words(text, min_len=1, max_len=64, lowercase=False, preserve_unicode=preserve_unicode)
    return [line.strip() for line in text.splitlines() if line.strip()]


def harvest_url(url: str, max_bytes: int = 2_000_000, timeout: int = 10) -> str:
    url = normalize_harvest_target(url)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported.")
    github_text = harvest_github_profile(url, max_bytes=max_bytes, timeout=timeout)
    if github_text is not None:
        return github_text
    try:
        text, _links = extract_page_text_and_links(url, max_bytes=max_bytes, timeout=timeout)
    except HTTPError as exc:
        hint_text = url_hint_text(url)
        if hint_text:
            return hint_text
        raise ValueError(f"URL returned HTTP {exc.code}: {exc.reason}") from exc
    except URLError as exc:
        hint_text = url_hint_text(url)
        if hint_text:
            return hint_text
        raise ValueError(f"Could not reach URL: {exc.reason}") from exc
    return text


def parse_mask(mask: str, custom: dict[str, str] | None = None) -> list[str]:
    custom = custom or {}
    parts: list[str] = []
    index = 0
    while index < len(mask):
        char = mask[index]
        if char != "?":
            parts.append(char)
            index += 1
            continue
        if index + 1 >= len(mask):
            raise ValueError("Dangling '?' at end of mask.")
        token = mask[index + 1]
        if token == "?":
            parts.append("?")
        elif token in custom:
            if not custom[token]:
                raise ValueError(f"Custom charset ?{token} is empty.")
            parts.append(custom[token])
        elif token in BUILTIN_MASK_CHARSETS:
            parts.append(BUILTIN_MASK_CHARSETS[token])
        else:
            raise ValueError(f"Unsupported mask token '?{token}'.")
        index += 2
    return parts


def mask_keyspace(mask: str, custom: dict[str, str] | None = None) -> int:
    total = 1
    for part in parse_mask(mask, custom):
        total *= len(part)
    return total


def generate_from_mask(
    mask: str,
    custom: dict[str, str] | None = None,
    limit: int = DEFAULT_MAX_CANDIDATES,
) -> list[str]:
    parts = parse_mask(mask, custom)
    candidates: list[str] = []
    for combo in itertools.product(*parts):
        candidates.append("".join(combo))
        if len(candidates) >= limit:
            break
    return candidates


def hashcat_append_rule(value: str) -> str:
    return "".join(f"${char}" for char in value)


def hashcat_prepend_rule(value: str) -> str:
    return "".join(f"^{char}" for char in reversed(value))


def generate_hashcat_rules(years: Sequence[str], symbols: Sequence[str]) -> list[str]:
    rules = [":", "l", "u", "c", "C", "r"]
    for symbol in symbols:
        rules.append(hashcat_append_rule(symbol))
    for year in years:
        rules.append(hashcat_append_rule(year))
        rules.append(hashcat_prepend_rule(year))
        for symbol in symbols[:4]:
            rules.append(hashcat_append_rule(year + symbol))
            rules.append(hashcat_append_rule(symbol + year))
    return ordered_unique(rules)


def escape_mask_literal(value: str) -> str:
    return "".join("??" if char == "?" else char for char in value)


def generate_huge_masks(
    words: Sequence[str],
    digit_lengths: Sequence[int],
    symbol_count: int = 0,
    case_modes: Sequence[str] = ("raw", "lower", "title", "capitalize"),
    known_digits: str = "",
    known_suffix: str = "",
    limit: int = 500,
    preserve_unicode: bool = False,
) -> list[str]:
    bases: list[str] = []
    for word in words:
        cleaned = clean_candidate(word, preserve_unicode=preserve_unicode)
        if not cleaned:
            continue
        bases.extend(case_variants(cleaned, case_modes))
    bases = ordered_unique(bases)
    lengths = ordered_unique(str(length) for length in digit_lengths if length >= 0)
    if known_digits:
        lengths = [str(len(known_digits))]

    masks: list[str] = []
    for base in bases:
        base_mask = escape_mask_literal(base)
        for raw_length in lengths:
            digit_part = escape_mask_literal(known_digits) if known_digits else "?d" * int(raw_length)
            suffix_part = escape_mask_literal(known_suffix) if known_suffix else "?s" * max(0, symbol_count)
            masks.append(base_mask + digit_part + suffix_part)
            if len(masks) >= limit:
                return ordered_unique(masks)[:limit]
    return ordered_unique(masks)[:limit]


def estimate_mask_collection_keyspace(masks: Sequence[str]) -> int:
    total = 0
    for mask in masks:
        total += mask_keyspace(mask)
    return total


def format_count(value: int | float) -> str:
    if isinstance(value, float):
        return f"{value:,.1f}"
    return f"{value:,}"


def banner() -> str:
    art = r"""
 __        __   ___              _   _   _
 \ \      / /  / _ \  _ __  __| | | | | | |_
  \ \ /\ / /  | | | || '__|/ _` | | | | | __|
   \ V  V /   | |_| || |  | (_| | |_| |_| |_
    \_/\_/     \___/ |_|   \__,_| (_) (_)\__|
"""
    lines = [
        color(art.rstrip("\n"), "bold", "cyan"),
        color(f"                         {APP_NAME} v{VERSION}", "bold", "green"),
        color(f"                      created by {CREATOR_NAME}", "cyan"),
        color("          Build useful candidates from the hints you actually have.", "green"),
        "",
        color("       =[ profiles ]====[ mutations ]====[ masks ]====[ rules ]=", "magenta"),
        color("       =[ authorized password recovery, auditing, CTFs, and labs ]=", "yellow"),
    ]
    return "\n".join(lines)


class WorditShell(cmd.Cmd):
    intro = None

    def __init__(self, preserve_unicode: bool = False) -> None:
        super().__init__()
        self.bank = WordBank(preserve_unicode=preserve_unicode)
        self.default_min_len = DEFAULT_MIN_LEN
        self.default_max_len = DEFAULT_MAX_LEN
        self.default_max_candidates = DEFAULT_MAX_CANDIDATES
        self.menu_mode = "main"
        self.loaded_ai_config = load_ai_config()
        self.update_prompt()
        self.intro = f"{banner()}\n\n{self.menu_text()}"

    def update_prompt(self) -> None:
        label = f"{APP_NAME} > " if self.menu_mode == "main" else f"{APP_NAME} advanced > "
        self.prompt = color(label, "bold", "green")

    def emptyline(self) -> None:
        return None

    def default(self, line: str) -> bool | None:
        line = line.strip()
        if line.isdigit():
            return self.do_use(line)
        print(f"Unknown command: {line}. Try 'menu' or 'help'.")

    def menu_text(self) -> str:
        items = [
            ("1", "Create wordlist from hints"),
            ("2", "Add words manually"),
            ("3", "Import a wordlist file"),
            ("4", "Improve / mutate current list"),
            ("5", "Preview current list"),
            ("6", "Save wordlist"),
            ("7", "Show stats"),
            ("8", "Advanced options"),
            ("9", "Clear session"),
            ("0", "Exit"),
        ]
        lines = [color("Main menu", "bold", "magenta")]
        lines.extend(f"  {color(f'[{key}]', 'yellow')} {label}" for key, label in items)
        lines.append(color("Tip: type a number, or type a command like add, mutate, preview, save.", "dim"))
        lines.append(color("     Press Tab when a prompt asks for a file path.", "dim"))
        return "\n".join(lines)

    def advanced_menu_text(self) -> str:
        items = [
            ("1", "Harvest words from text file or URL"),
            ("2", "Huge password patterns"),
            ("3", "AI smart harvest"),
            ("4", "AI API setup"),
            ("5", "Generate from a mask"),
            ("6", "Build passphrases"),
            ("7", "Advanced mutation settings"),
            ("8", "Export helpers"),
            ("0", "Back to main menu"),
            ("9", "Exit"),
        ]
        lines = [color("Advanced options", "bold", "magenta")]
        lines.extend(f"  {color(f'[{key}]', 'yellow')} {label}" for key, label in items)
        lines.append(color("Tip: 0 goes back. Type menu for main, advanced for this screen.", "dim"))
        lines.append(color("     Type typegen for password-base, subdomain, directory, or cloud-resource lists.", "dim"))
        return "\n".join(lines)

    def do_help(self, arg: str) -> None:
        print(
            textwrap.dedent(
                """
                Core commands:
                  menu                 Show the main menu
                  advanced             Show advanced options
                  back                 Return to the main menu
                  profile              Guided hint-based wordlist builder
                  add WORDS...         Add manual words or phrases
                  import PATH          Import one candidate per line
                  mutate [style]       Mutate current list
                  stats                Show counts and length summary
                  preview [N]          Show the first N candidates
                  save PATH            Write current wordlist
                  clear                Clear current session
                  exit                 Quit

                Mutation styles: focused, numbers, symbols, both, caps, quick, wide.
                Advanced commands: harvest, huge, aiharvest, typegen, typebatch, aisetup, mask, passphrase, rules, hcmask.

                Mask tokens: ?l lower, ?u upper, ?d digit, ?s symbol, ?a all,
                ?h lowercase hex, ?H uppercase hex, ?1-?4 custom charsets.
                """
            ).strip()
        )

    def complete_import(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return path_completions(text)

    def complete_load(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self.complete_import(text, line, begidx, endidx)

    def complete_harvest(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return path_completions(text)

    def complete_save(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return path_completions(text)

    def complete_rules(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return path_completions(text)

    def complete_hcmask(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return path_completions(text)

    def complete_typebatch(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return path_completions(text)

    def do_menu(self, arg: str) -> None:
        self.menu_mode = "main"
        self.update_prompt()
        print(self.menu_text())

    def do_advanced(self, arg: str) -> None:
        self.menu_mode = "advanced"
        self.update_prompt()
        print(self.advanced_menu_text())

    def do_adv(self, arg: str) -> None:
        self.do_advanced(arg)

    def do_back(self, arg: str) -> None:
        self.do_menu(arg)

    def do_main(self, arg: str) -> None:
        self.do_menu(arg)

    def do_use(self, arg: str) -> bool | None:
        main_actions = {
            "1": self.do_profile,
            "2": self.do_add,
            "3": self.do_import,
            "4": self.do_mutate,
            "5": self.do_preview,
            "6": self.do_save,
            "7": self.do_stats,
            "8": self.do_advanced,
            "9": self.do_clear,
            "0": self.do_exit,
        }
        advanced_actions = {
            "1": self.do_harvest,
            "2": self.do_huge,
            "3": self.do_aiharvest,
            "4": self.do_aisetup,
            "5": self.do_mask,
            "6": self.do_passphrase,
            "7": self.do_mutate_advanced,
            "8": self.do_export_helpers,
            "0": self.do_back,
            "9": self.do_exit,
        }
        actions = advanced_actions if self.menu_mode == "advanced" else main_actions
        action = actions.get(arg.strip())
        if not action:
            if self.menu_mode == "advanced":
                print("No such advanced menu item. Use 0 to go back, or type advanced to show options.")
            else:
                print("No such menu item.")
            return
        result = action("")
        return result if isinstance(result, bool) else None

    def ask(self, prompt: str, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        value = input(f"{prompt}{suffix}: ").strip()
        return value if value else default

    def ask_secret(self, prompt: str, default: str = "") -> str:
        suffix = f" [{mask_secret(default)}]" if default else ""
        if not sys.stdin.isatty():
            value = input(f"{prompt}{suffix}: ").strip()
            return value if value else default
        value = getpass.getpass(f"{prompt}{suffix}: ").strip()
        return value if value else default

    def ask_path(
        self,
        prompt: str,
        default: str = "",
        include_files: bool = True,
        include_dirs: bool = True,
    ) -> str:
        suffix = f" [{default}]" if default else ""
        if readline is None or not sys.stdin.isatty():
            value = input(f"{prompt}{suffix}: ").strip()
            return value if value else default

        old_completer = readline.get_completer()
        old_delims = readline.get_completer_delims()

        def complete_path(text: str, state: int) -> str | None:
            matches = path_completions(
                text,
                include_files=include_files,
                include_dirs=include_dirs,
            )
            if state < len(matches):
                return matches[state]
            return None

        try:
            readline.set_completer_delims("\t\n")
            readline.set_completer(complete_path)
            readline.parse_and_bind("tab: complete")
            value = input(f"{prompt}{suffix}: ").strip()
            return value if value else default
        finally:
            readline.set_completer(old_completer)
            readline.set_completer_delims(old_delims)

    def ask_int(self, prompt: str, default: int, minimum: int = 0) -> int:
        while True:
            raw = self.ask(prompt, str(default))
            try:
                value = int(raw)
            except ValueError:
                print("Enter a number.")
                continue
            if value < minimum:
                print(f"Enter {minimum} or higher.")
                continue
            return value

    def ask_bool(self, prompt: str, default: bool = False) -> bool:
        marker = "Y/n" if default else "y/N"
        raw = input(f"{prompt} [{marker}]: ").strip().lower()
        if not raw:
            return default
        return raw in {"y", "yes", "true", "1"}

    def ask_choice(self, prompt: str, choices: Sequence[str], default: str) -> str:
        choice_set = set(choices)
        while True:
            raw = self.ask(f"{prompt} ({'/'.join(choices)})", default).lower()
            if raw in choice_set:
                return raw
            print(f"Choose one of: {', '.join(choices)}.")

    def print_mutation_styles(self) -> None:
        print(color("Mutation styles", "bold", "magenta"))
        print("  focused  best first try: words, caps, numbers, symbols, and word+number+word")
        print("  numbers  add digits only")
        print("  symbols  add special characters only")
        print("  both     add numbers and special characters")
        print("  caps     capitalization variants only")
        print("  quick    smaller and faster")
        print("  wide     larger search space")

    def ask_mutation_style(self, default: str = "focused") -> str:
        self.print_mutation_styles()
        while True:
            raw = self.ask("Style", default)
            style = normalize_style(raw)
            if style in MUTATION_STYLES or style == "balanced":
                return style
            print(f"Unknown style: {raw}.")

    def simple_options_from_prompt(self, style: str) -> BuildOptions:
        size = self.ask_choice("Wordlist size", ("small", "medium", "large"), "medium")
        return replace(option_preset(style, WORDLIST_SIZE_CAPS[size]), preserve_unicode=self.bank.preserve_unicode)

    def options_from_prompt(self, preset: str) -> BuildOptions:
        options = replace(
            option_preset(preset, self.default_max_candidates),
            preserve_unicode=self.bank.preserve_unicode,
        )
        min_len = self.ask_int("Minimum length", options.min_len, minimum=1)
        max_len = self.ask_int("Maximum length", options.max_len, minimum=min_len)
        max_candidates = self.ask_int(
            "Candidate cap",
            options.max_candidates,
            minimum=1,
        )
        use_numbers = self.ask_bool("Use numbers", bool(options.numbers or options.years))
        use_symbols = self.ask_bool("Use special characters", bool(options.symbols))
        use_capitals = self.ask_bool(
            "Use capitalization variants",
            any(mode in options.case_modes for mode in ("upper", "title", "capitalize")),
        )
        combine_words = self.ask_bool("Combine two hint words", options.include_pairs)
        use_leet = self.ask_bool("Use leetspeak swaps like a -> 4", options.leet_depth > 0)
        numbers = options.numbers if use_numbers else ()
        years = options.years if use_numbers else ()
        if use_numbers and not years:
            years = recent_years(5)
        symbols = options.symbols if use_symbols else ()
        case_modes = ("raw", "lower", "upper", "title", "capitalize") if use_capitals else ("raw", "lower")
        leet_depth = options.leet_depth if use_leet else 0
        return replace(
            options,
            min_len=min_len,
            max_len=max_len,
            max_candidates=max_candidates,
            numbers=numbers,
            years=years,
            symbols=symbols,
            case_modes=case_modes,
            include_pairs=combine_words,
            include_sandwich=use_numbers and use_symbols,
            leet_depth=leet_depth,
        )

    def report_added(self, added: int) -> None:
        print(color(f"Added {format_count(added)} new candidates.", "green"))
        print(f"Session total: {format_count(len(self.bank))}.")

    def do_profile(self, arg: str) -> None:
        print(color("Create from hints", "bold", "magenta"))
        print("Use only for systems and accounts you are authorized to assess.")
        profile = {
            "names": self.ask("Important words, names, handles, teams"),
            "dates": self.ask("Numbers, dates, years"),
            "places": self.ask("Places, projects, products"),
            "extras": self.ask("Extra hints"),
        }
        self.bank.preserve_unicode = self.ask_bool(
            "Preserve non-ASCII characters",
            self.bank.preserve_unicode,
        )
        style = self.ask_mutation_style("focused")
        options = self.simple_options_from_prompt(style)
        candidates = build_profile_wordlist(profile, options)
        added = self.bank.add_many(candidates, source=f"profile:{style}")
        self.report_added(added)

    def do_add(self, arg: str) -> None:
        raw = arg.strip() or self.ask("Words or phrases")
        items = parse_human_list(raw)
        expanded: list[str] = []
        for item in items:
            tokens = extract_words(
                item,
                min_len=1,
                max_len=64,
                lowercase=False,
                preserve_unicode=self.bank.preserve_unicode,
            )
            if len(tokens) > 1:
                expanded.append("".join(tokens))
            expanded.extend(tokens or [item])
        added = self.bank.add_many(expanded, source="manual")
        self.report_added(added)

    def do_import(self, arg: str) -> None:
        path = arg.strip() or self.ask_path("Path to wordlist")
        if Path(path).expanduser().is_dir():
            print("That path is a directory. Press Tab after the trailing slash to choose a file inside it.")
            return
        token_mode = self.ask_bool("Extract tokens instead of one word per line", False)
        try:
            words = read_word_file(
                path,
                token_mode=token_mode,
                preserve_unicode=self.bank.preserve_unicode,
            )
        except IsADirectoryError:
            print("That path is a directory. Press Tab after the trailing slash to choose a file inside it.")
            return
        except OSError as exc:
            print(f"Could not read file: {exc}")
            return
        added = self.bank.add_many(words, source=f"import:{Path(path).name}")
        self.report_added(added)

    def do_load(self, arg: str) -> None:
        self.do_import(arg)

    def do_harvest(self, arg: str) -> None:
        target = normalize_harvest_target(arg.strip() or self.ask_path("Text file path or URL"))
        target_is_url = target.startswith(("http://", "https://"))
        if not target_is_url and Path(target).expanduser().is_dir():
            print("That path is a directory. Press Tab after the trailing slash to choose a file inside it.")
            return
        min_len = self.ask_int("Minimum harvested word length", 3, minimum=1)
        max_len = self.ask_int("Maximum harvested word length", 32, minimum=min_len)
        preserve_unicode = self.ask_bool("Preserve non-ASCII harvested words", self.bank.preserve_unicode)
        self.bank.preserve_unicode = preserve_unicode
        try:
            if target_is_url:
                if not self.ask_bool("Confirm this URL is in scope for you", False):
                    print("Skipped URL harvest.")
                    return
                text = harvest_url(target)
                source = f"url:{urlparse(target).netloc}"
            else:
                text = Path(target).expanduser().read_text(encoding="utf-8", errors="ignore")
                source = f"harvest:{Path(target).name}"
        except IsADirectoryError:
            print("That path is a directory. Press Tab after the trailing slash to choose a file inside it.")
            return
        except (OSError, ValueError) as exc:
            print(f"Harvest failed: {exc}")
            return
        words = extract_words(
            text,
            min_len=min_len,
            max_len=max_len,
            lowercase=True,
            preserve_unicode=preserve_unicode,
        )
        if not words:
            if target_is_url:
                print("No words were found. Check that the URL exists, is public, and is not rendered only by JavaScript.")
            else:
                print("No words were found in that file with the selected length limits.")
            return
        added = self.bank.add_many(words, source=source, preserve_unicode=preserve_unicode)
        if added == 0:
            print("No new candidates added; the harvested words were already in this session.")
            return
        self.report_added(added)

    def do_aiharvest(self, arg: str) -> None:
        print(color("AI smart harvest", "bold", "magenta"))
        print("Crawls a small authorized scope, then asks an optional AI provider for useful seed words.")
        target = normalize_harvest_target(arg.strip() or self.ask_path("Start URL"))
        if not target.startswith(("http://", "https://")):
            print("AI smart harvest needs an http or https URL.")
            return
        if not self.ask_bool("Confirm this URL and linked pages are in scope for you", False):
            print("Skipped AI smart harvest.")
            return
        max_pages = min(self.ask_int("Maximum pages to fetch", 3, minimum=1), 10)
        max_depth = min(self.ask_int("Link depth", 1, minimum=0), 3)
        same_host = self.ask_bool("Stay on the same host", True)
        preserve_unicode = self.ask_bool("Preserve non-ASCII harvested words", self.bank.preserve_unicode)
        self.bank.preserve_unicode = preserve_unicode
        provider = self.ask("AI provider openai/gemini/off", "off").strip().lower()
        if provider in {"none", "no", "n"}:
            provider = "off"
        model = ""
        if provider != "off":
            model = self.ask("Model override (blank = provider default)")

        text, fetched, errors = crawl_url_text(
            target,
            max_pages=max_pages,
            max_depth=max_depth,
            same_host_only=same_host,
        )
        if fetched:
            print(f"Fetched {format_count(len(fetched))} page(s).")
        if errors:
            print("Fetch notes:")
            for error in errors[:5]:
                print(f"  {error}")
        url_fallback_only = not fetched and bool(errors)
        if url_fallback_only:
            print("Only URL-derived fallback tokens were available; no page content was harvested.")
            host = urlparse(target).netloc.lower()
            if host == "linkedin.com" or host.endswith(".linkedin.com"):
                print(
                    "LinkedIn often blocks direct non-browser fetches; export or copy the profile text "
                    "and harvest that file for richer seeds."
                )
        normal_words = extract_words(
            text,
            min_len=2,
            max_len=32,
            lowercase=True,
            preserve_unicode=preserve_unicode,
        )
        hint_words = extract_words(
            " ".join(url_hint_text(url) for url in ordered_unique([target, *fetched])),
            min_len=2,
            max_len=32,
            lowercase=True,
            preserve_unicode=preserve_unicode,
        )
        ai_words: list[str] = []
        if provider != "off" and url_fallback_only:
            print("AI enrichment skipped: no fetched page text was available to send to the provider.")
        elif provider != "off":
            try:
                ai_words = ai_extract_keywords(
                    provider,
                    text,
                    max_keywords=100,
                    model=model,
                    preserve_unicode=preserve_unicode,
                )
                if ai_words:
                    print(f"AI enrichment returned {format_count(len(ai_words))} keyword(s).")
                else:
                    print("AI enrichment returned no usable keywords.")
            except ValueError as exc:
                print(f"AI enrichment skipped: {exc}")
                if provider == "openai":
                    print("Run AI API setup from Advanced options to enable OpenAI enrichment.")
                elif provider == "gemini":
                    print("Run AI API setup from Advanced options to enable Gemini enrichment.")
        if ai_words:
            combined = ordered_unique([*hint_words, *ai_words])
            print("Using AI-filtered keywords plus URL hints.")
        else:
            combined = normal_words
        if not combined:
            print("No words were found. Check that the URL is public and reachable.")
            return
        if url_fallback_only:
            source_provider = "url-fallback"
        elif ai_words:
            source_provider = provider
        elif provider == "off":
            source_provider = "off"
        else:
            source_provider = "raw-harvest"
        added = self.bank.add_many(combined, source=f"aiharvest:{source_provider}", preserve_unicode=preserve_unicode)
        if added == 0:
            print("No new candidates added; the harvested words were already in this session.")
            return
        self.report_added(added)

    def do_ai(self, arg: str) -> None:
        self.do_aiharvest(arg)

    def print_target_wordlist_types(self) -> None:
        print(color("Typed wordlists", "bold", "magenta"))
        print("  password-base   clean base words for hashcat/rules")
        print("  subdomain       DNS labels for gobuster, ffuf, and similar tools")
        print("  directory       relative paths for web directory/file fuzzing")
        print("  cloud-resource  bucket/storage/resource-name candidates")

    def ask_target_wordlist_type(self, default: str = "password-base") -> str:
        self.print_target_wordlist_types()
        while True:
            raw = self.ask("Type", default)
            try:
                return normalize_target_wordlist_type(raw)
            except ValueError as exc:
                print(exc)

    def typed_seeds_from_prompt(self, raw_values: Sequence[str]) -> list[str]:
        if raw_values:
            return seed_words_from_values(raw_values, preserve_unicode=self.bank.preserve_unicode)
        if self.bank and self.ask_bool("Use current session words as context", True):
            return self.bank.words()
        raw = self.ask("Seed words")
        return seed_words_from_values([raw], preserve_unicode=self.bank.preserve_unicode)

    def do_typegen(self, arg: str) -> None:
        print(color("Generate typed wordlist", "bold", "magenta"))
        print("Builds tool-ready candidates and validates them before adding them to this session.")
        raw_parts = parse_human_list(arg)
        kind = ""
        seed_parts = raw_parts
        if raw_parts:
            try:
                kind = normalize_target_wordlist_type(raw_parts[0])
                seed_parts = raw_parts[1:]
            except ValueError:
                kind = ""
        if not kind:
            kind = self.ask_target_wordlist_type("password-base")
        print(f"Seed hints: {typed_wordlist_seed_hints(kind)}")
        seeds = self.typed_seeds_from_prompt(seed_parts)
        if not seeds:
            print("No seed words found.")
            return
        limit = self.ask_int("Target candidates", min(250, self.default_max_candidates), minimum=1)
        use_ai = self.ask_bool("Use AI generation", False)
        if use_ai:
            dry_run = self.ask_bool("Dry run / preview prompt only", False)
            instructions = self.ask("Extra AI instructions (blank skips)")
            if dry_run:
                print(ai_wordlist_prompt(kind, seeds, limit, instructions=instructions))
                return
            load_ai_config()
            provider = self.ask_choice("AI provider", ("openai", "gemini"), select_default_ai_provider())
            model = self.ask("Model override (blank = provider default)")
            try:
                candidates = ai_generate_wordlist(
                    provider,
                    kind,
                    seeds,
                    max_words=limit,
                    model=model,
                    instructions=instructions,
                    preserve_unicode=self.bank.preserve_unicode,
                )
            except ValueError as exc:
                print(f"AI generation failed: {exc}")
                print("Run AI API setup from Advanced options if you need to configure a key.")
                return
            source = f"ai-generate:{kind}"
        else:
            candidates = generate_typed_wordlist(
                kind,
                seeds,
                limit=limit,
                preserve_unicode=self.bank.preserve_unicode,
            )
            source = f"type:{kind}"
        if not candidates:
            print("No valid typed candidates were generated.")
            return
        added = self.bank.add_many(candidates, source=source, preserve_unicode=self.bank.preserve_unicode)
        self.report_added(added)
        print(typed_wordlist_usage(kind))

    def do_typed(self, arg: str) -> None:
        self.do_typegen(arg)

    def do_typebatch(self, arg: str) -> None:
        print(color("Typed batch generation", "bold", "magenta"))
        path = arg.strip() or self.ask_path("Batch seed file")
        if Path(path).expanduser().is_dir():
            print("That path is a directory. Press Tab after the trailing slash to choose a file inside it.")
            return
        kind = self.ask_target_wordlist_type("subdomain")
        batch_size = self.ask_int("Seed lines per batch", 5, minimum=1)
        limit = self.ask_int("Total candidate cap", min(1000, self.default_max_candidates), minimum=1)
        use_ai = self.ask_bool("Use AI generation", False)
        try:
            seed_groups = read_batch_seed_groups(path, preserve_unicode=self.bank.preserve_unicode)
        except OSError as exc:
            print(f"Could not read batch file: {exc}")
            return
        if not seed_groups:
            print("No seed groups found.")
            return
        ai_provider = ""
        ai_model = ""
        ai_instructions = ""
        if use_ai:
            if self.ask_bool("Dry run / preview first batch prompt only", False):
                first = ordered_unique([*(seed for group in seed_groups[:batch_size] for seed in group)])
                print(ai_wordlist_prompt(kind, first, max(1, limit // max(1, len(seed_groups))), instructions=""))
                return
            load_ai_config()
            ai_provider = self.ask_choice("AI provider", ("openai", "gemini"), select_default_ai_provider())
            ai_model = self.ask("Model override (blank = provider default)")
            ai_instructions = self.ask("Extra AI instructions (blank skips)")
        try:
            candidates = generate_batch_typed_wordlist(
                kind,
                seed_groups,
                batch_size=batch_size,
                limit=limit,
                base_context=self.bank.words(),
                preserve_unicode=self.bank.preserve_unicode,
                ai_provider=ai_provider,
                ai_model=ai_model,
                ai_instructions=ai_instructions,
            )
        except ValueError as exc:
            print(f"Batch generation failed: {exc}")
            return
        added = self.bank.add_many(candidates, source=f"typebatch:{kind}", preserve_unicode=self.bank.preserve_unicode)
        self.report_added(added)
        print(typed_wordlist_usage(kind))

    def do_aisetup(self, arg: str) -> None:
        print(color("AI API setup", "bold", "magenta"))
        print(f"OpenAI key: {mask_secret(os.environ.get('OPENAI_API_KEY', ''))}")
        print(f"Gemini key: {mask_secret(os.environ.get('GEMINI_API_KEY', ''))}")
        provider = self.ask_choice("Provider", ("openai", "gemini"), "openai")
        provider_label = ai_provider_label(provider)
        if provider == "openai":
            key_env = "OPENAI_API_KEY"
            model_env = "W0RDIT_OPENAI_MODEL"
            default_model = "gpt-4.1-mini"
        else:
            key_env = "GEMINI_API_KEY"
            model_env = "W0RDIT_GEMINI_MODEL"
            default_model = "gemini-2.5-flash"

        current_key = os.environ.get(key_env, "")
        key = self.ask_secret(f"{provider_label} API key", current_key)
        if not key:
            print("No key entered.")
            return
        os.environ[key_env] = key

        current_model = os.environ.get(model_env, "")
        model = self.ask("Default model", current_model or default_model)
        if model:
            os.environ[model_env] = model
        else:
            os.environ.pop(model_env, None)

        print(f"{provider_label} is configured for this session.")
        if self.ask_bool("Save for future w0rd!t sessions", False):
            values = {key_env: key}
            if model:
                values[model_env] = model
            path = write_ai_config(values)
            print(f"Saved AI settings to {path} with permissions 600.")
        else:
            print("Not saved. This key will disappear when you exit w0rd!t.")

    def do_aiapi(self, arg: str) -> None:
        self.do_aisetup(arg)

    def do_api(self, arg: str) -> None:
        self.do_aisetup(arg)

    def do_mutate(self, arg: str) -> None:
        if not self.bank:
            print("Add or import words first.")
            return
        if arg.strip().lower() in {"advanced", "adv"}:
            self.do_mutate_advanced("")
            return
        style = normalize_style(arg.strip()) if arg.strip() else self.ask_mutation_style("focused")
        if style not in MUTATION_STYLES and style != "balanced":
            print(f"Unknown mutation style: {arg.strip()}.")
            return
        options = self.simple_options_from_prompt(style)
        candidates = mutate_wordlist(self.bank.words(), options)
        added = self.bank.add_many(candidates, source=f"mutate:{style}")
        self.report_added(added)

    def do_mutate_advanced(self, arg: str) -> None:
        if not self.bank:
            print("Add or import words first.")
            return
        style = self.ask_mutation_style("focused")
        options = self.options_from_prompt(style)
        candidates = mutate_wordlist(self.bank.words(), options)
        added = self.bank.add_many(candidates, source=f"mutate-advanced:{style}")
        self.report_added(added)

    def do_huge(self, arg: str) -> None:
        print(color("Huge password patterns", "bold", "magenta"))
        print("For very large spaces, w0rd!t writes masks instead of giant text files.")
        raw_bases = arg.strip()
        if not raw_bases:
            default_hint = "blank uses current words" if self.bank else "example: kista"
            raw_bases = self.ask(f"Base words ({default_hint})")
        if raw_bases:
            bases: list[str] = []
            for item in parse_human_list(raw_bases):
                bases.extend(
                    extract_words(
                        item,
                        min_len=1,
                        max_len=64,
                        lowercase=False,
                        preserve_unicode=self.bank.preserve_unicode,
                    )
                    or [item]
                )
        else:
            bases = self.bank.words()
        bases = ordered_unique(bases)
        if not bases:
            print("Add words first, or enter base words like kista.")
            return

        known_digits = self.ask("Known digit chunk (blank = any digits)")
        if known_digits and not known_digits.isdigit():
            print("Known digit chunk must contain digits only.")
            return
        if known_digits:
            min_digits = max_digits = len(known_digits)
        else:
            min_digits = self.ask_int("Minimum trailing digits", 8, minimum=0)
            max_digits = self.ask_int("Maximum trailing digits", max(9, min_digits), minimum=min_digits)
        known_suffix = self.ask("Known exact ending (blank = any symbols)")
        symbol_count = 0
        if not known_suffix:
            symbol_count = self.ask_int("Trailing symbols", 2, minimum=0)
        use_capitals = self.ask_bool("Try capitalization variants", True)
        path = self.ask_path("Mask output path", "w0rdit-huge.hcmask")

        case_modes = ("raw", "lower", "upper", "title", "capitalize") if use_capitals else ("raw", "lower")
        digit_lengths = range(min_digits, max_digits + 1)
        masks = generate_huge_masks(
            bases,
            digit_lengths=digit_lengths,
            symbol_count=symbol_count,
            case_modes=case_modes,
            known_digits=known_digits,
            known_suffix=known_suffix,
            preserve_unicode=self.bank.preserve_unicode,
        )
        try:
            Path(path).expanduser().write_text("\n".join(masks) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Could not write masks: {exc}")
            return

        total = estimate_mask_collection_keyspace(masks)
        print(f"Wrote {format_count(len(masks))} huge-pattern masks to {path}.")
        print(f"Estimated represented keyspace: {format_count(total)} candidates.")
        if masks:
            print(f"Example mask: {masks[0]}")

    def do_mask(self, arg: str) -> None:
        mask = arg.strip() or self.ask("Mask")
        custom: dict[str, str] = {}
        for index in range(1, 5):
            value = self.ask(f"Custom ?{index} charset (blank skips)")
            if value:
                custom[str(index)] = value
        try:
            count = mask_keyspace(mask, custom)
        except ValueError as exc:
            print(f"Invalid mask: {exc}")
            return
        print(f"Mask keyspace: {format_count(count)} candidates.")
        limit_default = min(count, self.default_max_candidates)
        if count > self.default_max_candidates:
            if not self.ask_bool(f"Generate only the first {format_count(limit_default)} candidates", False):
                print("Skipped generation. Use hcmask to export the pattern instead.")
                return
        limit = self.ask_int("Generation limit", int(limit_default), minimum=1)
        candidates = generate_from_mask(mask, custom, limit=limit)
        added = self.bank.add_many(candidates, source="mask")
        self.report_added(added)

    def do_passphrase(self, arg: str) -> None:
        if not self.bank:
            print("Add or import source words first.")
            return
        count = self.ask_int("Words per passphrase", 3, minimum=2)
        raw_separators = self.ask("Separators, comma separated", "-,_,.")
        separators = tuple(item for item in parse_human_list(raw_separators) if item)
        style = self.ask("Style focused/quick/wide", "quick").lower()
        options = self.options_from_prompt(style)
        candidates = generate_passphrases(
            self.bank.words(),
            word_count=count,
            separators=separators or ("-",),
            options=options,
        )
        added = self.bank.add_many(candidates, source="passphrase")
        self.report_added(added)

    def do_rules(self, arg: str) -> None:
        path = arg.strip() or self.ask_path("Rule output path", "w0rdit.rule")
        style = self.ask("Style focused/quick/wide", "focused").lower()
        options = option_preset(style)
        rules = generate_hashcat_rules(options.years, options.symbols)
        try:
            Path(path).expanduser().write_text("\n".join(rules) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Could not write rules: {exc}")
            return
        print(f"Wrote {format_count(len(rules))} rules to {path}.")

    def do_hcmask(self, arg: str) -> None:
        path = arg.strip() or self.ask_path("Mask output path", "w0rdit.hcmask")
        top_words = [
            word
            for word in self.bank.words()[:50]
            if word and all(char not in word for char in ",\n\r")
        ]
        if not top_words:
            top_words = ["password", "summer", "welcome"]
        masks: list[str] = []
        for word in top_words:
            masks.extend(
                [
                    f"{word}?d?d",
                    f"{word}?d?d?d?d",
                    f"{word}?s?d?d",
                    f"{word}?d?d?s",
                ]
            )
        try:
            Path(path).expanduser().write_text("\n".join(ordered_unique(masks)) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Could not write masks: {exc}")
            return
        print(f"Wrote {format_count(len(ordered_unique(masks)))} masks to {path}.")

    def do_export_helpers(self, arg: str) -> None:
        choice = self.ask_choice("Export", ("rules", "hcmask", "both"), "both")
        if choice in {"rules", "both"}:
            self.do_rules("")
        if choice in {"hcmask", "both"}:
            self.do_hcmask("")

    def do_stats(self, arg: str) -> None:
        stats = self.bank.stats()
        print(f"Candidates: {format_count(stats['count'])}")
        print(f"Length: min {stats['min']}, max {stats['max']}, avg {format_count(stats['avg'])}")
        sources = stats["sources"]
        if isinstance(sources, Counter) and sources:
            print("Sources:")
            for source, count in sources.most_common(8):
                print(f"  {source}: {format_count(count)}")

    def do_preview(self, arg: str) -> None:
        count = 20
        if arg.strip():
            try:
                count = int(arg.strip())
            except ValueError:
                print("Usage: preview [count]")
                return
        if not self.bank:
            print("No candidates yet.")
            return
        for index, word in enumerate(self.bank.words()[:count], start=1):
            print(f"{index:>5}  {word}")

    def do_save(self, arg: str) -> None:
        if not self.bank:
            print("No candidates to save.")
            return
        path = arg.strip() or self.ask_path("Output path", "w0rdit.txt")
        sort_words = self.ask_bool("Sort alphabetically", False)
        words = sorted(self.bank.words()) if sort_words else self.bank.words()
        try:
            Path(path).expanduser().write_text("\n".join(words) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Could not save file: {exc}")
            return
        print(f"Wrote {format_count(len(words))} candidates to {path}.")

    def do_clear(self, arg: str) -> None:
        if self.ask_bool("Clear current session", False):
            self.bank.clear()
            print("Session cleared.")

    def do_exit(self, arg: str) -> bool:
        print("Later. Build sharp, test only where authorized.")
        return True

    def do_quit(self, arg: str) -> bool:
        return self.do_exit(arg)

    def do_EOF(self, arg: str) -> bool:
        print()
        return self.do_exit(arg)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Interactive and scriptable wordlist builder for authorized security work.",
    )
    parser.add_argument("--add", action="append", default=[], help="Seed words or phrases.")
    parser.add_argument("--import-file", action="append", default=[], help="Import a wordlist file.")
    parser.add_argument("--harvest-file", action="append", default=[], help="Extract words from a text file.")
    parser.add_argument("--harvest-url", action="append", default=[], help="Extract words from a single in-scope URL.")
    parser.add_argument("--profile", help="Comma-separated hint words for focused generation.")
    parser.add_argument(
        "--type",
        dest="wordlist_type",
        help="Generate a tool-ready typed list: password-base, subdomain, directory, or cloud-resource.",
    )
    parser.add_argument(
        "--ai-generate",
        action="store_true",
        help="Use OpenAI or Gemini to generate the typed list. Requires --type.",
    )
    parser.add_argument("--ai-provider", choices=("openai", "gemini"), help="AI provider for --ai-generate.")
    parser.add_argument("--ai-model", help="Model override for --ai-generate.")
    parser.add_argument("--ai-instructions", help="Extra instructions for typed AI generation.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview a typed generation plan or AI prompt without writing candidates.",
    )
    parser.add_argument("--batch-file", help="Read seed groups from a file for typed batch generation.")
    parser.add_argument("--batch-size", type=int, default=5, help="Seed lines per typed batch.")
    parser.add_argument(
        "--mutate",
        choices=("focused", "numbers", "symbols", "both", "caps", "quick", "balanced", "wide"),
        help="Mutate loaded words with a named style.",
    )
    parser.add_argument("--mask", help="Generate candidates from a hashcat-style mask.")
    parser.add_argument("--custom1", help="Custom ?1 charset for --mask.")
    parser.add_argument("--custom2", help="Custom ?2 charset for --mask.")
    parser.add_argument("--custom3", help="Custom ?3 charset for --mask.")
    parser.add_argument("--custom4", help="Custom ?4 charset for --mask.")
    parser.add_argument("--passphrase", type=int, help="Build passphrases with N words.")
    parser.add_argument("-o", "--output", help="Write candidates to this file and exit.")
    parser.add_argument("--rules-out", help="Write hashcat-compatible rules and exit.")
    parser.add_argument("--hcmask-out", help="Write hcmask templates and exit.")
    parser.add_argument("--min-len", type=int, default=DEFAULT_MIN_LEN)
    parser.add_argument("--max-len", type=int, default=DEFAULT_MAX_LEN)
    parser.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES)
    parser.add_argument(
        "--preserve-unicode",
        action="store_true",
        help="Keep non-ASCII letters when extracting and storing words.",
    )
    parser.add_argument("--i-understand", action="store_true", help="Confirm URL harvesting is authorized.")
    return parser


def run_noninteractive(args: argparse.Namespace) -> int:
    bank = WordBank(preserve_unicode=args.preserve_unicode)
    context_words: list[str] = []
    options = replace(
        option_preset(args.mutate or "focused", args.max_candidates),
        min_len=args.min_len,
        max_len=args.max_len,
        max_candidates=args.max_candidates,
        preserve_unicode=args.preserve_unicode,
    )
    if (args.ai_generate or args.batch_file or args.dry_run) and not args.wordlist_type:
        raise SystemExit("--ai-generate, --batch-file, and --dry-run are used with --type.")
    if args.batch_size < 1:
        raise SystemExit("--batch-size must be 1 or higher.")

    for raw in args.add:
        words: list[str] = []
        for item in parse_human_list(raw):
            words.extend(
                extract_words(
                    item,
                    min_len=1,
                    max_len=64,
                    lowercase=False,
                    preserve_unicode=args.preserve_unicode,
                )
                or [item]
            )
        context_words.extend(words)
        bank.add_many(words, source="manual")
    for path in args.import_file:
        imported_words = read_word_file(path, preserve_unicode=args.preserve_unicode)
        context_words.extend(imported_words)
        bank.add_many(
            imported_words,
            source=f"import:{Path(path).name}",
        )
    for path in args.harvest_file:
        text = Path(path).expanduser().read_text(encoding="utf-8", errors="ignore")
        harvested_words = extract_words(
            text,
            min_len=args.min_len,
            max_len=args.max_len,
            preserve_unicode=args.preserve_unicode,
        )
        context_words.extend(harvested_words)
        bank.add_many(
            harvested_words,
            source="harvest:file",
        )
    for url in args.harvest_url:
        if not args.i_understand:
            raise SystemExit("--harvest-url requires --i-understand to confirm authorization.")
        try:
            harvested = harvest_url(url)
        except ValueError as exc:
            raise SystemExit(f"Harvest failed: {exc}") from exc
        harvested_words = extract_words(
            harvested,
            min_len=args.min_len,
            max_len=args.max_len,
            preserve_unicode=args.preserve_unicode,
        )
        context_words.extend(harvested_words)
        bank.add_many(
            harvested_words,
            source="harvest:url",
        )
    if args.profile:
        profile = {"extras": args.profile, "dates": args.profile}
        tokens, dates = profile_tokens(profile, preserve_unicode=args.preserve_unicode)
        context_words.extend([*tokens, *dates])
        bank.add_many(build_profile_wordlist(profile, options), source="profile")
    if args.mask:
        custom = {
            key: value
            for key, value in {
                "1": args.custom1,
                "2": args.custom2,
                "3": args.custom3,
                "4": args.custom4,
            }.items()
            if value
        }
        count = mask_keyspace(args.mask, custom)
        if count > args.max_candidates:
            print(f"Mask keyspace is {format_count(count)}; generating first {format_count(args.max_candidates)}.")
        bank.add_many(generate_from_mask(args.mask, custom, limit=args.max_candidates), source="mask")
    if args.wordlist_type:
        try:
            wordlist_type = normalize_target_wordlist_type(args.wordlist_type)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        if args.ai_generate and not args.dry_run:
            load_ai_config()
        ai_provider = args.ai_provider or select_default_ai_provider()
        base_context = ordered_unique(context_words or bank.words())
        try:
            if args.batch_file:
                seed_groups = read_batch_seed_groups(
                    args.batch_file,
                    preserve_unicode=args.preserve_unicode,
                )
                if not seed_groups:
                    raise SystemExit("Batch file did not contain any seed words.")
                first_batch_seeds = ordered_unique(
                    [
                        *base_context,
                        *(seed for group in seed_groups[: args.batch_size] for seed in group),
                    ]
                )
                if args.dry_run:
                    print(f"Typed batch plan: {wordlist_type}, {len(seed_groups)} seed group(s), batch size {args.batch_size}.")
                    if args.ai_generate:
                        print(ai_wordlist_prompt(
                            wordlist_type,
                            first_batch_seeds,
                            max(1, min(args.max_candidates, args.max_candidates // max(1, len(seed_groups)) or 1)),
                            instructions=args.ai_instructions or "",
                        ))
                    else:
                        preview = generate_typed_wordlist(
                            wordlist_type,
                            first_batch_seeds,
                            limit=min(20, args.max_candidates),
                            preserve_unicode=args.preserve_unicode,
                        )
                        print("\n".join(preview))
                    return 0
                candidates = generate_batch_typed_wordlist(
                    wordlist_type,
                    seed_groups,
                    batch_size=args.batch_size,
                    limit=args.max_candidates,
                    base_context=base_context,
                    preserve_unicode=args.preserve_unicode,
                    ai_provider=ai_provider if args.ai_generate else "",
                    ai_model=args.ai_model or "",
                    ai_instructions=args.ai_instructions or "",
                )
            else:
                seeds = base_context
                if not seeds:
                    raise SystemExit("--type needs context from --add, --profile, --import-file, --harvest-file, --harvest-url, or --batch-file.")
                if args.dry_run:
                    print(f"Typed generation plan: {wordlist_type}, {len(seeds)} seed(s), limit {format_count(args.max_candidates)}.")
                    if args.ai_generate:
                        print(ai_wordlist_prompt(
                            wordlist_type,
                            seeds,
                            args.max_candidates,
                            instructions=args.ai_instructions or "",
                        ))
                    else:
                        preview = generate_typed_wordlist(
                            wordlist_type,
                            seeds,
                            limit=min(20, args.max_candidates),
                            preserve_unicode=args.preserve_unicode,
                        )
                        print("\n".join(preview))
                    return 0
                if args.ai_generate:
                    candidates = ai_generate_wordlist(
                        ai_provider,
                        wordlist_type,
                        seeds,
                        max_words=args.max_candidates,
                        model=args.ai_model or "",
                        instructions=args.ai_instructions or "",
                        preserve_unicode=args.preserve_unicode,
                    )
                else:
                    candidates = generate_typed_wordlist(
                        wordlist_type,
                        seeds,
                        limit=args.max_candidates,
                        preserve_unicode=args.preserve_unicode,
                    )
        except ValueError as exc:
            raise SystemExit(f"Typed generation failed: {exc}") from exc
        source = f"ai-generate:{wordlist_type}" if args.ai_generate else f"type:{wordlist_type}"
        added = bank.add_many(candidates, source=source, preserve_unicode=args.preserve_unicode)
        print(f"Added {format_count(added)} {wordlist_type} candidates.")
        if args.output:
            print(typed_wordlist_usage(wordlist_type, args.output))
    if args.mutate:
        bank.add_many(mutate_wordlist(bank.words(), options), source=f"mutate:{args.mutate}")
    if args.passphrase:
        bank.add_many(
            generate_passphrases(bank.words(), args.passphrase, ("-", "_", "."), options),
            source="passphrase",
        )
    if args.rules_out:
        rules = generate_hashcat_rules(options.years, options.symbols)
        Path(args.rules_out).expanduser().write_text("\n".join(rules) + "\n", encoding="utf-8")
        print(f"Wrote {format_count(len(rules))} rules to {args.rules_out}.")
    if args.hcmask_out:
        masks = []
        for word in (bank.words()[:50] or ["password", "summer", "welcome"]):
            masks.extend([f"{word}?d?d", f"{word}?d?d?d?d", f"{word}?s?d?d", f"{word}?d?d?s"])
        Path(args.hcmask_out).expanduser().write_text("\n".join(ordered_unique(masks)) + "\n", encoding="utf-8")
        print(f"Wrote {format_count(len(ordered_unique(masks)))} masks to {args.hcmask_out}.")
    if args.output:
        Path(args.output).expanduser().write_text("\n".join(bank.words()) + "\n", encoding="utf-8")
        print(f"Wrote {format_count(len(bank))} candidates to {args.output}.")
    elif any(
        [
            args.add,
            args.import_file,
            args.harvest_file,
            args.harvest_url,
            args.profile,
            args.mask,
            args.mutate,
            args.passphrase,
        ]
    ):
        for word in bank.words():
            print(word)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    noninteractive = any(
        [
            args.add,
            args.import_file,
            args.harvest_file,
            args.harvest_url,
            args.profile,
            args.wordlist_type,
            args.ai_generate,
            args.dry_run,
            args.batch_file,
            args.mask,
            args.mutate,
            args.passphrase,
            args.output,
            args.rules_out,
            args.hcmask_out,
        ]
    )
    if noninteractive:
        return run_noninteractive(args)
    try:
        WorditShell(preserve_unicode=args.preserve_unicode).cmdloop()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
