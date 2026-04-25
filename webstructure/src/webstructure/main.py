"""webstructure — HTML structure-discovery tool.

Ports the core crawl logic of LLMAppSec's webstructure-collector service
(2426 LOC, 4-stage PageDiscovery → PageRetrieval → FunctionDiscovery →
RequestExtraction) into a single /invoke endpoint. This is the v0.1.0
MVP port — no Playwright, no SPA rendering, no OpenAPI dereferencing.
Covers:

1. **Link discovery**: recursive same-origin crawl starting from a seed
   page, BFS up to `max_depth` / `max_pages`. Extracts `<a href>`,
   `<link href>`, and `<form action>` values.
2. **Form extraction**: every HTML `<form>` becomes a structured record
   with method / action / input names / types / `required` flags — the
   main "real endpoints" signal (feroxbuster can't find these).
3. **API-doc hints**: paths that look like OpenAPI / Swagger docs
   (`/openapi.json`, `/swagger.json`, `/api-docs/*`, `/docs`) are
   flagged so an upstream engine can follow up with a targeted fetch.

Designed to be called by recon engines via
`ctx.call_tool("webstructure", {...})`. The engine merges the returned
`web_pages[]` / `forms[]` into its Endpoint / Form lists. This is the
piece that catches endpoints feroxbuster misses — things like form
action URLs that never appear in a wordlist.

Deferred to v0.2.0:
- Playwright / SPA rendering (adds 200 MB Chromium to the image; skip
  until we hit an engine that actually needs it)
- robots.txt parsing / respect (v0.1 is opt-in to crawl; pentest
  contexts usually IGNORE robots, so that's fine here)
- OpenAPI / Swagger JSON dereferencing → structured endpoint list
- Session-aware crawl (auth-walled pages)
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Literal
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (compatible; trustchain-tool-webstructure/0.1)"

# ---- API doc heuristics ----
# Any discovered URL whose path matches one of these hints gets flagged
# in the api_hints list. Engines can then follow up with a targeted
# fetch to parse the spec.
_API_DOC_HINT_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api/docs",
    "/docs",
    "/redoc",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/api-docs",
)


# ==============================================================
# Request / Response models
# ==============================================================


class WebstructureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(
        description="Seed URL to start the crawl. Must include scheme (http:// or https://).",
        min_length=1,
        max_length=2048,
    )
    max_depth: int = Field(
        default=2,
        ge=0,
        le=4,
        description="Recursion depth cap. 0 = fetch the seed page only. Default 2 is a reasonable bound for a recon-stage crawl; >=3 starts getting expensive on large sites.",
    )
    max_pages: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Hard cap on total pages fetched across all depths. Prevents runaway crawls.",
    )
    same_origin_only: bool = Field(
        default=True,
        description="If true, only crawl URLs whose (scheme, host, port) match the seed. Off-origin URLs are still reported as external links but not fetched.",
    )
    timeout_sec: float = Field(
        default=10.0,
        gt=0,
        le=60,
        description="Per-request HTTP timeout.",
    )
    concurrency: int = Field(
        default=4,
        ge=1,
        le=20,
        description="Max concurrent in-flight fetches.",
    )
    use_playwright: bool = Field(
        default=True,
        description="Render pages via headless Chromium before parsing. ON by default (matches LLMAppSec). Required for SPA targets (React/Vue/Angular/Next.js) where the initial HTML is a near-empty shell. Disable for static / SSR sites where the ~1-3s/page rendering overhead is wasted; the httpx fast path is then used instead.",
    )
    playwright_wait_until: str = Field(
        default="networkidle",
        description="Playwright page.goto() wait condition. 'networkidle' is the safest default for SPAs (waits until ~500ms of no network activity). Other valid values: 'load' / 'domcontentloaded' / 'commit'. Ignored when use_playwright=false.",
    )
    playwright_extra_wait_ms: int = Field(
        default=0,
        ge=0,
        le=10_000,
        description="Additional delay after networkidle before extracting the DOM. Set 1000-3000 for very lazy SPAs that fire XHR after networkidle. 0 by default to keep the common case fast.",
    )


class WebPage(BaseModel):
    path: str = Field(description="Path + query, relative to seed origin. '/' for root.")
    status_code: int = Field(description="HTTP status code. 0 if fetch failed (connection error, timeout).")
    title: str = Field(default="", description="HTML <title> text, trimmed to 200 chars. Empty if not HTML / no title.")
    content_type: str = Field(default="", description="Content-Type response header, minus charset.")
    size_bytes: int = Field(default=0, ge=0)


class FormField(BaseModel):
    name: str
    type: str = Field(default="text", description="<input type=...> value, or 'textarea' / 'select'.")
    required: bool = False


class Form(BaseModel):
    page_path: str = Field(description="Path of the page this form was found on.")
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"] = "GET"
    action: str = Field(description="Resolved absolute URL of the form action. Empty string if action attribute was missing (submits to page_path).")
    fields: list[FormField] = Field(default_factory=list)


class WebstructureResponse(BaseModel):
    success: bool
    web_pages: list[WebPage] = Field(default_factory=list)
    forms: list[Form] = Field(default_factory=list)
    api_hints: list[str] = Field(default_factory=list, description="Paths that look like OpenAPI/Swagger docs.")
    pages_crawled: int = 0
    duration_sec: float = 0.0
    error: str = ""


# ==============================================================
# Crawler
# ==============================================================


class _Crawler:
    def __init__(self, req: WebstructureRequest):
        self.req = req
        parsed = urlparse(req.target_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"target_url must include scheme and host: {req.target_url!r}")
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.seed_path = parsed.path or "/"

        self.visited: set[str] = set()
        self.queue: deque[tuple[str, int]] = deque()  # (path, depth)
        self.queue.append((self.seed_path, 0))

        self.pages: list[WebPage] = []
        self.forms: list[Form] = []
        self.api_hints: set[str] = set()

        self.sem = asyncio.Semaphore(req.concurrency)
        # Set when run() with use_playwright=True launches a browser. The
        # context manager is held inside run() for the whole crawl so we
        # pay the ~500ms launch cost once, not per-page.
        self._browser = None

    async def run(self, client: httpx.AsyncClient) -> None:
        """BFS-ish crawl. Pops up to `concurrency` pages per wave and
        fetches in parallel, adds their discovered links back to queue.

        When use_playwright=True, holds a single headless Chromium context
        for the whole crawl (each page gets its own tab). Falls back to
        httpx if Playwright import fails or browser launch fails (so a
        misconfigured image still produces partial output)."""
        if self.req.use_playwright:
            try:
                from playwright.async_api import async_playwright
            except ImportError:
                logger.warning("playwright not installed; falling back to httpx fast path")
            else:
                try:
                    async with async_playwright() as pw:
                        self._browser = await pw.chromium.launch(headless=True)
                        try:
                            await self._crawl_loop(client)
                        finally:
                            await self._browser.close()
                            self._browser = None
                    return
                except Exception as exc:
                    logger.warning("playwright launch failed (%s); falling back to httpx", exc)
                    self._browser = None
                    # Reset visited/queue state so the fallback re-crawls cleanly.
                    self.visited.clear()
                    self.queue.clear()
                    self.queue.append((self.seed_path, 0))
                    self.pages.clear()
                    self.forms.clear()
                    self.api_hints.clear()

        await self._crawl_loop(client)

    async def _crawl_loop(self, client: httpx.AsyncClient) -> None:
        """The actual BFS loop, called by run() with or without an active
        Playwright browser context. _fetch_and_parse picks the path."""
        while self.queue and len(self.visited) < self.req.max_pages:
            batch: list[tuple[str, int]] = []
            while self.queue and len(batch) < self.req.concurrency:
                path, depth = self.queue.popleft()
                if path in self.visited:
                    continue
                if len(self.visited) >= self.req.max_pages:
                    break
                self.visited.add(path)
                batch.append((path, depth))

            if not batch:
                break

            await asyncio.gather(*(self._fetch_and_parse(client, p, d) for p, d in batch))

    async def _fetch_and_parse(
        self, client: httpx.AsyncClient, path: str, depth: int
    ) -> None:
        async with self.sem:
            if self._browser is not None:
                await self._fetch_via_playwright(path, depth)
            else:
                await self._fetch_via_httpx(client, path, depth)

    async def _fetch_via_httpx(
        self, client: httpx.AsyncClient, path: str, depth: int
    ) -> None:
        try:
            resp = await client.get(
                self.origin + path,
                timeout=self.req.timeout_sec,
                follow_redirects=True,
            )
        except (httpx.HTTPError, asyncio.TimeoutError) as exc:
            logger.debug("fetch failed for %s: %s", path, exc)
            self.pages.append(WebPage(path=path, status_code=0))
            return

        ctype_raw = resp.headers.get("content-type", "")
        ctype = ctype_raw.split(";", 1)[0].strip().lower()
        body = resp.text if ctype.startswith("text/") else ""
        title, size_bytes = "", len(resp.content)
        if ctype == "text/html" and body:
            soup = BeautifulSoup(body, "html.parser")
            title = self._title_from_soup(soup)
            self._handle_links_and_forms(soup, path, depth, body)

        self._record_api_doc_hint_if_matches_path(path)

        self.pages.append(
            WebPage(
                path=path,
                status_code=resp.status_code,
                title=title,
                content_type=ctype,
                size_bytes=size_bytes,
            )
        )

    async def _fetch_via_playwright(self, path: str, depth: int) -> None:
        """Open a fresh tab in the shared browser, navigate, wait for
        rendering to settle, then extract from the rendered DOM."""
        url = self.origin + path
        # Per-page context so cookies don't leak across pages and we can
        # close cleanly even on errors.
        ctx = await self._browser.new_context()
        try:
            page = await ctx.new_page()
            try:
                resp = await page.goto(
                    url,
                    wait_until=self.req.playwright_wait_until,
                    timeout=int(self.req.timeout_sec * 1000),
                )
            except Exception as exc:
                logger.debug("playwright goto failed for %s: %s", url, exc)
                self.pages.append(WebPage(path=path, status_code=0))
                return

            if self.req.playwright_extra_wait_ms:
                await page.wait_for_timeout(self.req.playwright_extra_wait_ms)

            status_code = resp.status if resp else 0
            ctype_raw = (resp.headers.get("content-type", "") if resp else "")
            ctype = ctype_raw.split(";", 1)[0].strip().lower()

            try:
                body = await page.content()
            except Exception as exc:
                logger.debug("playwright content() failed for %s: %s", url, exc)
                body = ""

            soup = BeautifulSoup(body, "html.parser") if body else None
            title = self._title_from_soup(soup) if soup else ""
            if soup is not None:
                self._handle_links_and_forms(soup, path, depth, body)

            self._record_api_doc_hint_if_matches_path(path)

            self.pages.append(
                WebPage(
                    path=path,
                    status_code=status_code,
                    title=title,
                    content_type=ctype or "text/html",
                    size_bytes=len(body.encode("utf-8")) if body else 0,
                )
            )
        finally:
            await ctx.close()

    def _record_api_doc_hint_if_matches_path(self, path: str) -> None:
        """If the URL we just fetched looks like an API doc endpoint
        (regardless of Content-Type — swagger.json is served as
        application/json, not text/html, so the body-based hint
        detection in _handle_links_and_forms misses it), flag it."""
        if any(path.endswith(hint) or path == hint for hint in _API_DOC_HINT_PATHS):
            self.api_hints.add(path)

    @staticmethod
    def _title_from_soup(soup: BeautifulSoup) -> str:
        if soup.title and soup.title.string:
            return soup.title.string.strip()[:200]
        return ""

    def _handle_links_and_forms(
        self, soup: BeautifulSoup, path: str, depth: int, body: str
    ) -> None:
        if depth < self.req.max_depth:
            for link in self._extract_links(soup, path):
                if link not in self.visited:
                    self.queue.append((link, depth + 1))

        for form_path, method, action, fields in self._extract_forms(soup, path):
            self.forms.append(
                Form(page_path=form_path, method=method, action=action, fields=fields)
            )

        # API-doc hint discovery from the rendered body. The path-based
        # check (request URL itself looks like an API doc) is done by
        # _record_api_doc_hint_if_matches_path in the caller.
        for hint in _API_DOC_HINT_PATHS:
            if hint in body:
                self.api_hints.add(hint)

    def _extract_links(self, soup: BeautifulSoup, current_path: str) -> list[str]:
        """Extract same-origin link paths from a parsed page.

        Sources: <a href>, <link href>, <form action>. JS-generated
        links are invisible — v0.2 Playwright work fixes that."""
        out: list[str] = []
        seen: set[str] = set()
        for tag_name, attr in (("a", "href"), ("link", "href"), ("form", "action")):
            for tag in soup.find_all(tag_name):
                val = tag.get(attr)
                if not val:
                    continue
                resolved = self._resolve_to_path(val, current_path)
                if resolved and resolved not in seen:
                    seen.add(resolved)
                    out.append(resolved)
        return out

    def _resolve_to_path(self, href: str, current_path: str) -> str | None:
        """Resolve an href to a path string (no scheme/host). Return None
        if the href is off-origin and same_origin_only is true, or if the
        href is a non-fetchable protocol (mailto:, tel:, javascript:)."""
        href = href.strip()
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
            return None
        absolute = urljoin(self.origin + current_path, href)
        absolute, _ = urldefrag(absolute)  # strip #fragment
        parsed = urlparse(absolute)
        if self.req.same_origin_only:
            seed_parsed = urlparse(self.origin)
            if (parsed.scheme, parsed.netloc) != (seed_parsed.scheme, seed_parsed.netloc):
                return None
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path

    def _extract_forms(
        self, soup: BeautifulSoup, page_path: str
    ) -> list[tuple[str, str, str, list[FormField]]]:
        out: list[tuple[str, str, str, list[FormField]]] = []
        for form in soup.find_all("form"):
            method_raw = (form.get("method") or "GET").upper()
            method = method_raw if method_raw in {"GET", "POST", "PUT", "DELETE", "PATCH"} else "GET"
            action_attr = form.get("action") or ""
            action_abs = (
                urljoin(self.origin + page_path, action_attr)
                if action_attr
                else self.origin + page_path
            )

            fields: list[FormField] = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name") or ""
                if not name:
                    continue
                if inp.name == "input":
                    ftype = (inp.get("type") or "text").lower()
                else:
                    ftype = inp.name
                required = inp.has_attr("required")
                fields.append(FormField(name=name, type=ftype, required=required))

            out.append((page_path, method, action_abs, fields))
        return out


# ==============================================================
# FastAPI app
# ==============================================================


app = FastAPI(
    title="trustchain-tool-webstructure",
    version="0.1.1",
    description="HTML structure-discovery tool. Recursively crawls a target site for pages, forms, and API-doc hints. v0.1: no Playwright / SPA support.",
)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/schema")
async def schema() -> dict[str, object]:
    return {
        "tool_id": "webstructure",
        "version": "0.1.1",
        "request_schema": WebstructureRequest.model_json_schema(),
        "response_schema": WebstructureResponse.model_json_schema(),
    }


@app.post("/invoke", response_model=WebstructureResponse)
async def invoke(body: WebstructureRequest) -> WebstructureResponse:
    started = time.perf_counter()
    try:
        crawler = _Crawler(body)
    except ValueError as exc:
        return WebstructureResponse(
            success=False,
            error=f"bad_request: {exc}",
            duration_sec=time.perf_counter() - started,
        )

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    ) as client:
        try:
            await crawler.run(client)
        except Exception as exc:
            logger.exception("crawl error")
            return WebstructureResponse(
                success=False,
                web_pages=crawler.pages,
                forms=crawler.forms,
                api_hints=sorted(crawler.api_hints),
                pages_crawled=len(crawler.pages),
                duration_sec=time.perf_counter() - started,
                error=f"crawl_failed: {exc}",
            )

    return WebstructureResponse(
        success=True,
        web_pages=crawler.pages,
        forms=crawler.forms,
        api_hints=sorted(crawler.api_hints),
        pages_crawled=len(crawler.pages),
        duration_sec=time.perf_counter() - started,
    )
