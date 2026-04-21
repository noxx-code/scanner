"""Command line interface for modular authorized web scanner."""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from secscan.checks.base import ScanContext
from secscan.crawler import WebCrawler
from secscan.fingerprint import Fingerprinter
from secscan.reporter import ReportGenerator
from secscan.scanner import ScannerCore
from secscan.utils.config import ScanConfig
from secscan.utils.logging import configure_logging
from secscan.utils.models import ScanMetadata, ScanSession
from secscan.utils.session_store import SessionStore

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser."""
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="Authorized testing only web security scanner",
    )
    parser.add_argument("target", help="Target base URL, e.g. https://example.com")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth")
    parser.add_argument("--threads", type=int, default=20, help="Parallel worker count")
    parser.add_argument("--rate-limit", type=float, default=5.0, help="Requests per second cap")
    parser.add_argument(
        "--output",
        choices=["json", "html", "csv", "all"],
        default="all",
        help="Output report format",
    )
    parser.add_argument("--output-dir", default="reports", help="Directory for generated reports")
    parser.add_argument("--name", default="scan_report", help="Report basename")
    parser.add_argument("--allow-external", action="store_true", help="Allow cross-domain crawling")
    parser.add_argument("--ignore-robots", action="store_true", help="Disable robots.txt respect")
    parser.add_argument("--resume", help="Resume from a saved session name")
    parser.add_argument("--save-session", help="Save session under this name")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser


def main() -> int:
    """CLI entry point."""
    args = build_parser().parse_args()
    configure_logging(verbose=args.verbose)

    print("=" * 72)
    print("Authorized testing only. Do not scan systems without explicit permission.")
    print("This scanner performs non-destructive, light security checks.")
    print("=" * 72)

    try:
        config = ScanConfig(
            target_url=args.target,
            depth=args.depth,
            threads=args.threads,
            rate_limit=args.rate_limit,
            same_domain_only=not args.allow_external,
            respect_robots_txt=not args.ignore_robots,
            output_dir=Path(args.output_dir),
            output_basename=args.name,
        )
    except ValueError as exc:
        print(f"Configuration error: {exc}")
        return 2

    session_store = SessionStore()
    metadata = ScanMetadata(target_url=config.target_url)

    if args.resume:
        try:
            session = session_store.load(args.resume)
        except FileNotFoundError:
            print(f"Session not found: {args.resume}")
            return 2
        except Exception as exc:  # noqa: BLE001
            print(f"Failed to load session '{args.resume}': {exc}")
            return 2

        crawl_result = session.crawl_result
        fingerprints = session.fingerprints
        findings = session.findings
        metadata = session.metadata
        print(f"Resumed session '{args.resume}' with {len(findings)} existing findings.")
    else:
        crawl_result, fingerprints, findings = asyncio.run(run_scan(config))

    if metadata.ended_at is None:
        metadata.finish()
    reporter = ReportGenerator(config.output_dir)

    json_path = html_path = csv_path = None
    if args.output in {"json", "all"}:
        json_path = reporter.write_json(config.output_basename, metadata, findings, fingerprints)
    if args.output in {"html", "all"}:
        html_path = reporter.write_html(config.output_basename, metadata, findings, fingerprints)
    if args.output in {"csv", "all"}:
        csv_path = reporter.write_csv(config.output_basename, findings)

    if args.save_session:
        try:
            session_store.save(
                args.save_session,
                ScanSession(
                    metadata=metadata,
                    crawl_result=crawl_result,
                    fingerprints=fingerprints,
                    findings=findings,
                ),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to save session", extra={"error": str(exc), "session": args.save_session})

    print("\nScan completed")
    print(f"Target: {config.target_url}")
    print(f"Pages discovered: {len(crawl_result.urls)}")
    print(f"Endpoints discovered: {len(crawl_result.endpoints)}")
    print(f"Fingerprints: {len(fingerprints)}")
    print(f"Findings: {len(findings)}")

    if json_path:
        print(f"JSON report: {json_path}")
    if html_path:
        print(f"HTML report: {html_path}")
    if csv_path:
        print(f"CSV report: {csv_path}")

    return 0


async def run_scan(config: ScanConfig):
    """Run full crawl -> fingerprint -> scan workflow."""
    crawler = WebCrawler(config)
    crawl_result = await crawler.crawl()

    fingerprinter = Fingerprinter(timeout=config.request_timeout)
    fingerprints = await fingerprinter.fingerprint(crawl_result)

    scanner = ScannerCore(config)
    context = ScanContext.from_target(target_url=config.target_url, js_files=crawl_result.js_files)
    findings = await scanner.scan(crawl_result.endpoints, context)

    return crawl_result, fingerprints, findings
