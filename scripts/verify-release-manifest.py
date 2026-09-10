#!/usr/bin/env python3
"""Independently fail closed when a pilot release manifest or bound file is invalid."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


REQUIRED_IMAGES = {
    "api",
    "browser-worker",
    "clamav",
    "cloudflared",
    "otel-collector",
    "private-gateway",
    "valkey",
    "web",
    "worker",
}
FIRST_PARTY_IMAGES = {"api", "browser-worker", "web", "worker"}
REQUIRED_KILL_SWITCHES = {
    "AI_GLOBAL_ENABLED",
    "AI_OPENAI_ROUTE_ENABLED",
    "AI_LOCAL_DETERMINISTIC_PROVIDERS_ENABLED",
    "AI_LOCAL_PRICING_DRAFTS_ENABLED",
    "ALLOW_EXTERNAL_WRITES",
    "TMS_EXTERNAL_WRITES_ENABLED",
    "BROWSER_EXECUTION_ENABLED",
    "OUTBOUND_OUTREACH_ENABLED",
    "ACCOUNTING_WRITES_ENABLED",
    "PAYMENT_EXECUTION_ENABLED",
    "APPLICATION_TELEPHONY_ENABLED",
    "EMAIL_DELIVERY_ENABLED",
    "SES_RECEIPT_SIGNATURE_VERIFICATION_ENABLED",
    "SES_SUPPRESSION_ENABLED",
    "PUBLIC_REGISTRATION_ENABLED",
    "SALES_PROVIDER_TEST_SEED_ENABLED",
    "SALES_VOICE_TEST_SEED_ENABLED",
    "TENDER_LOAD_CREATION_E2E_ENABLED",
}
SHA_RE = re.compile(r"[0-9a-f]{40}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
IMAGE_RE = re.compile(
    r"[0-9]{12}\.dkr\.ecr\.us-east-1\.amazonaws\.com/"
    r"freight-broker-pilot-([a-z0-9-]+)@sha256:[0-9a-f]{64}"
)
UPSTREAM_RE = re.compile(r"[^\s@]+(?:/[^\s@]+)+@sha256:[0-9a-f]{64}")


class VerificationError(ValueError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _file(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str):
        raise VerificationError("artifact path must be a string")
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts or candidate == Path("."):
        raise VerificationError("unsafe artifact path")
    path = root / candidate
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise VerificationError("missing bound artifact") from exc
    if not resolved.is_relative_to(root.resolve()) or path.is_symlink() or not path.is_file():
        raise VerificationError("artifact escapes release bundle")
    return path


def _verify_artifact(root: Path, value: Any, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise VerificationError(f"{label} must contain only path and sha256")
    path = _file(root, value["path"])
    if value["sha256"] != _sha256(path):
        raise VerificationError(f"{label} sha256 mismatch")


def _require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise VerificationError(f"{label} must contain exactly {sorted(expected)}")
    return value


def verify_manifest(args: argparse.Namespace) -> str:
    root = args.bundle_root.resolve(strict=True)
    manifest_path = args.manifest.resolve(strict=True)
    if not manifest_path.is_relative_to(root) or manifest_path.is_symlink():
        raise VerificationError("manifest must be a regular file inside bundle root")
    raw = manifest_path.read_bytes()
    payload = json.loads(raw)
    canonical = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if raw != canonical:
        raise VerificationError("manifest is not canonical JSON")
    top = _require_exact_keys(
        payload,
        {
            "configuration",
            "images",
            "kill_switches",
            "migration",
            "release",
            "rollback",
            "schema_version",
            "security",
            "signature_policy",
        },
        "manifest",
    )
    if top["schema_version"] != 1:
        raise VerificationError("unsupported schema_version")

    release = _require_exact_keys(
        top["release"],
        {
            "commit_sha",
            "created_at",
            "platform",
            "ref",
            "repository",
            "workflow_run_attempt",
            "workflow_run_id",
        },
        "release",
    )
    expected = {
        "repository": args.expected_repository,
        "ref": args.expected_ref,
        "commit_sha": args.expected_commit_sha,
        "platform": args.expected_platform,
    }
    for key, value in expected.items():
        if release.get(key) != value:
            raise VerificationError(f"release {key} does not match the trusted deployment input")
    if SHA_RE.fullmatch(release["commit_sha"]) is None:
        raise VerificationError("release commit_sha is invalid")
    if args.expected_platform != "linux/arm64":
        raise VerificationError("pilot deployment platform must be linux/arm64")
    if not isinstance(release["workflow_run_id"], str) or not release["workflow_run_id"].isdigit():
        raise VerificationError("workflow_run_id is invalid")
    if (
        not isinstance(release["workflow_run_attempt"], str)
        or not release["workflow_run_attempt"].isdigit()
        or int(release["workflow_run_attempt"]) <= 0
    ):
        raise VerificationError("workflow_run_attempt is invalid")
    try:
        created_at = datetime.fromisoformat(release["created_at"].replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise VerificationError("release created_at is invalid") from exc
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise VerificationError("release created_at must be timezone-aware")

    images = _require_exact_keys(top["images"], REQUIRED_IMAGES, "images")
    seen_uris: set[str] = set()
    for name, image in images.items():
        item = _require_exact_keys(
            image, {"first_party", "provenance", "sbom", "source", "uri"}, f"image {name}"
        )
        match = IMAGE_RE.fullmatch(item["uri"] if isinstance(item["uri"], str) else "")
        if match is None or match.group(1) != name or item["uri"] in seen_uris:
            raise VerificationError(f"image {name} must have one unique exact ECR digest URI")
        seen_uris.add(item["uri"])
        first_party = name in FIRST_PARTY_IMAGES
        if item["first_party"] is not first_party:
            raise VerificationError(f"image {name} first_party classification is invalid")
        source = item["source"]
        if first_party:
            source = _require_exact_keys(source, {"kind", "revision"}, f"image {name} source")
            if source != {"kind": "built", "revision": release["commit_sha"]}:
                raise VerificationError(f"image {name} is not bound to release commit_sha")
        else:
            source = _require_exact_keys(source, {"kind", "upstream_uri"}, f"image {name} source")
            if (
                source.get("kind") != "mirrored"
                or UPSTREAM_RE.fullmatch(source.get("upstream_uri", "")) is None
            ):
                raise VerificationError(f"image {name} upstream source is not digest-bound")
        _verify_artifact(root, item["sbom"], f"image {name} SBOM")
        _verify_artifact(root, item["provenance"], f"image {name} provenance")

    configuration = top["configuration"]
    if not isinstance(configuration, dict) or not configuration:
        raise VerificationError("configuration must be a non-empty hash map")
    for relative, expected_sha in configuration.items():
        if expected_sha != _sha256(_file(root, relative)):
            raise VerificationError(f"configuration {relative} sha256 mismatch")

    security = _require_exact_keys(top["security"], {"ci", "codeql", "trivy"}, "security")
    ci = _require_exact_keys(
        security["ci"],
        {
            "commit_sha",
            "ref",
            "run_attempt",
            "run_id",
            "workflow_identity",
            "workflow_path",
        },
        "security CI binding",
    )
    expected_ci = {
        "commit_sha": release["commit_sha"],
        "ref": release["ref"],
        "workflow_identity": (
            f"https://github.com/{release['repository']}/.github/workflows/ci.yml@{release['ref']}"
        ),
        "workflow_path": ".github/workflows/ci.yml",
    }
    if any(ci.get(key) != value for key, value in expected_ci.items()):
        raise VerificationError("security CI identity, commit, or ref does not match the release")
    for key in ("run_id", "run_attempt"):
        if not isinstance(ci[key], str) or not ci[key].isdigit() or int(ci[key]) <= 0:
            raise VerificationError(f"security CI {key} is invalid")
    for scanner, label in (("codeql", "CodeQL"), ("trivy", "Trivy")):
        evidence = _require_exact_keys(
            security[scanner], {"evidence", "sigstore_bundle"}, f"{label} security evidence"
        )
        _verify_artifact(root, evidence["evidence"], f"{label} evidence")
        _verify_artifact(root, evidence["sigstore_bundle"], f"{label} Sigstore bundle")

    switches = _require_exact_keys(top["kill_switches"], REQUIRED_KILL_SWITCHES, "kill switches")
    if any(value is not False for value in switches.values()):
        raise VerificationError("every integration kill switch must be false")

    migration = _require_exact_keys(
        top["migration"], {"direction", "expected_head", "owner"}, "migration"
    )
    if migration["direction"] != "forward-only" or migration["owner"] != "single-core-migration-job":
        raise VerificationError("migration must be a single forward-only core job")

    rollback = _require_exact_keys(
        top["rollback"],
        {"previous_release_digest", "schema_downgrade_allowed", "scope"},
        "rollback",
    )
    previous = rollback["previous_release_digest"]
    if previous is not None and DIGEST_RE.fullmatch(previous) is None:
        raise VerificationError("previous release digest is invalid")
    if (
        rollback["schema_downgrade_allowed"] is not False
        or rollback["scope"] != "application-and-configuration-only"
    ):
        raise VerificationError("rollback must never permit a schema downgrade")

    policy = _require_exact_keys(
        top["signature_policy"], {"issuer", "release_workflow"}, "signature policy"
    )
    if policy["issuer"] != "https://token.actions.githubusercontent.com":
        raise VerificationError("signature issuer is invalid")
    expected_identity = (
        f"https://github.com/{args.expected_repository}/.github/workflows/release.yml@"
        f"{args.expected_ref}"
    )
    if policy["release_workflow"] != expected_identity:
        raise VerificationError("release workflow signature identity is invalid")
    return _sha256(manifest_path)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-ref", required=True)
    parser.add_argument("--expected-commit-sha", required=True)
    parser.add_argument("--expected-platform", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        digest = verify_manifest(parse_args(argv or sys.argv[1:]))
        print(f"verified release manifest sha256:{digest}")
        return 0
    except (VerificationError, OSError, json.JSONDecodeError) as exc:
        print(f"release manifest verification failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
