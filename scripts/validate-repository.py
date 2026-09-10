#!/usr/bin/env python3
"""Fail closed when the public control repository contains unsafe material."""

from __future__ import annotations

import re
import sys
from pathlib import Path


MAX_TEXT_BYTES = 512_000

ALLOWED_FILES = frozenset(
    {
        ".github/CODEOWNERS",
        ".github/dependabot.yml",
        ".github/workflows/ci.yml",
        ".github/workflows/deploy-pilot.yml",
        ".gitignore",
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "scripts/extract-release-bundle.py",
        "scripts/validate-repository.py",
        "scripts/verify-release-manifest.py",
        "scripts/wait-for-ssm-command.sh",
        "tests/test_release_verification.py",
        "tests/test_repository_contract.py",
    }
)

_IGNORED_PARTS = frozenset({".git", "__pycache__", ".pytest_cache"})
_FORBIDDEN_PATTERNS = (
    ("AWS account identifier", re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")),
    ("EC2 instance identifier", re.compile(r"\bi-[0-9a-f]{17}\b")),
    (
        "private key material",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    ("private repository clone", re.compile(r"\bgit\s+clone\s+\S+", re.IGNORECASE)),
    ("unsafe pull request trigger", re.compile(r"^\s*pull_request_target\s*:", re.MULTILINE)),
    (
        "literal secret assignment",
        re.compile(
            r"(?im)^\s*(?:api[_-]?key|client[_-]?secret|password|private[_-]?key)"
            r"\s*[:=]\s*(?!\$\{\{\s*secrets\.)[^\s#]{8,}"
        ),
    ),
)
_USES_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)
_PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$")


def _repository_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part in _IGNORED_PARTS for part in relative.parts):
            continue
        if path.is_symlink() or path.is_file():
            paths.append(path)
    return sorted(paths, key=lambda item: item.as_posix())


def validate_repository(root: Path) -> list[str]:
    root = root.resolve()
    findings: list[str] = []
    repository_files = _repository_files(root)
    present = {path.relative_to(root).as_posix() for path in repository_files}
    for missing in sorted(ALLOWED_FILES - present):
        findings.append(f"missing required path: {missing}")
    for path in repository_files:
        relative = path.relative_to(root).as_posix()
        if relative not in ALLOWED_FILES:
            findings.append(f"unexpected path: {relative}")
            continue
        if path.is_symlink():
            findings.append(f"symlink forbidden: {relative}")
            continue
        size = path.stat().st_size
        if size > MAX_TEXT_BYTES:
            findings.append(f"oversized file forbidden: {relative}")
            continue
        payload = path.read_bytes()
        if b"\x00" in payload:
            findings.append(f"binary file forbidden: {relative}")
            continue
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            findings.append(f"non-UTF-8 file forbidden: {relative}")
            continue
        for label, pattern in _FORBIDDEN_PATTERNS:
            if pattern.search(text):
                findings.append(f"{label} forbidden in: {relative}")
        for action in _USES_LINE.findall(text):
            if action.startswith("./"):
                continue
            if not _PINNED_ACTION.fullmatch(action):
                findings.append(f"unpinned action forbidden in: {relative}")
    return sorted(set(findings))


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    findings = validate_repository(root)
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1
    print(f"public repository safety validation passed ({len(ALLOWED_FILES)} allowlisted paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
