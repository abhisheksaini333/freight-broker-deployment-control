#!/usr/bin/env python3
"""Extract the one signed release layer without trusting tar member paths."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath


MAX_MEMBERS = 256
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024

_EXACT_FILES = frozenset(
    {
        "deploy/compose/core.yml",
        "deploy/compose/isolated-worker.yml",
        "deploy/systemd/freight-broker-core.service",
        "deploy/systemd/freight-broker-isolated.service",
        "evidence/security/codeql-evidence.json",
        "evidence/security/codeql-evidence.sigstore.json",
        "evidence/security/trivy-evidence.json",
        "evidence/security/trivy-evidence.sigstore.json",
        "images.json",
        "migration-head.txt",
        "release-manifest.v1.json",
        "scripts/validate-production-config.py",
        "scripts/verify-release-manifest.py",
    }
)
_DYNAMIC_FILE = re.compile(
    r"(?:fragments/[a-z0-9-]+\.json|"
    r"evidence/sbom/[a-z0-9-]+\.spdx\.json|"
    r"evidence/provenance/[a-z0-9-]+\.intoto\.json)"
)
_ALLOWED_DIRECTORIES = frozenset(
    {
        "deploy",
        "deploy/compose",
        "deploy/systemd",
        "evidence",
        "evidence/provenance",
        "evidence/sbom",
        "evidence/security",
        "fragments",
        "scripts",
    }
)


class ExtractionError(ValueError):
    pass


def _normalized_member(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    if name in {"", "."}:
        return ""
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts or any(part in {"", "."} for part in pure.parts):
        raise ExtractionError("release archive contains an unsafe path")
    return pure.as_posix()


def _allowed_file(relative: str) -> bool:
    return relative in _EXACT_FILES or _DYNAMIC_FILE.fullmatch(relative) is not None


def _target_path(output: Path, relative: str) -> Path:
    target = output.joinpath(*PurePosixPath(relative).parts)
    if not target.resolve(strict=False).is_relative_to(output.resolve()):
        raise ExtractionError("release archive target escapes output directory")
    return target


def extract_archive(archive_path: Path, output: Path) -> list[str]:
    archive_path = archive_path.resolve(strict=True)
    if archive_path.is_symlink() or not archive_path.is_file():
        raise ExtractionError("release archive must be one regular file")
    output = output.resolve(strict=False)
    if output.exists() and any(output.iterdir()):
        raise ExtractionError("release output directory must be empty")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)

    extracted: list[str] = []
    seen: set[str] = set()
    total_bytes = 0
    try:
        archive = tarfile.open(archive_path, mode="r:")
    except tarfile.TarError as exc:
        raise ExtractionError("release archive is not an uncompressed tar file") from exc

    with archive:
        members = archive.getmembers()
        if len(members) > MAX_MEMBERS:
            raise ExtractionError("release archive has too many members")
        for member in members:
            relative = _normalized_member(member.name)
            if not relative:
                if member.isdir():
                    continue
                raise ExtractionError("release archive root member is invalid")
            if relative in seen:
                raise ExtractionError("release archive contains duplicate members")
            seen.add(relative)
            if member.isdir():
                if relative not in _ALLOWED_DIRECTORIES:
                    raise ExtractionError("release archive contains an unexpected directory")
                _target_path(output, relative).mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            if not member.isfile():
                raise ExtractionError("release archive contains a link or special file")
            if not _allowed_file(relative):
                raise ExtractionError("release archive contains an unexpected file")
            if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                raise ExtractionError("release archive member exceeds the size limit")
            total_bytes += member.size
            if total_bytes > MAX_TOTAL_BYTES:
                raise ExtractionError("release archive exceeds the total size limit")
            target = _target_path(output, relative)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source = archive.extractfile(member)
            if source is None:
                raise ExtractionError("release archive member cannot be read")
            try:
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except OSError as exc:
                raise ExtractionError("release archive target cannot be created safely") from exc
            with source, os.fdopen(descriptor, "wb") as destination:
                shutil.copyfileobj(source, destination, length=1024 * 1024)
            if target.stat().st_size != member.size:
                raise ExtractionError("release archive member size changed during extraction")
            extracted.append(relative)
    if "release-manifest.v1.json" not in extracted:
        raise ExtractionError("release archive manifest is missing")
    return sorted(extracted)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv or sys.argv[1:])
        extracted = extract_archive(args.archive, args.output)
        print(f"extracted {len(extracted)} bounded release files")
        return 0
    except (ExtractionError, OSError, tarfile.TarError) as exc:
        print(f"release extraction failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
