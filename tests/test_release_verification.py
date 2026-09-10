from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR_PATH = ROOT / "scripts" / "extract-release-bundle.py"
VERIFIER_PATH = ROOT / "scripts" / "verify-release-manifest.py"
EXPECTED_REPOSITORY = "abhisheksaini333/freight-broker"
EXPECTED_REF = "refs/tags/release-control-test"
EXPECTED_COMMIT = "a" * 40
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
KILL_SWITCHES = {
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


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical(payload: object) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def add_tar_member(archive: tarfile.TarFile, name: str, payload: bytes = b"{}\n") -> None:
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    member.mode = 0o600
    archive.addfile(member, io.BytesIO(payload))


def write_artifact(root: Path, relative: str, payload: bytes) -> dict[str, str]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return {"path": relative, "sha256": sha256(payload)}


def build_bundle(root: Path) -> tuple[Path, dict]:
    configuration: dict[str, str] = {}
    for relative, payload in {
        "deploy/compose/core.yml": b"services: {}\n",
        "deploy/compose/isolated-worker.yml": b"services: {}\n",
    }.items():
        write_artifact(root, relative, payload)
        configuration[relative] = sha256(payload)

    account = "1" * 12
    images: dict[str, dict] = {}
    for name in sorted(REQUIRED_IMAGES):
        digest = sha256(name.encode())
        sbom = write_artifact(
            root, f"evidence/sbom/{name}.spdx.json", canonical({"image": name})
        )
        provenance = write_artifact(
            root, f"evidence/provenance/{name}.intoto.json", canonical({"subject": name})
        )
        first_party = name in FIRST_PARTY_IMAGES
        source = (
            {"kind": "built", "revision": EXPECTED_COMMIT}
            if first_party
            else {
                "kind": "mirrored",
                "upstream_uri": f"docker.io/example/{name}@sha256:{sha256((name + '-source').encode())}",
            }
        )
        images[name] = {
            "first_party": first_party,
            "provenance": provenance,
            "sbom": sbom,
            "source": source,
            "uri": (
                f"{account}.dkr.ecr.us-east-1.amazonaws.com/"
                f"freight-broker-pilot-{name}@sha256:{digest}"
            ),
        }

    codeql = write_artifact(
        root, "evidence/security/codeql-evidence.json", canonical({"status": "pass"})
    )
    codeql_bundle = write_artifact(
        root,
        "evidence/security/codeql-evidence.sigstore.json",
        canonical({"verificationMaterial": {}}),
    )
    trivy = write_artifact(
        root, "evidence/security/trivy-evidence.json", canonical({"status": "pass"})
    )
    trivy_bundle = write_artifact(
        root,
        "evidence/security/trivy-evidence.sigstore.json",
        canonical({"verificationMaterial": {}}),
    )
    payload = {
        "configuration": configuration,
        "images": images,
        "kill_switches": {name: False for name in KILL_SWITCHES},
        "migration": {
            "direction": "forward-only",
            "expected_head": "release_control_test_head",
            "owner": "single-core-migration-job",
        },
        "release": {
            "commit_sha": EXPECTED_COMMIT,
            "created_at": "2026-09-10T00:00:00+00:00",
            "platform": "linux/arm64",
            "ref": EXPECTED_REF,
            "repository": EXPECTED_REPOSITORY,
            "workflow_run_attempt": "1",
            "workflow_run_id": "1",
        },
        "rollback": {
            "previous_release_digest": "sha256:" + "b" * 64,
            "schema_downgrade_allowed": False,
            "scope": "application-and-configuration-only",
        },
        "schema_version": 1,
        "security": {
            "ci": {
                "commit_sha": EXPECTED_COMMIT,
                "ref": EXPECTED_REF,
                "run_attempt": "1",
                "run_id": "1",
                "workflow_identity": (
                    f"https://github.com/{EXPECTED_REPOSITORY}/.github/workflows/ci.yml@"
                    f"{EXPECTED_REF}"
                ),
                "workflow_path": ".github/workflows/ci.yml",
            },
            "codeql": {"evidence": codeql, "sigstore_bundle": codeql_bundle},
            "trivy": {"evidence": trivy, "sigstore_bundle": trivy_bundle},
        },
        "signature_policy": {
            "issuer": "https://token.actions.githubusercontent.com",
            "release_workflow": (
                f"https://github.com/{EXPECTED_REPOSITORY}/.github/workflows/release.yml@"
                f"{EXPECTED_REF}"
            ),
        },
    }
    manifest = root / "release-manifest.v1.json"
    manifest.write_bytes(canonical(payload))
    return manifest, payload


def verifier_args(root: Path, manifest: Path) -> argparse.Namespace:
    return argparse.Namespace(
        bundle_root=root,
        manifest=manifest,
        expected_repository=EXPECTED_REPOSITORY,
        expected_ref=EXPECTED_REF,
        expected_commit_sha=EXPECTED_COMMIT,
        expected_platform="linux/arm64",
    )


class ReleaseExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.extractor = load_module("release_extractor", EXTRACTOR_PATH)

    def test_regular_bounded_release_members_extract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "release-bundle.tar"
            with tarfile.open(archive_path, "w") as archive:
                add_tar_member(archive, "release-manifest.v1.json")
                add_tar_member(archive, "deploy/compose/core.yml", b"services: {}\n")
            output = root / "output"

            extracted = self.extractor.extract_archive(archive_path, output)

            self.assertEqual(
                extracted,
                ["deploy/compose/core.yml", "release-manifest.v1.json"],
            )
            self.assertEqual((output / "release-manifest.v1.json").read_bytes(), b"{}\n")

    def test_path_traversal_links_duplicates_and_unknown_paths_are_rejected(self) -> None:
        cases = ("../escape", "/absolute", "unknown/private-source.py")
        for name in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive_path = root / "release-bundle.tar"
                with tarfile.open(archive_path, "w") as archive:
                    add_tar_member(archive, name)
                with self.assertRaises(self.extractor.ExtractionError):
                    self.extractor.extract_archive(archive_path, root / "output")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "release-bundle.tar"
            with tarfile.open(archive_path, "w") as archive:
                member = tarfile.TarInfo("release-manifest.v1.json")
                member.type = tarfile.SYMTYPE
                member.linkname = "../escape"
                archive.addfile(member)
            with self.assertRaises(self.extractor.ExtractionError):
                self.extractor.extract_archive(archive_path, root / "output")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "release-bundle.tar"
            with tarfile.open(archive_path, "w") as archive:
                add_tar_member(archive, "release-manifest.v1.json")
                add_tar_member(archive, "release-manifest.v1.json")
            with self.assertRaises(self.extractor.ExtractionError):
                self.extractor.extract_archive(archive_path, root / "output")


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = load_module("release_verifier", VERIFIER_PATH)

    def test_canonical_manifest_and_bound_artifacts_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, _ = build_bundle(root)

            digest = self.verifier.verify_manifest(verifier_args(root, manifest))

            self.assertEqual(digest, sha256(manifest.read_bytes()))

    def test_identity_mutability_hash_and_policy_attacks_are_rejected(self) -> None:
        mutations = {
            "wrong repository": lambda payload: payload["release"].__setitem__(
                "repository", "example/wrong"
            ),
            "mutable image": lambda payload: payload["images"]["api"].__setitem__(
                "uri", "example.invalid/api:latest"
            ),
            "configuration mismatch": lambda payload: payload["configuration"].__setitem__(
                "deploy/compose/core.yml", "0" * 64
            ),
            "enabled kill switch": lambda payload: payload["kill_switches"].__setitem__(
                "ALLOW_EXTERNAL_WRITES", True
            ),
            "schema downgrade": lambda payload: payload["rollback"].__setitem__(
                "schema_downgrade_allowed", True
            ),
            "unsafe path": lambda payload: payload["configuration"].__setitem__(
                "../outside.yml", "0" * 64
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, payload = build_bundle(root)
                mutate(payload)
                manifest.write_bytes(canonical(payload))
                with self.assertRaises(self.verifier.VerificationError):
                    self.verifier.verify_manifest(verifier_args(root, manifest))

    def test_noncanonical_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, payload = build_bundle(root)
            manifest.write_text(json.dumps(payload, indent=2) + "\n")

            with self.assertRaises(self.verifier.VerificationError):
                self.verifier.verify_manifest(verifier_args(root, manifest))


if __name__ == "__main__":
    unittest.main()
