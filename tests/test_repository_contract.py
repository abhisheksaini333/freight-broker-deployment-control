from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate-repository.py"
DEPLOY_WORKFLOW = ROOT / ".github" / "workflows" / "deploy-pilot.yml"
WAITER = ROOT / "scripts" / "wait-for-ssm-command.sh"
README = ROOT / "README.md"
SECURITY = ROOT / "SECURITY.md"
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def load_validator():
    spec = importlib.util.spec_from_file_location("repository_validator", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("repository validator cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RepositoryValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = load_validator()

    def test_clean_allowlisted_repository_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in self.validator.ALLOWED_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("safe placeholder\n")

            self.assertEqual(self.validator.validate_repository(root), [])

    def test_unexpected_files_and_sensitive_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            (root / "app" / "source.py").write_text("print('private source')\n")
            (root / ".env").write_text("VALUE=redacted\n")

            findings = self.validator.validate_repository(root)

            self.assertIn("unexpected path: .env", findings)
            self.assertIn("unexpected path: app/source.py", findings)

    def test_every_allowlisted_control_file_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("safe placeholder\n")

            findings = self.validator.validate_repository(root)

            self.assertIn("missing required path: SECURITY.md", findings)
            self.assertNotIn("missing required path: README.md", findings)

    def test_sensitive_patterns_are_rejected_without_echoing_values(self) -> None:
        cases = {
            "aws-account": "account = " + "123456" + "789012",
            "instance": "target = i-" + "0123456789abcdef0",
            "private-key": "-----BEGIN " + "PRIVATE KEY-----",
            "secret-assignment": "client_" + "secret = do-not-print-this-value",
            "private-checkout": "git " + "clone https://github.com/example/private-source.git",
            "pull-request-target": "pull_request" + "_target:",
            "unpinned-action": "uses: actions/" + "checkout@v4",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "README.md"
            for label, value in cases.items():
                with self.subTest(label=label):
                    candidate.write_text(value + "\n")
                    findings = self.validator.validate_repository(root)
                    self.assertTrue(findings)
                    self.assertNotIn("do-not-print-this-value", "\n".join(findings))

    def test_binary_and_oversized_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "README.md"
            candidate.write_bytes(b"safe\x00binary")
            self.assertIn("binary file forbidden: README.md", self.validator.validate_repository(root))

            candidate.write_bytes(b"x" * (self.validator.MAX_TEXT_BYTES + 1))
            self.assertIn("oversized file forbidden: README.md", self.validator.validate_repository(root))


class DeploymentWorkflowContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = DEPLOY_WORKFLOW.read_text()
        self.waiter = WAITER.read_text()

    def test_manual_approval_gate_and_minimal_permissions(self) -> None:
        self.assertIn("workflow_dispatch:", self.workflow)
        for name in (
            "source_repository",
            "release_ref",
            "commit_sha",
            "release_uri",
            "manifest_sha256",
            "release_run_id",
            "release_run_attempt",
            "previous_release_digest",
        ):
            self.assertIn(f"      {name}:", self.workflow)
        self.assertIn("environment: pilot", self.workflow)
        self.assertIn("runs-on: ubuntu-latest", self.workflow)
        self.assertIn("contents: read", self.workflow)
        self.assertEqual(self.workflow.count("id-token: write"), 1)
        self.assertIn("cancel-in-progress: false", self.workflow)
        self.assertNotIn("pull_request_target", self.workflow)
        self.assertNotIn("AWS_ACCESS_KEY_ID", self.workflow)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", self.workflow)

    def test_only_environment_secrets_hold_aws_identifiers(self) -> None:
        for name in (
            "AWS_PILOT_APP_DEPLOY_ROLE_ARN",
            "AWS_ACCOUNT_ID",
            "AWS_PILOT_CORE_INSTANCE_ID",
            "AWS_PILOT_ISOLATED_INSTANCE_ID",
            "AWS_PILOT_RDS_INSTANCE_ID",
            "AWS_PILOT_RDS_KMS_KEY_ARN",
        ):
            self.assertIn(f"secrets.{name}", self.workflow)
        self.assertNotIn("vars.AWS_", self.workflow)

    def test_inputs_and_release_are_verified_before_host_or_database_mutation(self) -> None:
        for expression in (
            "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
            "^refs/tags/release-",
            "^[0-9a-f]{40}$",
            "@sha256:[0-9a-f]{64}$",
            "^[0-9a-f]{64}$",
            "^[1-9][0-9]*$",
        ):
            self.assertIn(expression, self.workflow)
        self.assertIn("oras pull", self.workflow)
        self.assertIn("scripts/extract-release-bundle.py", self.workflow)
        self.assertIn("scripts/verify-release-manifest.py", self.workflow)
        self.assertIn("cosign verify", self.workflow)
        self.assertIn(".github/workflows/release.yml@${RELEASE_REF}", self.workflow)
        self.assertIn("--certificate-oidc-issuer https://token.actions.githubusercontent.com", self.workflow)
        verification = self.workflow.index("Verify the release manifest and every image")
        first_mutation = self.workflow.index("aws ssm send-command")
        snapshot = self.workflow.index("aws rds create-db-snapshot")
        self.assertLess(verification, first_mutation)
        self.assertLess(verification, snapshot)

    def test_deployment_is_fixed_order_migrate_once_and_application_only_rollback(self) -> None:
        self.assertIn("--document-name freight-broker-pilot-release", self.workflow)
        self.assertNotIn("AWS-RunShellScript", self.workflow)
        self.assertEqual(self.workflow.count('send_operation "${CORE_INSTANCE_ID}" migrate-forward'), 1)
        core_start = self.workflow.index('send_operation "${CORE_INSTANCE_ID}" start-core')
        core_health = self.workflow.index('send_operation "${CORE_INSTANCE_ID}" health-core')
        isolated_start = self.workflow.index('send_operation "${ISOLATED_INSTANCE_ID}" start-isolated')
        isolated_health = self.workflow.index('send_operation "${ISOLATED_INSTANCE_ID}" health-isolated')
        self.assertLess(core_start, core_health)
        self.assertLess(core_health, isolated_start)
        self.assertLess(isolated_start, isolated_health)
        self.assertIn("rollback-app", self.workflow)
        self.assertNotIn("downgrade", self.workflow.lower())
        self.assertIn("db-snapshot-completed", self.workflow)
        self.assertIn(".Encrypted == true", self.workflow)

    def test_waiter_and_sanitized_evidence_are_bounded(self) -> None:
        self.assertIn("for attempt in $(seq 1 180)", self.waiter)
        self.assertIn("sleep 10", self.waiter)
        self.assertIn("did not complete within 30 minutes", self.waiter)
        self.assertIn("Cancelled|Failed|TimedOut|Undeliverable|Terminated", self.waiter)
        self.assertIn("Retain sanitized deployment evidence", self.workflow)
        self.assertIn("retention-days: 90", self.workflow)
        self.assertNotIn("handoff/release-bundle/evidence/", self.workflow)

    def test_all_actions_are_pinned_to_full_commit_shas(self) -> None:
        import re

        uses = re.findall(r"^\s*uses:\s*([^\s#]+)", self.workflow, flags=re.MULTILINE)
        self.assertTrue(uses)
        for action in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")


class PublicRepositoryPolicyTests(unittest.TestCase):
    def test_readme_explains_boundary_approval_inputs_and_initial_blockers(self) -> None:
        readme = README.read_text()
        for phrase in (
            "contains no application source",
            "private source repository",
            "required reviewer",
            "prevent self-review",
            "No manual bypass",
            "GitHub billing",
            "second named staff identity",
            "no additional software subscription",
        ):
            self.assertIn(phrase, readme)
        for name in (
            "source_repository",
            "release_ref",
            "commit_sha",
            "release_uri",
            "manifest_sha256",
            "release_run_id",
            "release_run_attempt",
            "previous_release_digest",
            "AWS_PILOT_APP_DEPLOY_ROLE_ARN",
            "AWS_ACCOUNT_ID",
            "AWS_PILOT_CORE_INSTANCE_ID",
            "AWS_PILOT_ISOLATED_INSTANCE_ID",
            "AWS_PILOT_RDS_INSTANCE_ID",
            "AWS_PILOT_RDS_KMS_KEY_ARN",
        ):
            self.assertIn(f"`{name}`", readme)

    def test_security_policy_keeps_sensitive_reports_out_of_public_issues(self) -> None:
        security = SECURITY.read_text()
        self.assertIn("Do not open a public issue", security)
        self.assertIn("GitHub private vulnerability reporting", security)
        self.assertNotIn("@gmail.com", security)
        self.assertNotIn("@datavedam", security)

    def test_code_ownership_and_weekly_action_updates_are_enabled(self) -> None:
        self.assertEqual(CODEOWNERS.read_text().strip(), "* @abhisheksaini333")
        dependabot = DEPENDABOT.read_text()
        self.assertIn('package-ecosystem: "github-actions"', dependabot)
        self.assertIn('interval: "weekly"', dependabot)

    def test_ci_revalidates_every_public_byte_without_cloud_credentials(self) -> None:
        ci = CI_WORKFLOW.read_text()
        self.assertIn("python3 -m unittest discover -s tests -v", ci)
        self.assertIn("python3 scripts/validate-repository.py", ci)
        self.assertIn("bash -n scripts/wait-for-ssm-command.sh", ci)
        self.assertNotIn("id-token: write", ci)
        self.assertNotIn("secrets.", ci)


if __name__ == "__main__":
    unittest.main()
