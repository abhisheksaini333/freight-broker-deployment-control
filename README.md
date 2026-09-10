# Freight Broker Deployment Control

This public repository is the minimal approval and deployment control plane for the controlled
freight-broker pilot. It contains no application source, customer data, credentials, infrastructure
state, cloud identifiers, or vendor configuration. The application and signed-release publisher
remain in the private source repository.

## Why This Repository Is Public

The private repository stays private. This separate public control plane makes GitHub's protected
environment reviewer control available without purchasing a private-repository plan upgrade, so it
adds no additional software subscription. Ordinary private Actions usage and AWS resource costs
remain separate. GitHub billing must still be resolved before the private repository can create a
qualifying signed release.

## Approval And Deployment Sequence

1. Private CI qualifies an exact release-tag commit, publishes digest-pinned images and a canonical
   release bundle to private ECR, and signs them using GitHub OIDC.
2. Staff review the immutable identifiers out of band and manually dispatch this repository's
   `Deploy signed pilot release` workflow.
3. The `pilot` environment requires a required reviewer and is configured to prevent self-review.
4. After approval, GitHub issues a short-lived OIDC credential. The workflow verifies the AWS
   account, release signature, manifest, every image, and the previous release before any host or
   database mutation.
5. The fixed SSM release document stages both hosts, takes an encrypted snapshot, migrates exactly
   once, starts core before isolated, and gates both health checks. Failure triggers application-only
   rollback; ambiguous recovery fails loudly.

Initially the repository owner's review requirement deliberately leaves deployment blocked when the
owner also initiates the run. A second named staff identity with write access must initiate the run
before the owner can approve it. Shared or alternate accounts are forbidden. No manual bypass of
the protected environment, signed release, fixed SSM document, snapshot, or health gates is allowed.

## Dispatch Inputs

All values identify one already-published immutable release:

- `source_repository`: exact private owner/repository name.
- `release_ref`: exact `refs/tags/release-*` tag.
- `commit_sha`: exact 40-character source commit.
- `release_uri`: exact private ECR release URI with a `sha256` digest.
- `manifest_sha256`: SHA-256 reviewed out of band.
- `release_run_id`: successful private signed-release workflow run ID.
- `release_run_attempt`: positive attempt number for that run.
- `previous_release_digest`: prior signed bundle digest, blank only for the first deployment.

AWS identifiers are never dispatch inputs or repository variables. The protected `pilot` environment
must eventually contain these environment secrets:

- `AWS_PILOT_APP_DEPLOY_ROLE_ARN`
- `AWS_ACCOUNT_ID`
- `AWS_PILOT_CORE_INSTANCE_ID`
- `AWS_PILOT_ISOLATED_INSTANCE_ID`
- `AWS_PILOT_RDS_INSTANCE_ID`
- `AWS_PILOT_RDS_KMS_KEY_ARN`

They are intentionally absent until the approved AWS foundation has been applied and independently
verified. Do not add long-lived AWS access keys.

## Local Verification

```bash
python3 -m unittest discover -s tests -v
python3 scripts/validate-repository.py
bash -n scripts/wait-for-ssm-command.sh
```

The validator fail-closes on any non-allowlisted, binary, oversized, sensitive-looking, or unpinned
content. The tests exercise unsafe release archives and manifest-policy attacks without cloud access.

## Current Activation Blockers

- GitHub billing must permit the private CI and release workflows to obtain runners.
- The AWS account and pilot foundation must be approved, applied, and verified.
- The six `pilot` environment secrets must be populated from that verified foundation.
- Two distinct named staff identities are required for initiator/reviewer separation.

Until all blockers are cleared, this repository is a locally and structurally verified control plane,
not proof of a live deployment.
