#!/usr/bin/env bash
set -euo pipefail

command_id="${1:?command ID is required}"
instance_id="${2:?instance ID is required}"
evidence_path="${3:-}"

for attempt in $(seq 1 180); do
  if invocation="$(aws ssm get-command-invocation \
    --command-id "${command_id}" \
    --instance-id "${instance_id}" \
    --query '{Status:Status,Output:StandardOutputContent,Error:StandardErrorContent}' \
    --output json 2>/dev/null)"; then
    status="$(jq -er '.Status' <<< "${invocation}")"
    case "${status}" in
      Success)
        if [[ -n "${evidence_path}" ]]; then
          printf '%s\n' "${invocation}" > "${evidence_path}"
        fi
        jq -r '.Output' <<< "${invocation}"
        exit 0
        ;;
      Cancelled|Failed|TimedOut|Undeliverable|Terminated)
        jq -r '.Error // empty' <<< "${invocation}" >&2
        printf 'SSM command %s reached terminal status %s\n' "${command_id}" "${status}" >&2
        exit 1
        ;;
      Pending|InProgress|Delayed) ;;
      *)
        printf 'SSM command %s returned unknown status %s\n' "${command_id}" "${status}" >&2
        exit 1
        ;;
    esac
  fi
  if [[ "${attempt}" -lt 180 ]]; then
    sleep 10
  fi
done

printf 'SSM command %s did not complete within 30 minutes\n' "${command_id}" >&2
exit 1
