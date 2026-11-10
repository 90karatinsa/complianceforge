#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/dr-drill.sh [options]

Options:
  --env <environment>           Target environment label (default: staging)
  --namespace <namespace>       Kubernetes namespace for the DR rehearsal (default: oss-platform-dr)
  --backup-uri <s3://bucket/key>
                                Source object containing the latest PostgreSQL backup (default: s3://oss-compliance-backups/latest.dump)
  --dry-run                     Print the actions without executing them
  --help                        Show this help message

Environment variables:
  DR_DATABASE_URL               PostgreSQL connection string for the staging/DR database (required)
  DR_KUBECONFIG_CONTEXT         kubectl context used to access the staging/DR cluster (required)
  DR_REDIS_URL                  Redis connection string used by perf smoke tests (optional, passed through)
USAGE
}

ENVIRONMENT="staging"
NAMESPACE="oss-platform-dr"
BACKUP_URI="s3://oss-compliance-backups/latest.dump"
DRY_RUN=false

while (($# > 0)); do
  case "$1" in
    --env)
      shift
      ENVIRONMENT="${1:-}"
      [[ -n "$ENVIRONMENT" ]] || { echo "--env requires a non-empty value" >&2; exit 1; }
      ;;
    --env=*)
      ENVIRONMENT="${1#*=}"
      [[ -n "$ENVIRONMENT" ]] || { echo "--env requires a non-empty value" >&2; exit 1; }
      ;;
    --namespace)
      shift
      NAMESPACE="${1:-}"
      [[ -n "$NAMESPACE" ]] || { echo "--namespace requires a non-empty value" >&2; exit 1; }
      ;;
    --namespace=*)
      NAMESPACE="${1#*=}"
      [[ -n "$NAMESPACE" ]] || { echo "--namespace requires a non-empty value" >&2; exit 1; }
      ;;
    --backup-uri)
      shift
      BACKUP_URI="${1:-}"
      [[ -n "$BACKUP_URI" ]] || { echo "--backup-uri requires a non-empty value" >&2; exit 1; }
      ;;
    --backup-uri=*)
      BACKUP_URI="${1#*=}"
      [[ -n "$BACKUP_URI" ]] || { echo "--backup-uri requires a non-empty value" >&2; exit 1; }
      ;;
    --dry-run)
      DRY_RUN=true
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

[[ -n "${DR_DATABASE_URL:-}" ]] || { echo "DR_DATABASE_URL must be set" >&2; exit 1; }
[[ -n "${DR_KUBECONFIG_CONTEXT:-}" ]] || { echo "DR_KUBECONFIG_CONTEXT must be set" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Required command not found: $1" >&2; exit 1; }
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT
BACKUP_PATH="${WORK_DIR}/database.dump"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

if [[ "$DRY_RUN" == true ]]; then
  for tool in aws pg_restore kubectl npm; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      log "DRY-RUN skipping availability check for missing command: $tool"
    fi
  done
else
  require_cmd aws
  require_cmd pg_restore
  require_cmd kubectl
  require_cmd npm
fi

run_cmd() {
  if [[ "$DRY_RUN" == true ]]; then
    log "DRY-RUN $*"
  else
    log "RUN $*"
    "$@"
  fi
}

log "Starting DR drill for environment=${ENVIRONMENT} namespace=${NAMESPACE}"
if [[ "$DRY_RUN" == true ]]; then
  log "Dry-run mode enabled; commands will not execute."
fi

log "Downloading latest backup from ${BACKUP_URI}"
run_cmd aws s3 cp "${BACKUP_URI}" "${BACKUP_PATH}"

log "Restoring backup to ${DR_DATABASE_URL}"
run_cmd pg_restore --clean --if-exists --no-owner --dbname="${DR_DATABASE_URL}" "${BACKUP_PATH}"

log "Applying Kubernetes manifests"
run_cmd kubectl --context "${DR_KUBECONFIG_CONTEXT}" apply -f - <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: ${NAMESPACE}
YAML
run_cmd kubectl --context "${DR_KUBECONFIG_CONTEXT}" apply -n "${NAMESPACE}" -f "${ROOT_DIR}/deploy/k8s/api.yaml"
run_cmd kubectl --context "${DR_KUBECONFIG_CONTEXT}" apply -n "${NAMESPACE}" -f "${ROOT_DIR}/deploy/k8s/worker.yaml"

log "Waiting for deployments to become ready"
run_cmd kubectl --context "${DR_KUBECONFIG_CONTEXT}" rollout status deployment/oss-licensing-api -n "${NAMESPACE}" --timeout=5m
run_cmd kubectl --context "${DR_KUBECONFIG_CONTEXT}" rollout status deployment/oss-licensing-worker -n "${NAMESPACE}" --timeout=5m

log "Executing post-restore smoke and performance checks"
if [[ -n "${DR_REDIS_URL:-}" ]]; then
  export REDIS_URL="${DR_REDIS_URL}"
fi
run_cmd npm run perf:test

log "DR drill completed successfully"
