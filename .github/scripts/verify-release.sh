#!/usr/bin/env bash
# Post-publication smoke check, not an OIDC integration suite. Native Linux only.
set -euo pipefail

image=${1:?usage: verify-release.sh ghcr.io/renevo/localoidc:TAG}
port=18083
container="localoidc-release-smoke-$$"
work=$(mktemp -d)

cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        timeout 5s docker logs "$container" >&2 || true
    fi
    timeout 10s docker rm -f "$container" >/dev/null 2>&1 || true
    rm -f "$work/manifest.json" "$work/discovery.json"
    rmdir "$work"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

test "$(uname -s)/$(uname -m)" = Linux/x86_64
if [ -n "$(ss -H -ltn "sport = :$port")" ]; then
    echo "Smoke-check port $port is already in use" >&2
    exit 1
fi

# .Manifest includes the index's own digest; --raw JSON does not.
timeout 30s docker buildx imagetools inspect "$image" --format '{{json .Manifest}}' > "$work/manifest.json"
digest=$(jq -er '
    if (.digest | test("^sha256:[0-9a-f]{64}$")) and
       ([.manifests[] |
         select(.annotations["vnd.docker.reference.type"] != "attestation-manifest") |
         "\(.platform.os)/\(.platform.architecture)"] | sort == ["linux/amd64", "linux/arm64"])
    then .digest
    else error("expected a digest and executable linux/amd64 + linux/arm64 manifests")
    end
' "$work/manifest.json")
immutable="${image%:*}@${digest}"
echo "Verifying $immutable"
timeout 60s docker pull --platform linux/amd64 "$immutable"
test "$(timeout 5s docker image inspect --format '{{.Config.User}}' "$immutable")" = 65532:65532

timeout 15s docker run -d --name "$container" --platform linux/amd64 \
    --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
    -e "HTTP_PORT=$port" "$immutable" >/dev/null

ready=false
for attempt in $(seq 1 30); do
    test "$(timeout 5s docker inspect --format '{{.State.Running}}' "$container")" = true
    if curl --silent --fail --noproxy '*' --max-time 1 \
        "http://127.0.0.1:$port/.well-known/openid-configuration" > "$work/discovery.json"; then
        ready=true
        break
    fi
    sleep 1
done
test "$ready" = true
jq -e --arg issuer "http://127.0.0.1:$port" '.issuer == $issuer' "$work/discovery.json"

# ss includes both address families. Reject wildcard, IPv6, or extra listeners.
addresses=$(ss -H -ltn "sport = :$port" | awk '{print $4}')
test "$addresses" = "127.0.0.1:$port"
echo "Published index platforms and immutable amd64 loopback smoke check passed"
