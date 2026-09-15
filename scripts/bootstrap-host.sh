#!/usr/bin/env bash
set -euo pipefail
umask 077

test "$(id -u)" -eq 0 || { echo 'Bootstrap requires root or passwordless sudo.' >&2; exit 1; }
# Host-provided metadata is unavailable to the repository linter.
# shellcheck source=/dev/null
. /etc/os-release
case "$ID:$VERSION_ID" in
  ubuntu:24.04) docker_suite=noble ;;
  ubuntu:26.04) docker_suite=resolute ;;
  *) echo 'Supported host: Ubuntu 24.04 or 26.04 LTS.' >&2; exit 1 ;;
esac
exec 9>/run/lock/network-stack-bootstrap.lock
flock -w 600 9
export DEBIAN_FRONTEND=noninteractive
if ! command -v python3 >/dev/null || ! command -v curl >/dev/null; then
  apt-get update -qq
  apt-get install -y --no-install-recommends python3 ca-certificates curl
fi
need_engine=false
need_compose=false
command -v docker >/dev/null || need_engine=true
docker compose version >/dev/null 2>&1 || need_compose=true
if [[ "$need_engine" == true || "$need_compose" == true ]]; then
  # Fail on another container runtime instead of removing somebody else's packages.
  if [[ "$need_engine" == true ]]; then
    for package in docker.io podman-docker containerd runc; do
      if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed'; then
        echo 'Conflicting container packages exist; review the host installation.' >&2
        exit 1
      fi
    done
  fi
  install -m 0755 -d /etc/apt/keyrings
  curl --fail --silent --show-error --connect-timeout 15 --max-time 60 \
    https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod 0644 /etc/apt/keyrings/docker.asc
  cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $docker_suite
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
  apt-get update -qq
  if [[ "$need_engine" == true ]]; then
    apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
  else
    apt-get install -y --no-install-recommends docker-compose-plugin
  fi
fi
docker info >/dev/null
version="$(docker compose version --short)"
python3 - "$version" <<'PY'
import re, sys
parts = re.match(r'v?(\d+)\.(\d+)\.(\d+)', sys.argv[1])
if not parts or tuple(map(int, parts.groups())) < (2, 23, 1):
    sys.exit('Docker Compose >= 2.23.1 is required; upgrade the existing installation explicitly.')
PY
install -d -m 0700 /opt/network-stack /opt/network-stack/releases /opt/network-stack/state /opt/network-stack/backups
echo 'Host prerequisites verified.'
