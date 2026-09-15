"""Send a release over verified SSH using the single DEPLOY_ENV Actions secret."""

import base64
import io
import os
from pathlib import Path
import re
import shlex
import sys
import tarfile
import tempfile

from settings import APP_FIELDS, StackError, decode64, dump_env, mask, parse_env, private_write, validate
from stack import run


def root_command(command):
    quoted = shlex.quote(command)
    return f'if [ "$(id -u)" -eq 0 ]; then bash -c {quoted}; else sudo -n bash -c {quoted}; fi'


def package(repository, values):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        files = [repository / "compose.yaml", *sorted((repository / "scripts").glob("*.py"))]
        for path in files:
            archive.add(path, arcname=path.relative_to(repository).as_posix(), recursive=False)
        data = dump_env({key: values[key] for key in APP_FIELDS}).encode()
        member = tarfile.TarInfo(".env")
        member.size, member.mode = len(data), 0o600
        archive.addfile(member, io.BytesIO(data))
    return base64.b64encode(buffer.getvalue()).decode()


def main():
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise StackError("Deployment is restricted to main")
    values = parse_env(os.environ.get("DEPLOY_ENV", ""))
    mask(values.values())
    validate(values, ssh=True)
    revision, run_id, attempt = (os.environ.get(key, "") for key in
                               ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or not run_id.isdigit() or not attempt.isdigit():
        raise StackError("Invalid GitHub deployment identifiers")
    name = f"{revision}-{run_id}-{attempt}"
    repository = Path(__file__).resolve().parent.parent
    remote = f"/opt/network-stack/releases/{name}"
    with tempfile.TemporaryDirectory(prefix="network-stack-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        key = decode64(values["SSH_PRIVATE_KEY_B64"], "SSH_PRIVATE_KEY_B64")
        known = decode64(values["SSH_KNOWN_HOSTS_B64"], "SSH_KNOWN_HOSTS_B64")
        mask([key.decode("utf-8"), known.decode("utf-8")])
        private_write(directory / "key", key)
        private_write(directory / "known_hosts", known)
        clean_env = {k: v for k, v in os.environ.items() if k != "DEPLOY_ENV"}
        run(["ssh-keygen", "-y", "-P", "", "-f", str(directory / "key")],
            env=clean_env, label="Validate SSH private key")
        run(["ssh-keygen", "-F", values["SSH_HOST"], "-f", str(directory / "known_hosts")],
            env=clean_env, label="Find pinned SSH host key")
        ssh = ["ssh", "-T", "-p", "22", "-i", str(directory / "key"),
               "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", f"UserKnownHostsFile={directory / 'known_hosts'}", "-o", "GlobalKnownHostsFile=/dev/null",
               "-o", "ConnectTimeout=15", "-o", "ConnectionAttempts=1",
               "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
               f"{values['SSH_USER']}@{values['SSH_HOST']}"]
        # Do not pass DEPLOY_ENV or the SSH key to child-process environments.
        print("Preparing Ubuntu host.", flush=True)
        run(ssh + [root_command("bash -s")], data=(repository / "scripts/bootstrap-host.sh").read_text(),
            env=clean_env, label="Ubuntu bootstrap over SSH", timeout=900)
        print("Uploading release over verified SSH.", flush=True)
        receive = f"set -euo pipefail; umask 077; mkdir {remote}; base64 --decode | tar -xz -C {remote}"
        run(ssh + [root_command(receive)], data=package(repository, values), env=clean_env,
            label="Upload release", timeout=120)
        # systemd owns the operation: loss of the SSH session does not kill the deployment.
        command = (f"systemd-run --quiet --wait --collect --unit=network-stack-deploy-{name} "
                   "--property=RuntimeMaxSec=900 --property=TimeoutStopSec=180 "
                   f"python3 {remote}/scripts/deploy.py apply --release {name}")
        print("Applying release on the server.", flush=True)
        run(ssh + [root_command(command)], env=clean_env, label="Server deployment", timeout=1100)
        print("Deployment completed. Connection credentials are available in the panel.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except StackError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("Delivery failed unexpectedly; sensitive details were suppressed.", file=sys.stderr)
        sys.exit(1)
