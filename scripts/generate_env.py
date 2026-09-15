"""Generate a private DEPLOY_ENV file using the pinned Xray key generator."""

import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import sys
import uuid

from settings import StackError, domain, dump_env, panel_host, private_write, validate
from stack import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel-host", help="Public IPv4 or DNS name; defaults to --ssh-host")
    parser.add_argument("--ssh-host", required=True)
    parser.add_argument("--ssh-user", required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--mtg-domain", required=True)
    parser.add_argument("--output", type=Path, default=Path(".env"))
    args = parser.parse_args()
    if args.output.exists():
        raise StackError("Output already exists; existing credentials will not be overwritten")
    host = args.panel_host or args.ssh_host
    if not panel_host(host) or not domain(args.mtg_domain):
        raise StackError("Invalid panel address or MTProto masking hostname")
    repository = Path(__file__).resolve().parents[1]
    mtg_secret = "ee" + secrets.token_hex(16) + args.mtg_domain.encode("ascii").hex()
    env = {key: value for key, value in os.environ.items() if not key.startswith("COMPOSE_")}
    env.update(PANEL_HOST=host, MTG_SECRET=mtg_secret)
    model = json.loads(run(["docker", "compose", "--env-file", os.devnull, "-f", str(repository / "compose.yaml"),
                            "config", "--format", "json"], env=env, label="Read Compose defaults"))
    output = run(["docker", "run", "--rm", "--entrypoint", "/bin/sh", model["services"]["xui"]["image"],
                  "-c", 'set -- /app/bin/xray-linux-*; exec "$@" x25519'], label="Generate REALITY keys")
    keys = re.findall(r":\s*([A-Za-z0-9_-]{43})\b", output)
    if len(keys) < 2:
        raise StackError("Unexpected key generator output")
    values = {
        "SSH_HOST": args.ssh_host, "SSH_USER": args.ssh_user,
        "SSH_PRIVATE_KEY_B64": base64.b64encode(args.ssh_key.read_bytes().replace(b"\r\n", b"\n")).decode(),
        "SSH_KNOWN_HOSTS_B64": base64.b64encode(args.known_hosts.read_bytes()).decode(),
        "PANEL_HOST": host,
        "INITIAL_PANEL_USERNAME": model["x-bootstrap"]["admin-username"],
        "INITIAL_PANEL_PASSWORD": secrets.token_urlsafe(24),
        "INITIAL_VLESS_UUID": str(uuid.uuid4()),
        "INITIAL_REALITY_PRIVATE_KEY": keys[0], "INITIAL_REALITY_PUBLIC_KEY": keys[1],
        "INITIAL_REALITY_SHORT_ID": secrets.token_hex(8), "MTG_SECRET": mtg_secret,
    }
    validate(values, ssh=True)
    private_write(args.output, dump_env(values))
    print("Private .env created. Upload its contents as the single Actions secret DEPLOY_ENV.")


if __name__ == "__main__":
    try:
        main()
    except (StackError, OSError) as error:
        print(str(error) if isinstance(error, StackError) else "Cannot read or write a credentials file.", file=sys.stderr)
        sys.exit(1)
