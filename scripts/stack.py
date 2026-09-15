"""Compose operations shared by deployment and integration tests."""

import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
import urllib.request

from panel import Panel, ensure_inbound, initial_inbound
from mtg_diagnostics import check_mtg_diagnostics
from settings import APP_FIELDS, SSH_FIELDS, StackError, private_write, read_env


def run(argv, *, label, cwd=None, env=None, data=None, timeout=300, allowed_codes=(0,)):
    try:
        # Binary pipes preserve LF and literal secrets on Windows as well as Linux.
        result = subprocess.run(argv, cwd=cwd, env=env, input=None if data is None else data.encode("utf-8"),
                                capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise StackError(f"{label}: could not complete within the time limit") from None
    if result.returncode not in allowed_codes:
        # Upstream CLI errors can contain credentials or an entire config.
        raise StackError(f"{label}: command failed (exit {result.returncode}); output suppressed")
    return result.stdout.decode("utf-8", errors="replace")


def wait_for(check, label, timeout=90):
    deadline = time.monotonic() + timeout
    while True:
        try:
            check()
            return
        except (StackError, OSError, ValueError):
            if time.monotonic() >= deadline:
                raise StackError(f"{label}: readiness deadline exceeded") from None
            time.sleep(2)


class Stack:
    def __init__(self, release, state, project="network-stack", env_file=None, override=None):
        self.release, self.state = Path(release).resolve(), Path(state).resolve()
        self.env_file = Path(env_file or self.release / ".env").resolve()
        self.values = read_env(self.env_file)
        self.env = {k: v for k, v in os.environ.items()
                    if k not in APP_FIELDS | SSH_FIELDS and not k.startswith("COMPOSE_")}
        self.env.update({k: self.values[k] for k in ("PANEL_HOST", "MTG_SECRET")})
        self.env["STACK_STATE_DIR"] = str(self.state)
        self.runtime = self.env_file.parent / ".runtime"
        self.env["STACK_RUNTIME_DIR"] = str(self.runtime)
        self.argv = ["docker", "compose", "--project-name", project, "--env-file", str(self.env_file),
                     "-f", str(self.release / "compose.yaml")]
        if override:
            self.argv += ["-f", str(Path(override).resolve())]
        self.model = json.loads(self.command("config", "--format", "json", label="Resolve Compose"))

    def command(self, *args, label="Compose", data=None, timeout=300, allowed_codes=(0,)):
        return run(self.argv + list(args), cwd=self.release, env=self.env,
                   label=label, data=data, timeout=timeout, allowed_codes=allowed_codes)

    def prepare_directories(self):
        for directory in (self.state, self.state / "xui", self.state / "caddy-data", self.state / "caddy-config"):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.chmod(0o700)
        config = self.runtime / "mtg.toml"
        private_write(config, self.model["x-mtg-config"])
        self.runtime.chmod(0o700)
        if os.name == "posix":
            # The bind-mounted file must be readable by the unprivileged mtg process.
            os.chown(config, 65532, 65532)

    def preflight(self):
        self.command("pull", label="Pull pinned images", timeout=420)
        self.command("run", "--rm", "--no-deps", "-T", "caddy", "caddy", "validate",
                     "--config", "/etc/caddy/Caddyfile", label="Validate Caddy")
        report = self.command("run", "--rm", "--no-deps", "-T", "mtg", "doctor", "/config.toml",
                              label="Validate MTProto connectivity", timeout=90, allowed_codes=(0, 1))
        check_mtg_diagnostics(report)

    def panel_ready(self):
        url = self.model["x-bootstrap"]["panel-url"] + "/"
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=4) as response:
            if response.status != 200:
                raise StackError("Panel is not ready")

    def bootstrap(self):
        marker = self.state / "xui" / "bootstrap-complete.json"
        if marker.exists():
            return
        defaults = self.model["x-bootstrap"]
        # No public reverse proxy is started until credentials are verified.
        self.command("stop", "caddy", "xui", label="Close panel for initialization")
        script = ('umask 077; IFS= read -r username; IFS= read -r password; '
                  'exec /app/x-ui setting -username "$username" -password "$password" '
                  '-port "$1" -webBasePath "$2"')
        self.command("run", "--rm", "--no-deps", "-T", "--entrypoint", "/bin/sh", "xui",
                     "-c", script, "bootstrap", str(defaults["panel-port"]), defaults["panel-base-path"],
                     data=self.values["INITIAL_PANEL_USERNAME"] + "\n" + self.values["INITIAL_PANEL_PASSWORD"] + "\n",
                     label="Initialize panel credentials")
        self.command("up", "-d", "--no-deps", "xui", label="Start private panel")
        wait_for(self.panel_ready, "Panel startup")
        # Verify the public/private key pair using Xray itself, not custom crypto.
        output = self.command("exec", "-T", "xui", "/bin/sh", "-c",
                              'IFS= read -r key; set -- /app/bin/xray-linux-*; exec "$@" x25519 -i "$key"',
                              data=self.values["INITIAL_REALITY_PRIVATE_KEY"] + "\n", label="Verify REALITY key pair")
        if self.values["INITIAL_REALITY_PUBLIC_KEY"] not in output.split():
            raise StackError("INITIAL_REALITY_PUBLIC_KEY does not match the private key")
        panel = Panel(defaults["panel-url"])
        panel.login(self.values["INITIAL_PANEL_USERNAME"], self.values["INITIAL_PANEL_PASSWORD"])
        ensure_inbound(panel, initial_inbound(defaults, self.values))
        panel.request("/panel/api/server/restartXrayService", {})
        panel.logout()
        wait_for(self.xray_ready, "Initial Xray startup")
        temporary = marker.with_suffix(".tmp")
        private_write(temporary, '{"version":1}\n')
        temporary.replace(marker)

    def xray_ready(self):
        self.command("exec", "-T", "xui", "/bin/sh", "-c",
                     'set -- /app/bin/xray-linux-*; "$@" run -test -config /app/bin/config.json >/dev/null 2>&1 '
                     '&& pgrep -f "(^|/)xray-linux-[a-z0-9]+ -c " >/dev/null',
                     label="Validate running Xray", timeout=15)

    def services_ready(self):
        wait_for(self.panel_ready, "Panel startup")
        wait_for(self.xray_ready, "Xray startup")
        ident = self.command("ps", "--all", "--quiet", "mtg", label="Find MTProto container").strip()
        if not ident:
            raise StackError("MTProto container is missing")
        state = json.loads(run(["docker", "inspect", "--format", "{{json .State}}", ident], label="MTProto state"))
        if not state["Running"] or state.get("OOMKilled"):
            raise StackError("MTProto is not running")

    def https_ready(self):
        # Local connection avoids VPS NAT hairpin issues; SNI and CA checks stay enabled.
        ports = self.model["services"]["caddy"]["ports"]
        port = next(int(p["published"]) for p in ports if p["target"] == 9443)
        host = self.values["PANEL_HOST"]
        with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
            with ssl.create_default_context().wrap_socket(connection, server_hostname=host) as tls:
                tls.sendall(f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode())
                if b" 200 " not in tls.recv(1024).split(b"\r\n", 1)[0]:
                    raise StackError("HTTPS panel did not return its login page")

    def start(self):
        self.command("up", "-d", "--no-deps", "xui", "mtg", label="Start VPN and MTProto")
        self.services_ready()
        self.command("up", "-d", "caddy", label="Open HTTPS panel")
        wait_for(self.https_ready, "Trusted HTTPS certificate", timeout=180)
