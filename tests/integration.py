"""Real containers, isolated ports/state, disposable credentials and a private test CA."""

import base64
from contextlib import redirect_stdout
import hashlib
import hmac
import http.client
import io
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import sys
import tempfile
import time
import uuid
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from panel import Panel
from settings import StackError, dump_env, private_write
from stack import Stack, run, wait_for
from test_contracts import sample_values


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def totp(secret):
    digest = hmac.new(base64.b32decode(secret), struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000:06d}"


def client_request(stack, link, good=True):
    address = urlsplit(link)
    params = parse_qs(address.query)
    assert address.hostname == stack.values["PANEL_HOST"] and address.port == 443, "Share-link endpoint"
    assert params.get("type") == ["tcp"], "Share link must use the client-compatible TCP transport"
    assert params.get("flow") == ["xtls-rprx-vision"], "Share link must include Vision"
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks", "settings": {"auth": "noauth"}}],
        # Only the public IP is replaced by the service name inside the isolated Docker network.
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "xui", "port": address.port,
            "users": [{"id": address.username if good else str(uuid.uuid4()),
                       "encryption": params["encryption"][0], "flow": params["flow"][0]}]}]},
            "streamSettings": {"network": params["type"][0], "security": params["security"][0], "realitySettings": {
                "serverName": params["sni"][0], "fingerprint": params["fp"][0],
                "password": params["pbk"][0], "shortId": params["sid"][0]}}}],
    }
    script = ('cat > /tmp/client.json; set -- /app/bin/xray-linux-*; '
              '"$@" run -config /tmp/client.json >/dev/null 2>&1 & pid=$!; '
              'trap \'kill "$pid" 2>/dev/null || true\' EXIT; sleep 2; '
              'curl --silent --fail --max-time 15 --socks5-hostname 127.0.0.1:1080 '
              'https://example.com/ >/dev/null')
    stack.command("run", "--rm", "--no-deps", "-T", "--entrypoint", "/bin/sh", "xui", "-c", script,
                  data=json.dumps(config), label="VLESS end-to-end request", timeout=30)


def sing_box_request(stack, link, config_path, good=True):
    address = urlsplit(link)
    params = parse_qs(address.query)
    config = {
        "log": {"disabled": True},
        "inbounds": [{"type": "socks", "listen": "0.0.0.0", "listen_port": 1080}],
        "outbounds": [{"type": "vless", "server": "xui", "server_port": address.port,
            "uuid": address.username if good else str(uuid.uuid4()), "flow": params["flow"][0],
            "tls": {"enabled": True, "server_name": params["sni"][0],
                "utls": {"enabled": True, "fingerprint": params["fp"][0]},
                "reality": {"enabled": True, "public_key": params["pbk"][0],
                            "short_id": params["sid"][0]}}}],
    }
    private_write(config_path, json.dumps(config))
    try:
        stack.command("up", "-d", "singbox", label="Start sing-box test client")
        time.sleep(2)
        stack.command("exec", "-T", "xui", "curl", "--silent", "--fail", "--max-time", "15",
                      "--socks5-hostname", "singbox:1080", "--output", "/dev/null", "https://example.com/",
                      label="sing-box VLESS end-to-end request", timeout=25)
    finally:
        stack.command("rm", "--stop", "--force", "singbox", label="Stop sing-box test client")


def main():
    repository = Path(__file__).resolve().parents[1]
    work = repository / ".work"
    work.mkdir(exist_ok=True)
    project = "network-stack-test-" + uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix="integration-", dir=work) as temporary:
        directory = Path(temporary)
        ports = [free_port() for _ in range(4)]
        panel_port, vpn_port, mtg_port, https_port = ports
        env_file, override = directory / ".env", directory / "override.yaml"
        singbox_config = directory / "singbox.json"
        values = sample_values()
        private_write(env_file, dump_env(values))
        production = Stack(repository, directory / "state", project, env_file)
        # Exercise production routes; replace only the certificate issuer for isolation.
        test_caddy, issuer_count = re.subn(r"(?m)^(\s*)tls \{\n[\s\S]*?^\1\}", r"\1tls internal",
                                         production.model["configs"]["caddy"]["content"])
        assert issuer_count == 1, "Expected one production TLS issuer"
        bootstrap_defaults = production.model["x-bootstrap"] | {
            "panel-url": f"http://127.0.0.1:{panel_port}",
            "subscription-url": f"https://{values['PANEL_HOST']}:{https_port}/subscription"}
        override.write_text(f'''services:
  xui:
    ports: !override ["127.0.0.1:{vpn_port}:443", "127.0.0.1:{panel_port}:2053"]
  mtg:
    ports: !override ["127.0.0.1:{mtg_port}:3128"]
    # Public-IP discovery is optional; the real connectivity checks must still pass.
    extra_hosts: ["ifconfig.co=127.0.0.1", "ifconfig.co=::1"]
  caddy:
    ports: !override ["127.0.0.1:{https_port}:9443"]
  singbox:
    image: ghcr.io/sagernet/sing-box:v1.14.0@sha256:4bed9332a0013fef72c31200a84e8fc0ed91a5ab2fe373a69f0acbbbbfbef3c5
    profiles: [test]
    command: [run, -c, /etc/sing-box/config.json]
    volumes:
      - type: bind
        source: {json.dumps(str(singbox_config))}
        target: /etc/sing-box/config.json
        read_only: true
x-bootstrap: {json.dumps(bootstrap_defaults)}
configs:
  caddy:
    content: {json.dumps(test_caddy)}
''', encoding="utf-8")
        stack = Stack(repository, directory / "state", project, env_file, override)
        try:
            stack.prepare_directories()
            if os.name == "posix":
                info = (stack.runtime / "mtg.toml").stat()
                assert info.st_mode & 0o777 == 0o600 and info.st_uid == 65532, "MTProto config permissions"
            print("Validate production Caddy config, then test with an isolated CA.", flush=True)
            production.command("run", "--rm", "--no-deps", "-T", "caddy", "caddy", "validate",
                               "--config", "/etc/caddy/Caddyfile", label="Production Caddy config")
            print("Generate disposable REALITY keys and validate Compose.", flush=True)
            output = stack.command("run", "--rm", "--no-deps", "-T", "--entrypoint", "/bin/sh", "xui", "-c",
                                   'set -- /app/bin/xray-linux-*; exec "$@" x25519', label="Generate test keys")
            keys = re.findall(r":\s*([A-Za-z0-9_-]{43})\b", output)
            if len(keys) < 2:
                raise StackError("Unexpected Xray key generation output")
            values.update(INITIAL_REALITY_PRIVATE_KEY=keys[0], INITIAL_REALITY_PUBLIC_KEY=keys[1])
            private_write(env_file, dump_env(values))
            stack = Stack(repository, stack.state, project, env_file, override)
            with redirect_stdout(io.StringIO()) as diagnostics:
                stack.preflight()
            print(diagnostics.getvalue(), end="", flush=True)
            assert "public IP lookup unavailable" in diagnostics.getvalue(), "IP discovery failure was not exercised"
            print("Bootstrap twice: no duplicates, initial credentials work.", flush=True)
            stack.bootstrap()
            stack.command("exec", "-T", "xui", "/bin/sh", "-c",
                          'test "$(stat -c %a /etc/x-ui/x-ui.db)" = 600 '
                          '&& test "$(stat -c %a /app/bin/config.json)" = 600',
                          label="Private panel database and Xray config")
            # Exercise resumption after the API POST but before the completion marker.
            (stack.state / "xui/bootstrap-complete.json").unlink()
            stack.bootstrap()
            stack.command("up", "-d", "mtg", "caddy", label="Start remaining test services")
            stack.services_ready()
            def certificate_present():
                if not (stack.state / "caddy-data/caddy/pki/authorities/local/root.crt").exists():
                    raise StackError("Test CA not ready")
            wait_for(certificate_present, "Test CA")
            context = ssl.create_default_context(cafile=str(stack.state / "caddy-data/caddy/pki/authorities/local/root.crt"))
            with patch("stack.ssl.create_default_context", return_value=context):
                wait_for(stack.https_ready, "TLS panel with trusted test CA")
            panel = Panel(stack.model["x-bootstrap"]["panel-url"])
            panel.login(values["INITIAL_PANEL_USERNAME"], values["INITIAL_PANEL_PASSWORD"])
            links = panel.request("/panel/api/inbounds/allLinks")
            assert len(links) == 1 and links[0].startswith("vless://"), "Expected one VLESS share link"
            subscription_settings = panel.request("/panel/api/setting/all", {})
            subscription_id = values["INITIAL_VLESS_UUID"].replace("-", "")
            subscription_url = subscription_settings["subURI"] + subscription_id
            subscription = urlsplit(subscription_url)
            assert subscription.scheme == "https" and subscription.port == https_port, "HTTPS subscription URL"
            assert subscription.path.startswith("/subscription/"), "Subscription proxy path"
            # Connect locally while verifying the same IP certificate as a public subscriber.
            def fetch_subscription(path):
                with socket.create_connection(("127.0.0.1", https_port), timeout=5) as connection:
                    with context.wrap_socket(connection, server_hostname=values["PANEL_HOST"]) as tls:
                        tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {values['PANEL_HOST']}:{https_port}\r\n"
                                    "Accept: text/plain\r\nConnection: close\r\n\r\n".encode())
                        response = http.client.HTTPResponse(tls)
                        response.begin()
                        return response.status, response.read(4 * 1024 * 1024)
            status, body = fetch_subscription(subscription.path)
            assert status == 200, "HTTPS subscription is unavailable"
            exported_links = base64.b64decode(body).decode().splitlines()
            assert len(exported_links) == len(links), "Subscription client count differs from panel"
            for exported, direct in zip(exported_links, links):
                exported_uri, direct_uri = urlsplit(exported), urlsplit(direct)
                assert exported_uri._replace(query="") == direct_uri._replace(query=""), "Subscription endpoint or client differs"
                exported_params, direct_params = parse_qs(exported_uri.query), parse_qs(direct_uri.query)
                # 3x-ui 3.4.2 generates a new random spider path for each export.
                for params in (exported_params, direct_params):
                    assert params.pop("spx")[0].startswith("/"), "Expected a REALITY spider path"
                assert exported_params == direct_params, "Subscription credentials or transport differ"
            status, _ = fetch_subscription(subscription.path.rsplit("/", 1)[0] + "/" + uuid.uuid4().hex)
            assert status == 404, "Unknown subscription must not expose client access"
            print("Panel share link uses TCP/Vision, carries HTTPS; incorrect UUID is rejected.", flush=True)
            client_request(stack, exported_links[0])
            print("sing-box 1.14.0 connects using the panel subscription; incorrect UUID is rejected.", flush=True)
            sing_box_request(stack, exported_links[0], singbox_config)
            try:
                sing_box_request(stack, exported_links[0], singbox_config, good=False)
            except StackError:
                pass
            else:
                raise StackError("sing-box VLESS accepted an incorrect UUID")
            try:
                client_request(stack, links[0], good=False)
            except StackError:
                pass
            else:
                raise StackError("VLESS accepted an incorrect UUID")
            panel.request("/panel/api/server/stopXrayService", {})
            try:
                stack.xray_ready()
            except StackError:
                pass
            else:
                raise StackError("Readiness accepted a stopped Xray process")
            panel.request("/panel/api/server/restartXrayService", {})
            wait_for(stack.xray_ready, "Restart Xray after readiness check")
            inbounds = panel.request("/panel/api/inbounds/list")
            assert len(inbounds) == 1, "Bootstrap duplicated the inbound"
            print("Change password, enable 2FA, delete initial access, then recreate containers.", flush=True)
            panel.request(f"/panel/api/inbounds/del/{inbounds[0]['id']}", {})
            new_password = "changed-after-install-$-password"
            panel.request("/panel/api/setting/updateUser", {
                "oldUsername": values["INITIAL_PANEL_USERNAME"], "oldPassword": values["INITIAL_PANEL_PASSWORD"],
                "newUsername": values["INITIAL_PANEL_USERNAME"], "newPassword": new_password})
            panel = Panel(stack.model["x-bootstrap"]["panel-url"])
            panel.login(values["INITIAL_PANEL_USERNAME"], new_password)
            settings = panel.request("/panel/api/setting/all", {})
            two_factor_secret = base64.b32encode(os.urandom(20)).decode()
            settings.update(twoFactorEnable=True, twoFactorToken=two_factor_secret)
            panel.request("/panel/api/setting/update", settings)
            stack.command("stop", "caddy", "xui", label="Simulate update shutdown")
            stack.bootstrap()  # Must not authenticate with old credentials or recreate deleted access.
            stack.command("up", "-d", "--force-recreate", "xui", "mtg", "caddy", label="Recreate services")
            stack.services_ready()
            panel = Panel(stack.model["x-bootstrap"]["panel-url"])
            panel.login(values["INITIAL_PANEL_USERNAME"], new_password, totp(two_factor_secret))
            assert panel.request("/panel/api/inbounds/list") == [], "Deleted inbound was recreated"
            assert panel.request("/panel/api/setting/all", {})["twoFactorEnable"] is True, "2FA was reset"
            panel.logout()
            with patch("stack.ssl.create_default_context", return_value=context):
                wait_for(stack.https_ready, "HTTPS after recreation")
            print("PASS: bootstrap/resume, VLESS, TLS, password/2FA preservation and deleted access.", flush=True)
        finally:
            stack.command("down", "--volumes", "--remove-orphans", label="Clean isolated test project")


if __name__ == "__main__":
    try:
        main()
    except StackError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
