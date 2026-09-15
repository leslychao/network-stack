"""One-time provisioning through the supported 3x-ui API (no database writes)."""

import copy
import http.cookiejar
import json
import urllib.error
import urllib.request

from settings import StackError, mask


class Panel:
    def __init__(self, url):
        self.url = url.rstrip("/")
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.csrf = ""

    def request(self, path, data=None):
        headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
        if data is not None:
            headers.update({"Content-Type": "application/json", "X-CSRF-Token": self.csrf})
        request = urllib.request.Request(self.url + path, headers=headers,
                                         data=None if data is None else json.dumps(data).encode())
        try:
            with self.opener.open(request, timeout=15) as response:
                body = response.read(4 * 1024 * 1024 + 1)
            if len(body) > 4 * 1024 * 1024:
                raise StackError("Panel API response exceeded the size limit")
            result = json.loads(body)
            if result.get("success") is not True:
                raise StackError("Panel API rejected the operation")
            return result.get("obj")
        except (OSError, ValueError, urllib.error.URLError):
            raise StackError("Panel API request failed; response suppressed to protect credentials") from None

    def login(self, username, password, two_factor=""):
        self.csrf = self.request("/csrf-token")
        mask([self.csrf])
        self.request("/login", {"username": username, "password": password, "twoFactorCode": two_factor})
        self.csrf = self.request("/csrf-token")
        mask([self.csrf])

    def logout(self):
        self.request("/logout", {})


def initial_inbound(defaults, values):
    inbound = copy.deepcopy(defaults["inbound"])
    client = copy.deepcopy(defaults["client"])
    client["id"] = values["INITIAL_VLESS_UUID"]
    # A stable subscription ID is required by the panel even for direct links.
    client["subId"] = values["INITIAL_VLESS_UUID"].replace("-", "")
    inbound["settings"]["clients"] = [client]
    reality = inbound["streamSettings"]["realitySettings"]
    reality["privateKey"] = values["INITIAL_REALITY_PRIVATE_KEY"]
    reality["shortIds"] = [values["INITIAL_REALITY_SHORT_ID"]]
    reality["settings"]["publicKey"] = values["INITIAL_REALITY_PUBLIC_KEY"]
    inbound["shareAddrStrategy"] = "custom"
    inbound["shareAddr"] = values["PANEL_HOST"]
    return inbound


def as_object(value):
    return json.loads(value) if isinstance(value, str) else value


def ensure_inbound(panel, expected):
    """Resume an interrupted initial POST; never overwrite a different inbound."""
    inbounds = panel.request("/panel/api/inbounds/list")
    matches = [item for item in inbounds if item["remark"] == expected["remark"]
               or item["port"] == expected["port"]]
    if matches:
        if len(matches) != 1:
            raise StackError("Initial inbound conflicts with existing panel configuration")
        actual = matches[0]
        for key in ("remark", "port", "protocol", "enable"):
            if actual[key] != expected[key]:
                raise StackError("Existing inbound does not match the incomplete bootstrap")
        clients = as_object(actual["settings"]).get("clients", [])
        reality = as_object(actual["streamSettings"])["realitySettings"]
        wanted = expected["streamSettings"]["realitySettings"]
        if (len(clients) != 1 or clients[0]["id"] != expected["settings"]["clients"][0]["id"]
                or reality["privateKey"] != wanted["privateKey"]
                or reality["shortIds"] != wanted["shortIds"]):
            raise StackError("Existing credentials do not match the incomplete bootstrap")
        return
    panel.request("/panel/api/inbounds/add", expected)
