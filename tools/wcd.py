#!/usr/bin/env python3
"""wcd: the workos.cloud device protocol from a terminal (stdlib only).

Signs in with the RFC 8628 device grant at signin.workos.com for exactly one
resource (https://mcp.workos.cloud/mcp) and calls read-only Alto MCP tools,
the same way the ESP-IDF component does. Use it to prove a flow before
putting it on a device.

  wcd.py register                      public client by dynamic client registration
  wcd.py login [--browser-cmd CMD]     device grant; opens the approval URL
  wcd.py whoami                        userinfo + alto_whoami
  wcd.py tools                         tools/list on the resource
  wcd.py call <tool> [json]            one allowlisted tool
  wcd.py app-tools <app>               alto_app_tools {app}
  wcd.py app-use <app> <tool> [json | key=value ...]
  wcd.py logout                        forget the local session

Client and session live in .local/ (mode 0600, gitignored). Tokens are never
printed. Tool output is untrusted data: it is printed, never acted on.
"""
import argparse
import json
import os
import shlex
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
PROTOCOL_VERSION = "2025-06-18"
RENEW_LEAD_S = 45


class WcdError(Exception):
    pass


# ---- config and local state -------------------------------------------------

def load_config(path=None):
    if not path:
        path = os.path.join(ROOT, "config", "workos-cloud.json")
        if not os.path.exists(path):
            path = os.path.join(ROOT, "config", "workos-cloud.example.json")
    with open(path) as f:
        cfg = json.load(f)
    res = cfg.get("resource")
    if not isinstance(res, str) or not res.startswith("https://") or any(c in res for c in " ,\t"):
        raise WcdError("config: resource must be exactly one https URL")
    cfg.setdefault("auth_server", "https://signin.workos.com")
    cfg.setdefault("scope", "openid profile email offline_access")
    cfg.setdefault("user_agent", "workos-cloud-device/0.1")
    cfg.setdefault("client_name", "workos-cloud-device")
    cfg.setdefault("allowlist", {})
    return cfg


class State:
    """Private files in the state directory, 0600."""

    def __init__(self, directory):
        self.dir = directory

    def path(self, name):
        return os.path.join(self.dir, name)

    def load(self, name):
        p = self.path(name)
        if not os.path.exists(p):
            return None
        with open(p) as f:
            return json.load(f)

    def save(self, name, obj):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        p = self.path(name)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f)
        os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)

    def delete(self, name):
        p = self.path(name)
        if os.path.exists(p):
            os.remove(p)


# ---- pure helpers (tested offline) ----------------------------------------------

def sse_events(body):
    """The data payloads of a streamable-HTTP reply: one JSON body, or the
    data: lines of each text/event-stream event joined with newlines."""
    text = body.strip()
    if text.startswith("{") or text.startswith("["):
        return [text]
    events, data = [], []
    for line in body.splitlines():
        if line == "":
            if data:
                events.append("\n".join(data))
                data = []
        elif line.startswith("data:"):
            v = line[5:]
            data.append(v[1:] if v.startswith(" ") else v)
    if data:
        events.append("\n".join(data))
    return events


def find_reply(body, req_id):
    """The JSON-RPC message with this id; notifications such as
    notifications/tools/list_changed may come first."""
    for data in sse_events(body):
        try:
            m = json.loads(data)
        except ValueError:
            continue
        if isinstance(m, dict) and m.get("id") == req_id:
            return m
    return None


def _tokens(value):
    if isinstance(value, str):
        return [t for t in value.replace(",", " ").split() if t]
    return [t for t in (value or []) if isinstance(t, str)]


def app_pairs(allow):
    pairs = set()
    for p in allow.get("app_tools") or []:
        if isinstance(p, dict) and p.get("app") and p.get("tool"):
            pairs.add((p["app"], p["tool"]))
        elif isinstance(p, str) and ":" in p:
            pairs.add(tuple(p.split(":", 1)))
    return pairs


READ_VERBS = ("list", "get", "status", "whoami", "me", "search", "read", "show", "describe", "info")


def _words(name):
    out, word = [], ""
    for i, c in enumerate(name):
        if c in "_-./ ":
            if word:
                out.append(word.lower())
            word = ""
            continue
        if word and c.isupper() and name[i - 1].islower():
            out.append(word.lower())
            word = ""
        word += c
    if word:
        out.append(word.lower())
    return out


def tool_allowed(allow, tool):
    """The device rule: no required arguments, not destructive, not
    readOnlyHint: false, and listed, annotated read-only, or (opt-in) named
    like a read."""
    name = tool.get("name")
    if not isinstance(name, str) or not name:
        return False
    ann = tool.get("annotations") or {}
    if ann.get("destructiveHint") is True or ann.get("readOnlyHint") is False:
        return False
    if (tool.get("inputSchema") or {}).get("required"):
        return False
    if ann.get("readOnlyHint") is True or name in _tokens(allow.get("direct_tools")):
        return True
    if allow.get("read_like_names"):
        words = _words(name)
        return bool(words) and (words[0] in READ_VERBS or "status" in words or "whoami" in words)
    return False


def app_use_allowed(allow, app, tool):
    return (app, tool) in app_pairs(allow)


def result_text(result):
    return "\n".join(c["text"] for c in (result or {}).get("content", [])
                     if isinstance(c, dict) and isinstance(c.get("text"), str))


def result_json(result):
    """structuredContent, else the text content parsed; raises on isError."""
    if result.get("isError"):
        raise WcdError("tool error: " + (result_text(result)[:300] or "(no text)"))
    if isinstance(result.get("structuredContent"), (dict, list)):
        return result["structuredContent"]
    text = result_text(result)
    try:
        return json.loads(text)
    except ValueError:
        return text


def unwrap_app_use(j):
    """Peel alto_app_use's {app, tool, provenance, result} wrapper and the
    app tool's own MCP result down to its payload (untrusted data)."""
    for _ in range(6):
        if isinstance(j, dict) and (isinstance(j.get("content"), list) or isinstance(j.get("structuredContent"), dict)):
            j = result_json(j)
        elif isinstance(j, dict) and "result" in j and ("provenance" in j or isinstance(j.get("tool"), str)):
            inner = j["result"]
            if isinstance(inner, str):
                try:
                    inner = json.loads(inner)
                except ValueError:
                    raise WcdError("app result is not JSON")
            j = inner
        else:
            return j
    raise WcdError("app result nested too deep")


def parse_arguments(args):
    """[] -> {}; ['{"limit":1}'] -> that object; ['limit=1', 'q=x'] -> {"limit":1,"q":"x"}."""
    if not args:
        return {}
    if len(args) == 1 and args[0].lstrip().startswith("{"):
        v = json.loads(args[0])
        if not isinstance(v, dict):
            raise WcdError("arguments must be a JSON object")
        return v
    out = {}
    for a in args:
        k, sep, v = a.partition("=")
        if not sep or not k:
            raise WcdError("arguments: use a JSON object or key=value pairs")
        try:
            out[k] = json.loads(v)
        except ValueError:
            out[k] = v
    return out


# ---- HTTP -------------------------------------------------------------------------

class Http:
    def __init__(self, user_agent):
        self.ua = user_agent   # Cloudflare answers python-urllib's default with error 1010

    def request(self, method, url, data=None, headers=None, form=False):
        h = dict(headers or {})
        body = None
        if data is not None:
            if form:
                body = urllib.parse.urlencode(data).encode()
                h["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                body = json.dumps(data).encode()
                h["Content-Type"] = "application/json"
        h.setdefault("Accept", "application/json")
        h["User-Agent"] = self.ua
        r = urllib.request.Request(url, data=body, headers=h, method=method)
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode(errors="replace")
        except urllib.error.URLError as e:
            raise WcdError("no response from %s: %s" % (urllib.parse.urlsplit(url).netloc, e.reason))


def oauth_error(status, body):
    """Status plus the error code, never the body (it can echo secrets)."""
    try:
        j = json.loads(body)
        return "HTTP %d %s %s" % (status, j.get("error", ""), j.get("error_description", "")[:200])
    except ValueError:
        return "HTTP %d" % status


# ---- session -----------------------------------------------------------------------

class Session:
    def __init__(self, cfg, state, http):
        self.cfg, self.state, self.http = cfg, state, http

    def url(self, path):
        return self.cfg["auth_server"].rstrip("/") + path

    def client_id(self):
        cid = self.cfg.get("client_id")
        if cid:
            return cid
        c = self.state.load("client.json")
        if not c:
            raise WcdError("no client: run `wcd.py register` or set client_id in the config")
        return c["client_id"]

    def token_form(self, *pairs):
        # Exactly one resource: two make aud the project and MCP answers 401.
        return list(pairs) + [("client_id", self.client_id()), ("resource", self.cfg["resource"])]

    def accept(self, j):
        if not j.get("access_token") or j.get("token_type", "Bearer").lower() != "bearer":
            raise WcdError("token response without a bearer access token")
        old = self.state.load("session.json") or {}
        sess = {
            "access_token": j["access_token"],
            # Refresh tokens rotate: save the new one before using the access token.
            "refresh_token": j.get("refresh_token") or old.get("refresh_token"),
            "expires_at": time.time() + int(j.get("expires_in") or 300),
            "resource": self.cfg["resource"],
        }
        self.state.save("session.json", sess)
        return sess

    def refresh(self):
        sess = self.state.load("session.json")
        if not sess or not sess.get("refresh_token"):
            raise WcdError("not signed in: run `wcd.py login`")
        if sess.get("resource") != self.cfg["resource"]:
            raise WcdError("session is for another resource: run `wcd.py login`")
        s, _, b = self.http.request("POST", self.url("/oauth2/token"),
                                    self.token_form(("grant_type", "refresh_token"),
                                                    ("refresh_token", sess["refresh_token"])), form=True)
        if s != 200:
            if 400 <= s < 500 and s != 429:
                self.state.delete("session.json")
                raise WcdError("refresh refused (%s); session forgotten: run `wcd.py login`" % oauth_error(s, b))
            raise WcdError("refresh failed (%s); session kept" % oauth_error(s, b))
        return self.accept(json.loads(b))

    def bearer(self, force=False):
        sess = self.state.load("session.json")
        if not force and sess and sess.get("access_token") and time.time() < sess.get("expires_at", 0) - RENEW_LEAD_S \
                and sess.get("resource") == self.cfg["resource"]:
            return sess["access_token"]
        return self.refresh()["access_token"]


# ---- MCP --------------------------------------------------------------------------------

class Mcp:
    def __init__(self, cfg, session, http):
        self.cfg, self.session, self.http = cfg, session, http
        self.url = cfg["resource"]
        self.sid = None
        self.next_id = 0
        self.bearer = None

    def _post(self, msg):
        h = {"Authorization": "Bearer " + self.bearer, "Accept": "application/json, text/event-stream"}
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
            h["MCP-Protocol-Version"] = PROTOCOL_VERSION
        return self.http.request("POST", self.url, msg, h)

    def open(self):
        for attempt in range(2):
            self.bearer = self.session.bearer(force=attempt > 0)
            self.sid, self.next_id = None, 0
            s, hd, b = self._send("initialize", {
                "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": {"name": self.cfg["client_name"], "version": "0.1"}})
            if s != 401:
                break   # the server may end an access token early: renew once
        if s // 100 != 2:
            raise WcdError("initialize: HTTP %d" % s)
        self.sid = hd.get("mcp-session-id")
        reply = find_reply(b, self.next_id)
        if not reply or "result" not in reply:
            raise WcdError("initialize: no result")
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return reply["result"]

    def _send(self, method, params=None):
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        return self._post(msg)

    def request(self, method, params=None):
        s, _, b = self._send(method, params)
        if s // 100 != 2:
            raise WcdError("%s: HTTP %d" % (method, s))
        reply = find_reply(b, self.next_id)
        if reply is None:
            raise WcdError("%s: no reply with id %d" % (method, self.next_id))
        if "error" in reply:
            e = reply["error"] or {}
            raise WcdError("%s: %s" % (method, e.get("message") or "JSON-RPC error %s" % e.get("code")))
        return reply.get("result") or {}

    def tools(self):
        return self.request("tools/list").get("tools") or []

    def call(self, name, arguments=None):
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})

    def close(self):
        if self.sid:
            h = {"Authorization": "Bearer " + self.bearer, "Mcp-Session-Id": self.sid}
            self.http.request("DELETE", self.url, headers=h)
            self.sid = None


# ---- commands ---------------------------------------------------------------------------

def show(value):
    print(json.dumps(value, indent=2, ensure_ascii=False) if not isinstance(value, str) else value)


def cmd_register(cfg, state, http, args):
    if state.load("client.json") and not args.force:
        print("client_id:", state.load("client.json")["client_id"], "(already registered; --force for a new one)")
        return
    s, _, b = http.request("POST", cfg["auth_server"].rstrip("/") + "/oauth2/register", {
        "client_name": args.name or cfg["client_name"],
        # Required non-empty even for a device-only client; never used.
        "redirect_uris": ["http://127.0.0.1/callback"],
        "grant_types": [DEVICE_GRANT, "refresh_token"],
        "token_endpoint_auth_method": "none",
        "scope": cfg["scope"],
    })
    if s >= 300:
        raise WcdError("register: " + oauth_error(s, b))
    c = json.loads(b)
    state.save("client.json", c)
    print("client_id:", c.get("client_id"), "(public; put it in your config / CONFIG_WORKOS_CLOUD_CLIENT_ID)")


def open_url(url, browser_cmd):
    if browser_cmd:
        subprocess.run(shlex.split(browser_cmd) + [url], check=False)
    elif sys.platform == "darwin":
        subprocess.run(["open", url], check=False)
    else:
        webbrowser.open(url)


def cmd_login(cfg, state, http, args):
    sess = Session(cfg, state, http)
    s, _, b = http.request("POST", sess.url("/oauth2/device_authorization"),
                           sess.token_form(("scope", cfg["scope"])), form=True)
    if s != 200:
        raise WcdError("device_authorization: " + oauth_error(s, b))
    d = json.loads(b)
    url = d.get("verification_uri_complete") or d["verification_uri"]
    print("Open:", url)
    print("Code:", d["user_code"], "(check it matches, sign in with SSO, approve)")
    if not args.no_open:
        open_url(url, args.browser_cmd or os.environ.get("WCD_BROWSER_CMD"))
    interval = int(d.get("interval") or 5)
    deadline = time.time() + min(900, int(d.get("expires_in") or 300))
    while time.time() < deadline:
        time.sleep(interval)
        s, _, b = http.request("POST", sess.url("/oauth2/token"),
                               sess.token_form(("grant_type", DEVICE_GRANT), ("device_code", d["device_code"])),
                               form=True)
        try:
            j = json.loads(b)
        except ValueError:
            j = {}
        if s == 200 and j.get("access_token"):
            sess.accept(j)
            print("Signed in; access token lasts", j.get("expires_in", "?"), "s; session saved to",
                  os.path.relpath(state.path("session.json")))
            return
        e = j.get("error") or "http %d" % s
        if e == "authorization_pending" or s >= 500 or s == 429:
            continue
        if e == "slow_down":
            interval += 5
            continue
        raise WcdError("sign-in stopped: %s %s" % (e, j.get("error_description", "")))
    raise WcdError("the code expired")


def with_mcp(cfg, state, http, fn):
    m = Mcp(cfg, Session(cfg, state, http), http)
    m.open()
    try:
        return fn(m)
    finally:
        m.close()


def cmd_whoami(cfg, state, http, args):
    sess = Session(cfg, state, http)
    s, _, b = http.request("GET", sess.url("/oauth2/userinfo"), headers={"Authorization": "Bearer " + sess.bearer()})
    print("userinfo: HTTP", s)
    if s == 200:
        u = json.loads(b)
        show({k: u[k] for k in ("sub", "name", "email", "org_id") if k in u})

    def alto(m):
        if "alto_whoami" not in _tokens(cfg["allowlist"].get("direct_tools")):
            print("alto_whoami: not in the allowlist; skipped")
            return
        print("alto_whoami:")
        show(result_json(m.call("alto_whoami")))
    with_mcp(cfg, state, http, alto)


def cmd_tools(cfg, state, http, args):
    def run(m):
        tools = m.tools()
        print(len(tools), "tools on", cfg["resource"], "(* = the device may call it on its own)")
        for t in tools:
            desc = (t.get("description") or "").split("\n")[0][:80]
            print(" %s %s | %s" % ("*" if tool_allowed(cfg["allowlist"], t) else " ", t.get("name"), desc))
    with_mcp(cfg, state, http, run)


def cmd_call(cfg, state, http, args):
    arguments = parse_arguments(args.arguments)

    def run(m):
        tool = next((t for t in m.tools() if t.get("name") == args.tool), None)
        if tool is None:
            raise WcdError("%s is not listed by the server" % args.tool)
        if not tool_allowed(cfg["allowlist"], tool):
            raise WcdError("%s is not allowlisted as read-only with no required arguments; "
                           "widening the allowlist is a deliberate config change" % args.tool)
        if arguments:
            raise WcdError("allowlisted direct tools take no arguments")
        show(result_json(m.call(args.tool)))
    with_mcp(cfg, state, http, run)


def cmd_app_tools(cfg, state, http, args):
    # Read-only discovery: lists the app's tools and their schemas.
    with_mcp(cfg, state, http, lambda m: show(result_json(m.call("alto_app_tools", {"app": args.app}))))


def cmd_app_use(cfg, state, http, args):
    if not app_use_allowed(cfg["allowlist"], args.app, args.tool):
        raise WcdError("%s:%s is not in allowlist.app_tools; alto_app_use is destructive-capable, so widening "
                       "the allowlist is a deliberate config change" % (args.app, args.tool))
    arguments = parse_arguments(args.arguments)
    call = {"app": args.app, "tool": args.tool, "arguments": arguments}   # "app", not "application"
    with_mcp(cfg, state, http, lambda m: show(unwrap_app_use(m.call("alto_app_use", call))))


def cmd_logout(cfg, state, http, args):
    state.delete("session.json")
    print("Local session forgotten.")


def main(argv=None):
    p = argparse.ArgumentParser(prog="wcd.py", description=__doc__.split("\n")[0])
    p.add_argument("--config", help="config JSON (default config/workos-cloud.json, else the example)")
    p.add_argument("--state", default=os.path.join(ROOT, ".local"), help="private state directory (default .local/)")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("register", help="register a public client (RFC 7591)")
    r.add_argument("--name")
    r.add_argument("--force", action="store_true")
    r.set_defaults(fn=cmd_register)
    r = sub.add_parser("login", help="device grant (RFC 8628)")
    r.add_argument("--browser-cmd", help='e.g. \'open -n -a "Google Chrome" --args --profile-directory="Profile 4"\'')
    r.add_argument("--no-open", action="store_true")
    r.set_defaults(fn=cmd_login)
    sub.add_parser("whoami").set_defaults(fn=cmd_whoami)
    sub.add_parser("tools").set_defaults(fn=cmd_tools)
    r = sub.add_parser("call")
    r.add_argument("tool")
    r.add_argument("arguments", nargs="*")
    r.set_defaults(fn=cmd_call)
    r = sub.add_parser("app-tools")
    r.add_argument("app")
    r.set_defaults(fn=cmd_app_tools)
    r = sub.add_parser("app-use")
    r.add_argument("app")
    r.add_argument("tool")
    r.add_argument("arguments", nargs="*")
    r.set_defaults(fn=cmd_app_use)
    sub.add_parser("logout").set_defaults(fn=cmd_logout)
    args = p.parse_args(argv)
    try:
        cfg = load_config(args.config)
        args.fn(cfg, State(args.state), Http(cfg["user_agent"]), args)
    except WcdError as e:
        print("error:", e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
