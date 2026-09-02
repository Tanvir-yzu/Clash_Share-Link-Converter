#!/usr/bin/env python3
"""
Clash YAML → Share Link Converter
Modern Streamlit UI (dark glassmorphism)
"""

import base64
import html
import json
import re
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

import streamlit as st
import yaml


# ============================================================
# Conversion Functions
# ============================================================

def encode_fragment(name: str) -> str:
    return urllib.parse.quote(str(name), safe="")


def build_query(params: Dict[str, Any]) -> str:
    filtered = {k: str(v) for k, v in params.items() if v is not None and v != ""}
    return urllib.parse.urlencode(filtered, doseq=True)


def convert_vless(proxy: Dict[str, Any]) -> Optional[str]:
    uuid = proxy.get("uuid")
    server = proxy.get("server")
    port = proxy.get("port")
    name = proxy.get("name", "VLESS")

    if not all([uuid, server, port]):
        return None

    params = {
        "encryption": proxy.get("encryption", "none"),
        "type": proxy.get("network", "tcp"),
        "fp": proxy.get("client-fingerprint") or proxy.get("fingerprint"),
    }

    flow = proxy.get("flow")
    if flow:
        params["flow"] = flow

    if proxy.get("tls") or proxy.get("reality-opts"):
        if proxy.get("reality-opts"):
            params["security"] = "reality"
            reality = proxy["reality-opts"]
            params["pbk"] = reality.get("public-key")
            params["sid"] = reality.get("short-id")
            if reality.get("spider-x"):
                params["spx"] = reality.get("spider-x")
        else:
            params["security"] = "tls"

        sni = proxy.get("servername") or proxy.get("sni")
        if sni:
            params["sni"] = sni

        if proxy.get("skip-cert-verify"):
            params["allowInsecure"] = "1"

    network = proxy.get("network", "tcp")
    if network == "ws":
        ws_opts = proxy.get("ws-opts", {}) or {}
        if ws_opts.get("path"):
            params["path"] = ws_opts["path"]
        headers = ws_opts.get("headers", {}) or {}
        if headers.get("Host"):
            params["host"] = headers["Host"]
    elif network == "grpc":
        grpc_opts = proxy.get("grpc-opts", {}) or {}
        if grpc_opts.get("grpc-service-name"):
            params["serviceName"] = grpc_opts["grpc-service-name"]
        params["mode"] = grpc_opts.get("grpc-mode", "gun")

    query = build_query(params)
    fragment = encode_fragment(name)
    return f"vless://{uuid}@{server}:{port}?{query}#{fragment}"


def convert_anytls(proxy: Dict[str, Any]) -> Optional[str]:
    password = proxy.get("password")
    server = proxy.get("server")
    port = proxy.get("port", 443)
    name = proxy.get("name", "anytls")

    if not all([password, server]):
        return None

    params = {}
    if proxy.get("sni"):
        params["sni"] = proxy["sni"]
    if proxy.get("skip-cert-verify"):
        params["insecure"] = "1"

    query = build_query(params)
    fragment = encode_fragment(name)

    link = f"anytls://{password}@{server}:{port}"
    if query:
        link += f"?{query}"
    link += f"#{fragment}"
    return link


def convert_trojan(proxy: Dict[str, Any]) -> Optional[str]:
    password = proxy.get("password")
    server = proxy.get("server")
    port = proxy.get("port")
    name = proxy.get("name", "Trojan")

    if not all([password, server, port]):
        return None

    params = {
        "security": "tls",
        "type": proxy.get("network", "tcp"),
    }

    sni = proxy.get("sni") or proxy.get("servername")
    if sni:
        params["sni"] = sni

    if proxy.get("skip-cert-verify"):
        params["allowInsecure"] = "1"
    else:
        params["allowInsecure"] = "0"

    network = proxy.get("network", "tcp")
    if network == "ws":
        ws_opts = proxy.get("ws-opts", {}) or {}
        if ws_opts.get("path"):
            params["path"] = ws_opts["path"]
        headers = ws_opts.get("headers", {}) or {}
        if headers.get("Host"):
            params["host"] = headers["Host"]
    elif network == "grpc":
        grpc_opts = proxy.get("grpc-opts", {}) or {}
        if grpc_opts.get("grpc-service-name"):
            params["serviceName"] = grpc_opts["grpc-service-name"]

    query = build_query(params)
    fragment = encode_fragment(name)
    return f"trojan://{password}@{server}:{port}?{query}#{fragment}"


def convert_vmess(proxy: Dict[str, Any]) -> Optional[str]:
    uuid = proxy.get("uuid") or proxy.get("id")
    server = proxy.get("server")
    port = proxy.get("port")
    name = proxy.get("name", "VMess")

    if not all([uuid, server, port]):
        return None

    config = {
        "v": "2",
        "ps": name,
        "add": server,
        "port": str(port),
        "id": uuid,
        "aid": str(proxy.get("alterId", 0)),
        "scy": proxy.get("cipher", "auto"),
        "net": proxy.get("network", "tcp"),
        "type": "none",
        "host": "",
        "path": "",
        "tls": "tls" if proxy.get("tls") else "",
        "sni": proxy.get("servername") or proxy.get("sni") or "",
        "fp": proxy.get("client-fingerprint") or "",
    }

    network = proxy.get("network", "tcp")
    if network == "ws":
        ws_opts = proxy.get("ws-opts", {}) or {}
        config["path"] = ws_opts.get("path", "")
        headers = ws_opts.get("headers", {}) or {}
        config["host"] = headers.get("Host", "")

    encoded = base64.b64encode(
        json.dumps(config, ensure_ascii=False).encode()
    ).decode()
    return f"vmess://{encoded}"


def convert_hysteria2(proxy: Dict[str, Any]) -> Optional[str]:
    password = proxy.get("password")
    server = proxy.get("server")
    port = proxy.get("port", 443)
    name = proxy.get("name", "Hysteria2")

    if not password or not server:
        return None

    # userpass auth: auth (username) + auth-str (password)
    auth = str(password)
    if proxy.get("auth") and proxy.get("auth-str"):
        auth = f"{proxy['auth']}:{proxy['auth-str']}"

    params = {}
    if proxy.get("sni"):
        params["sni"] = proxy["sni"]
    if proxy.get("skip-cert-verify"):
        params["insecure"] = "1"
    if proxy.get("obfs"):
        params["obfs"] = proxy["obfs"]
    if proxy.get("obfs-password"):
        params["obfs-password"] = proxy["obfs-password"]
    if proxy.get("fingerprint"):
        params["pinSHA256"] = proxy["fingerprint"]

    query = build_query(params)
    fragment = encode_fragment(name)

    link = f"hysteria2://{urllib.parse.quote(auth, safe=':')}@{server}:{port}"
    if query:
        link += f"?{query}"
    link += f"#{fragment}"
    return link


CONVERTERS = {
    "vless": convert_vless,
    "anytls": convert_anytls,
    "trojan": convert_trojan,
    "vmess": convert_vmess,
    "hysteria2": convert_hysteria2,
}


def convert_proxies(
    proxies: List[Dict[str, Any]],
    selected_types: List[str],
) -> List[Dict[str, str]]:
    """Return list of {name, type, link}"""
    results = []
    for proxy in proxies:
        ptype = (proxy.get("type") or "").lower()
        if ptype not in selected_types:
            continue
        converter = CONVERTERS.get(ptype)
        if not converter:
            continue
        link = converter(proxy)
        if link:
            results.append({
                "name": proxy.get("name", "Unknown"),
                "type": ptype.upper(),
                "link": link,
            })
    return results


# ============================================================
# Subscription Parsing (Share Link → Clash Proxy)
# ============================================================

def _b64_decode_flex(s: str) -> str:
    """Decode base64 (auto-padding; tries standard then urlsafe)."""
    s = re.sub(r"\s+", "", s)
    if not s:
        return ""
    s += "=" * (-len(s) % 4)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return fn(s.encode("ascii")).decode("utf-8", errors="replace")
        except Exception:
            continue
    return ""


def _b64_decode_urlsafe(s: str) -> str:
    s = re.sub(r"\s+", "", s)
    if not s:
        return ""
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _split_userinfo(netloc: str) -> tuple:
    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")
        return userinfo, hostport
    return "", netloc


def _split_host_port(hostport: str) -> tuple:
    hostport = hostport.strip()
    if not hostport:
        return "", 0
    if hostport.startswith("["):
        end = hostport.find("]")
        host = hostport[: end + 1]
        rest = hostport[end + 1 :]
        return host, int(rest.strip(":")) if rest.strip(":") else 0
    if ":" in hostport:
        host, _, port = hostport.rpartition(":")
        return host, int(port) if port.isdigit() else 0
    return hostport, 0


def _clean_proxy(obj):
    if not isinstance(obj, dict):
        return obj
    out = {}
    for k, v in obj.items():
        if isinstance(v, dict):
            v = _clean_proxy(v)
            if not v:
                continue
        if v is None or v == "":
            continue
        out[k] = v
    return out


def parse_vless_link(link: str) -> Optional[Dict[str, Any]]:
    u = urllib.parse.urlsplit(link)
    if u.scheme.lower() != "vless":
        return None
    uuid, hostport = _split_userinfo(u.netloc)
    host, port = _split_host_port(hostport)
    if not uuid or not host or not port:
        return None
    params = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    proxy = {
        "name": urllib.parse.unquote(u.fragment) or "VLESS",
        "type": "vless", "server": host, "port": port, "uuid": uuid, "udp": True,
        "network": params.get("type", "tcp"),
        "flow": params.get("flow", ""),
        "client-fingerprint": params.get("fp", ""),
    }
    security = params.get("security", "")
    if security == "reality":
        proxy["tls"] = True
        proxy["servername"] = params.get("sni", "")
        proxy["reality-opts"] = {
            "public-key": params.get("pbk", ""),
            "short-id": params.get("sid", ""),
        }
        if params.get("spx"):
            proxy["reality-opts"]["spider-x"] = params["spx"]
    elif security == "tls":
        proxy["tls"] = True
        proxy["servername"] = params.get("sni", "")
    if params.get("allowInsecure") == "1":
        proxy["skip-cert-verify"] = True
    if proxy["network"] == "ws":
        proxy["ws-opts"] = {"path": params.get("path", "/")}
        if params.get("host"):
            proxy["ws-opts"]["headers"] = {"Host": params["host"]}
    elif proxy["network"] == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": params.get("serviceName", "")}
    return _clean_proxy(proxy)


def parse_trojan_link(link: str) -> Optional[Dict[str, Any]]:
    u = urllib.parse.urlsplit(link)
    if u.scheme.lower() != "trojan":
        return None
    password, hostport = _split_userinfo(u.netloc)
    host, port = _split_host_port(hostport)
    if not password or not host or not port:
        return None
    params = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    proxy = {
        "name": urllib.parse.unquote(u.fragment) or "Trojan",
        "type": "trojan", "server": host, "port": port, "password": password, "udp": True,
        "sni": params.get("sni", ""),
        "network": params.get("type", "tcp"),
    }
    if params.get("allowInsecure") == "1":
        proxy["skip-cert-verify"] = True
    if proxy["network"] == "ws":
        proxy["ws-opts"] = {"path": params.get("path", "/")}
        if params.get("host"):
            proxy["ws-opts"]["headers"] = {"Host": params["host"]}
    elif proxy["network"] == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": params.get("serviceName", "")}
    return _clean_proxy(proxy)


def parse_vmess_link(link: str) -> Optional[Dict[str, Any]]:
    if not link.lower().startswith("vmess://"):
        return None
    decoded = _b64_decode_flex(link[len("vmess://"):])
    if not decoded:
        return None
    try:
        cfg = json.loads(decoded)
    except Exception:
        return None
    if not isinstance(cfg, dict):
        return None
    try:
        port = int(cfg.get("port", 0))
    except (TypeError, ValueError):
        return None
    server = cfg.get("add", "")
    if not server or not port:
        return None
    net = cfg.get("net", "tcp").lower()
    proxy = {
        "name": cfg.get("ps") or "VMess",
        "type": "vmess", "server": server, "port": port,
        "uuid": cfg.get("id", ""), "alterId": int(cfg.get("aid", 0) or 0),
        "cipher": cfg.get("scy", "auto"), "udp": True,
    }
    if net in ("ws", "grpc", "tcp", "http", "h2"):
        proxy["network"] = net
    if cfg.get("tls") == "tls":
        proxy["tls"] = True
        proxy["servername"] = cfg.get("sni", "") or cfg.get("host", "")
    if net == "ws":
        proxy["ws-opts"] = {"path": cfg.get("path", "/")}
        if cfg.get("host"):
            proxy["ws-opts"]["headers"] = {"Host": cfg["host"]}
    if cfg.get("fp"):
        proxy["client-fingerprint"] = cfg["fp"]
    return _clean_proxy(proxy)


def parse_ss_link(link: str) -> Optional[Dict[str, Any]]:
    if not link.lower().startswith("ss://"):
        return None
    payload = link[len("ss://"):]
    name = "SS"
    if "#" in payload:
        payload, _, _name = payload.rpartition("#")
        name = urllib.parse.unquote(_name) or "SS"
    if "@" in payload:
        userinfo, _, hostport = payload.rpartition("@")
        hostport = hostport.split("/")[0]
        host, port = _split_host_port(hostport)
        if ":" in userinfo:
            method, _, password = userinfo.partition(":")
        else:
            cred = _b64_decode_urlsafe(userinfo)
            if ":" in cred:
                method, _, password = cred.partition(":")
            else:
                method, password = cred, ""
    else:
        decoded = _b64_decode_urlsafe(payload)
        if "@" not in decoded:
            return None
        cred, _, hostport = decoded.rpartition("@")
        if ":" not in cred:
            return None
        method, _, password = cred.partition(":")
        host, port = _split_host_port(hostport)
    if not method or not host:
        return None
    return _clean_proxy({
        "name": name, "type": "ss", "server": host, "port": port,
        "cipher": method, "password": password, "udp": True,
    })


def parse_ssr_link(link: str) -> Optional[Dict[str, Any]]:
    if not link.lower().startswith("ssr://"):
        return None
    decoded = _b64_decode_urlsafe(link[len("ssr://"):])
    if not decoded:
        return None
    main, _, query = decoded.partition("/?")
    parts = main.split(":")
    if len(parts) < 6:
        return None
    server, port_s, protocol, method, obfs, pwd_enc = parts[:6]
    try:
        port = int(port_s)
    except ValueError:
        return None
    params = dict(urllib.parse.parse_qsl(query)) if query else {}
    proxy = {
        "name": _b64_decode_urlsafe(params.get("remarks", "")) or "SSR",
        "type": "ssr", "server": server, "port": port,
        "cipher": method, "password": _b64_decode_urlsafe(pwd_enc),
        "protocol": protocol, "obfs": obfs, "udp": True,
    }
    obfs_param = _b64_decode_urlsafe(params.get("obfsparam", ""))
    proto_param = _b64_decode_urlsafe(params.get("protoparam", ""))
    if obfs_param:
        proxy["obfs-param"] = obfs_param
    if proto_param:
        proxy["protocol-param"] = proto_param
    return _clean_proxy(proxy)


def parse_anytls_link(link: str) -> Optional[Dict[str, Any]]:
    u = urllib.parse.urlsplit(link)
    if u.scheme.lower() != "anytls":
        return None
    password, hostport = _split_userinfo(u.netloc)
    host, port = _split_host_port(hostport)
    if not password or not host:
        return None
    params = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    proxy = {
        "name": urllib.parse.unquote(u.fragment) or "anytls",
        "type": "anytls", "server": host, "port": port or 443,
        "password": password, "udp": True,
    }
    if params.get("sni"):
        proxy["sni"] = params["sni"]
    if params.get("insecure") == "1":
        proxy["skip-cert-verify"] = True
    return _clean_proxy(proxy)


def parse_hysteria2_link(link: str) -> Optional[Dict[str, Any]]:
    u = urllib.parse.urlsplit(link)
    if u.scheme.lower() not in ("hysteria2", "hy2"):
        return None
    auth_raw, hostport = _split_userinfo(u.netloc)
    host, port = _split_host_port(hostport)
    if not host:
        return None
    params = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    auth_raw = urllib.parse.unquote(auth_raw)

    proxy = {
        "name": urllib.parse.unquote(u.fragment) or "hysteria2",
        "type": "hysteria2", "server": host, "port": port or 443,
        "udp": True,
    }
    # userpass auth is formatted as "username:password"
    if auth_raw and ":" in auth_raw:
        user, _, pwd = auth_raw.partition(":")
        proxy["auth"] = user
        proxy["auth-str"] = pwd
    elif auth_raw:
        proxy["password"] = auth_raw
    elif params.get("auth"):
        proxy["password"] = params["auth"]

    if params.get("sni"):
        proxy["sni"] = params["sni"]
    if params.get("insecure") == "1":
        proxy["skip-cert-verify"] = True
    if params.get("obfs"):
        proxy["obfs"] = params["obfs"]
    if params.get("obfs-password"):
        proxy["obfs-password"] = params["obfs-password"]
    if params.get("pinSHA256"):
        proxy["fingerprint"] = params["pinSHA256"]
    return _clean_proxy(proxy)


LINK_PARSERS = {
    "vless": parse_vless_link,
    "vmess": parse_vmess_link,
    "trojan": parse_trojan_link,
    "ss": parse_ss_link,
    "ssr": parse_ssr_link,
    "anytls": parse_anytls_link,
    "hysteria2": parse_hysteria2_link,
    "hy2": parse_hysteria2_link,
}


def parse_share_links(text: str):
    proxies: List[Dict[str, Any]] = []
    errors: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        scheme = line.split("://", 1)[0].lower() if "://" in line else ""
        parser = LINK_PARSERS.get(scheme)
        if not parser:
            errors.append(f"Unsupported link: {line[:60]}")
            continue
        proxy = parser(line)
        if proxy:
            proxies.append(proxy)
        else:
            errors.append(f"Could not parse: {line[:60]}")
    return proxies, errors


def decode_subscription(content: str) -> str:
    content = content.strip()
    for _ in range(3):
        if "://" in content or re.search(r"^\s*(proxies|proxy-groups)\s*:", content, re.MULTILINE):
            break
        decoded = _b64_decode_flex(content)
        if not decoded or decoded.strip() == content:
            break
        content = decoded.strip()
    return content


def parse_subscription(content: str):
    content = content.strip()
    if not content:
        raise ValueError("Subscription content is empty.")
    content = decode_subscription(content)
    if re.search(r"^\s*(proxies|proxy-groups)\s*:", content, re.MULTILINE):
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            return [_clean_proxy(p) for p in (data.get("proxies") or []) if isinstance(p, dict)], []
        raise ValueError("Subscription YAML has an invalid structure.")
    proxies, errors = parse_share_links(content)
    if not proxies and not errors:
        raise ValueError("No recognizable proxy data was found in the subscription.")
    return [_clean_proxy(p) for p in proxies], errors


def build_clash_yaml(proxies: List[Dict[str, Any]]) -> str:
    return yaml.safe_dump({"proxies": proxies}, allow_unicode=True, sort_keys=False)


def fetch_subscription_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise ValueError("Subscription URL must start with http:// or https://")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "clash-verge/v1.5.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
    except Exception as e:
        raise ValueError(f"Failed to fetch subscription: {e}")
    for enc in ("utf-8", "gb18030"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


# ============================================================
# Streamlit Setup + Theme
# ============================================================

st.set_page_config(
    page_title="Clash → Share Link Converter",
    page_icon="🔗",
    layout="wide",
    initial_sidebar_state="expanded",
)

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* ---------- Global ---------- */
.stApp {
    background:
        radial-gradient(ellipse 70% 45% at 15% -5%, rgba(99,102,241,.16), transparent 60%),
        radial-gradient(ellipse 55% 40% at 95% 5%, rgba(236,72,153,.09), transparent 60%),
        radial-gradient(ellipse 50% 35% at 50% 110%, rgba(139,92,246,.10), transparent 60%),
        #070b16;
    color: #e2e8f0;
    font-family: 'Inter', -apple-system, sans-serif;
}
h1, h2, h3, h4 { color: #f1f5f9 !important; letter-spacing: -0.02em; }
#MainMenu, footer { visibility: hidden; }
header[data-testid="stHeader"] { background: transparent; }

::selection { background: rgba(99,102,241,.4); color: #fff; }
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #2b3654; border-radius: 8px; }
::-webkit-scrollbar-thumb:hover { background: #3d4a6e; }

/* ---------- Hero ---------- */
.main-header {
    font-size: 2.7rem; font-weight: 900; line-height: 1.15;
    letter-spacing: -0.03em;
    background: linear-gradient(90deg, #818cf8, #a78bfa, #f472b6, #818cf8);
    background-size: 250% auto;
    -webkit-background-clip: text; background-clip: text;
    -webkit-text-fill-color: transparent;
    animation: shine 8s linear infinite;
}
@keyframes shine { to { background-position: 250% center; } }

.sub-header { color: #94a3b8; font-size: 1.02rem; margin-bottom: .8rem; }
hr.divider {
    height: 1px; border: none;
    background: linear-gradient(90deg, transparent, rgba(99,102,241,.45), transparent);
    margin: .4rem 0 1.2rem 0;
}

/* ---------- Sidebar ---------- */
div[data-testid="stSidebar"] {
    background:
        radial-gradient(ellipse 100% 30% at 50% 0%, rgba(99,102,241,.12), transparent),
        linear-gradient(180deg, #0b1022 0%, #0d1428 100%);
    border-right: 1px solid rgba(148,163,184,.08);
}
div[data-testid="stSidebar"] * { color: #cbd5e1; }
div[data-testid="stSidebar"] h2, div[data-testid="stSidebar"] h3, div[data-testid="stSidebar"] h4 { color: #f1f5f9 !important; }

/* ---------- Tabs (pill style) ---------- */
.stTabs [data-baseweb="tab-list"] {
    gap: 6px; padding: 5px;
    background: rgba(255,255,255,.03);
    border: 1px solid rgba(148,163,184,.09);
    border-radius: 14px;
}
.stTabs [data-baseweb="tab"] {
    border-radius: 10px; padding: 8px 18px;
    font-weight: 600; font-size: .9rem; color: #94a3b8;
}
.stTabs [data-baseweb="tab"]:hover { color: #e2e8f0; background: rgba(255,255,255,.04); }
.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, rgba(99,102,241,.4), rgba(139,92,246,.4)) !important;
    color: #fff !important;
    box-shadow: 0 2px 14px rgba(99,102,241,.3);
}
.stTabs [data-baseweb="tab-highlight"],
.stTabs [data-baseweb="tab-border"] { display: none; }
.stTabs [data-baseweb="tab-panel"] { padding-top: 1.1rem; }

/* ---------- Inputs ---------- */
.stTextArea textarea {
    background: rgba(255,255,255,.03) !important;
    border: 1px solid rgba(148,163,184,.14) !important;
    border-radius: 12px !important;
    color: #e2e8f0 !important;
    font-family: 'JetBrains Mono', Consolas, monospace !important;
    font-size: .84rem !important;
    transition: border-color .25s, box-shadow .25s;
}
.stTextArea textarea:focus {
    border-color: rgba(99,102,241,.7) !important;
    box-shadow: 0 0 0 3px rgba(99,102,241,.16) !important;
}
div[data-testid="stFileUploaderDropzone"] {
    background: rgba(255,255,255,.03) !important;
    border: 2px dashed rgba(99,102,241,.35) !important;
    border-radius: 14px !important;
    transition: all .25s;
}
div[data-testid="stFileUploaderDropzone"]:hover {
    border-color: rgba(99,102,241,.75) !important;
    background: rgba(99,102,241,.07) !important;
}
div[data-baseweb="select"] > div {
    background: rgba(255,255,255,.04) !important;
    border-color: rgba(148,163,184,.16) !important;
    border-radius: 10px !important;
}
div[data-testid="stMultiSelect"] span[data-baseweb="tag"] {
    background: rgba(99,102,241,.28) !important;
    border-radius: 8px !important;
    color: #c7d2fe !important;
}
div[data-testid="stRadio"] label,
div[data-testid="stCheckbox"] label { color: #cbd5e1; }
div[data-testid="stRadio"] label:hover { color: #f1f5f9; }

/* ---------- Buttons ---------- */
.stDownloadButton button, .stButton button {
    border-radius: 10px !important;
    border: 1px solid rgba(99,102,241,.35) !important;
    background: linear-gradient(135deg, rgba(99,102,241,.2), rgba(139,92,246,.2)) !important;
    color: #e0e7ff !important; font-weight: 600 !important;
    transition: all .25s ease !important;
}
.stDownloadButton button:hover, .stButton button:hover {
    background: linear-gradient(135deg, rgba(99,102,241,.5), rgba(139,92,246,.5)) !important;
    border-color: rgba(99,102,241,.85) !important;
    box-shadow: 0 4px 18px rgba(99,102,241,.35);
    transform: translateY(-1px);
}

/* ---------- Code / Expander / Alert ---------- */
pre, code { font-family: 'JetBrains Mono', Consolas, monospace !important; }
div[data-testid="stExpander"] {
    background: rgba(255,255,255,.02);
    border: 1px solid rgba(148,163,184,.1) !important;
    border-radius: 14px !important;
}
div[data-testid="stExpander"] summary { font-weight: 600; }
div[data-testid="stAlert"] {
    border-radius: 12px;
    border: 1px solid rgba(148,163,184,.12);
}

/* ---------- Stat cards ---------- */
.stat-card {
    position: relative; overflow: hidden; height: 100%;
    background: linear-gradient(160deg, rgba(255,255,255,.05), rgba(255,255,255,.015));
    border: 1px solid rgba(148,163,184,.12);
    border-radius: 16px;
    padding: 1.05rem 1.2rem;
    transition: transform .25s, box-shadow .25s, border-color .25s;
}
.stat-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
    background: linear-gradient(90deg, var(--c1), var(--c2));
}
.stat-card:hover {
    transform: translateY(-3px);
    border-color: rgba(99,102,241,.4);
    box-shadow: 0 10px 30px rgba(0,0,0,.35);
}
.stat-value { font-size: 1.9rem; font-weight: 800; color: #f8fafc; line-height: 1.25; }
.stat-label {
    font-size: .76rem; color: #8b98ad; font-weight: 600;
    text-transform: uppercase; letter-spacing: .08em; margin-top: 2px;
}

/* ---------- Node cards ---------- */
.node-card {
    background: linear-gradient(160deg, rgba(255,255,255,.045), rgba(255,255,255,.01));
    border: 1px solid rgba(148,163,184,.1);
    border-radius: 14px;
    padding: .85rem 1.1rem;
    margin: .6rem 0 .2rem 0;
    transition: border-color .25s, box-shadow .25s;
}
.node-card:hover { border-color: rgba(99,102,241,.45); box-shadow: 0 6px 24px rgba(0,0,0,.3); }
.node-head { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }
.node-idx {
    font-family: 'JetBrains Mono', monospace;
    font-size: .72rem; font-weight: 700; color: #64748b;
    background: rgba(148,163,184,.1);
    border-radius: 6px; padding: 2px 8px;
}
.node-name { font-weight: 600; color: #f1f5f9; font-size: .95rem; }

/* ---------- Badges & chips ---------- */
.badge {
    display: inline-flex; align-items: center;
    padding: 3px 10px; border-radius: 999px;
    font-size: .68rem; font-weight: 700;
    letter-spacing: .06em; text-transform: uppercase; color: #fff;
    box-shadow: 0 2px 8px rgba(0,0,0,.25);
}
.badge-vless  { background: linear-gradient(135deg, #3b82f6, #2563eb); }
.badge-anytls { background: linear-gradient(135deg, #10b981, #059669); }
.badge-trojan { background: linear-gradient(135deg, #f59e0b, #d97706); }
.badge-vmess  { background: linear-gradient(135deg, #8b5cf6, #7c3aed); }
.badge-ss     { background: linear-gradient(135deg, #06b6d4, #0891b2); }
.badge-ssr    { background: linear-gradient(135deg, #6366f1, #4f46e5); }
.badge-hysteria2 { background: linear-gradient(135deg, #ec4899, #db2777); }

.count-pill {
    display: inline-flex; align-items: center;
    background: rgba(99,102,241,.18);
    border: 1px solid rgba(99,102,241,.35);
    color: #c7d2fe; border-radius: 999px;
    font-size: .8rem; font-weight: 700;
    padding: 2px 11px; margin-left: 8px; vertical-align: middle;
}
.chip {
    display: inline-block; padding: 4px 12px; margin: 2px 3px 2px 0;
    border-radius: 999px; font-size: .74rem; font-weight: 600;
    background: rgba(99,102,241,.12);
    border: 1px solid rgba(99,102,241,.25);
    color: #a5b4fc;
}

/* ---------- Feature cards / steps ---------- */
.feature-grid {
    display: grid; gap: .9rem;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    margin: 1rem 0 1.3rem 0;
}
.feature-card {
    background: linear-gradient(160deg, rgba(255,255,255,.045), rgba(255,255,255,.015));
    border: 1px solid rgba(148,163,184,.1);
    border-radius: 14px; padding: 1.15rem;
    transition: transform .25s, border-color .25s;
}
.feature-card:hover { transform: translateY(-3px); border-color: rgba(99,102,241,.4); }
.feature-icon { font-size: 1.5rem; margin-bottom: .45rem; }
.feature-title { font-weight: 700; color: #f1f5f9; font-size: .95rem; margin-bottom: .3rem; }
.feature-desc { color: #94a3b8; font-size: .83rem; line-height: 1.55; }

@keyframes fadeUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: none; } }
.fade-in { animation: fadeUp .45s ease both; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

EXAMPLE_YAML = """proxies:
  - name: "🇭🇰 HK Reality"
    type: vless
    server: example.com
    port: 443
    uuid: b8e1f6a2-1234-5678-9abc-def012345678
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: example.com
    reality-opts:
      public-key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
      short-id: "0123abcd"
    client-fingerprint: chrome

  - name: "🇯🇵 JP anytls"
    type: anytls
    server: jp.example.com
    port: 443
    password: my-secret-password
    sni: jp.example.com
    skip-cert-verify: false
"""

# ============================================================
# Sidebar
# ============================================================

with st.sidebar:
    st.markdown("## ⚙️ Settings")
    st.markdown('<hr class="divider">', unsafe_allow_html=True)

    st.caption("PROTOCOLS")
    selected_types = st.multiselect(
        "Types to convert",
        options=["vless", "anytls", "trojan", "vmess", "hysteria2"],
        default=["vless", "anytls", "trojan", "hysteria2"],
        label_visibility="collapsed",
    )

    st.markdown("<div style='height:.6rem'></div>", unsafe_allow_html=True)
    st.caption("OUTPUT")
    output_mode = st.radio(
        "Mode",
        options=["🔗 Share Links", "📦 Base64 Subscription"],
        index=0,
        label_visibility="collapsed",
    )

    st.markdown("<div style='height:.6rem'></div>", unsafe_allow_html=True)
    st.caption("DISPLAY")
    show_names = st.checkbox("Show node names", value=True)
    show_type_badge = st.checkbox("Show protocol badge", value=True)

    st.markdown('<hr class="divider">', unsafe_allow_html=True)
    st.markdown("#### 📦 Supported Protocols")
    st.markdown(
        '<span class="chip">VLESS · Reality</span>'
        '<span class="chip">anytls</span>'
        '<span class="chip">Trojan</span>'
        '<span class="chip">VMess</span>'
        '<span class="chip">SS</span>'
        '<span class="chip">SSR</span>'
        '<span class="chip">Hysteria2</span>',
        unsafe_allow_html=True,
    )
    st.caption("Reality / Vision · WebSocket · gRPC")

    st.markdown('<hr class="divider">', unsafe_allow_html=True)
    st.caption("🔒 Made for Clash Meta / Mihomo · Everything runs locally")

# ============================================================
# Hero
# ============================================================

st.markdown("""
<div class="fade-in">
    <div class="main-header">🔗 Clash → Share Link Converter</div>
    <div class="sub-header">
        Turn Clash / Mihomo YAML configs into standard share links —
        <span class="chip">vless://</span><span class="chip">anytls://</span><span class="chip">trojan://</span><span class="chip">vmess://</span>
    </div>
</div>
<hr class="divider">
""", unsafe_allow_html=True)

# ============================================================
# Input
# ============================================================

sub_tab, tab1, tab2 = st.tabs([
    "� Import Subscription",
    "� Upload YAML File",
    "📝 Paste YAML Content",
])

subscription_content = None
yaml_content = None

with sub_tab:
    st.caption(
        "Enter a subscription URL or paste subscription content "
        "(Base64 blob / share links / Clash YAML). It will be converted into Clash YAML."
    )
    sub_url = st.text_input(
        "Subscription URL",
        placeholder="https://example.com/sub?token=xxxx",
        label_visibility="collapsed",
    )
    if st.button("⬇️ Fetch subscription", use_container_width=True):
        if sub_url.strip():
            with st.spinner("Fetching subscription..."):
                try:
                    subscription_content = fetch_subscription_url(sub_url.strip())
                    st.success("Subscription fetched successfully.", icon="✅")
                except ValueError as e:
                    st.error(str(e), icon="🚫")
        else:
            st.warning("Please enter a subscription URL.", icon="⚠️")

    st.markdown("<div style='height:.5rem'></div>", unsafe_allow_html=True)
    st.caption("OR PASTE SUBSCRIPTION CONTENT")
    sub_pasted = st.text_area(
        "Subscription content",
        height=180,
        label_visibility="collapsed",
        placeholder="vless://...\nvmess://...\n( or a Base64 blob )",
    )
    if sub_pasted.strip():
        subscription_content = sub_pasted

with tab1:
    uploaded_file = st.file_uploader(
        "Upload your Clash config.yaml",
        type=["yaml", "yml"],
        label_visibility="collapsed",
        help="Standard Clash / Clash Meta / Mihomo configs",
    )
    if uploaded_file is not None:
        yaml_content = uploaded_file.read().decode("utf-8")

with tab2:
    pasted = st.text_area(
        "YAML content",
        height=280,
        label_visibility="collapsed",
        placeholder="proxies:\n  - name: ...\n    type: vless\n    ...",
    )
    if pasted.strip():
        yaml_content = pasted

# ============================================================
# Processing & Output
# ============================================================

if subscription_content:
    try:
        proxies, parse_errors = parse_subscription(subscription_content)
        if not proxies:
            st.error("No valid proxies were found in the subscription.", icon="🚫")
            if parse_errors:
                with st.expander("🔍 Details"):
                    for e in parse_errors:
                        st.write(f"- {e}")
            st.stop()

        clash_yaml = build_clash_yaml(proxies)

        # ---- Stat cards ----
        type_count: Dict[str, int] = {}
        for p in proxies:
            t = str(p.get("type", "unknown")).upper()
            type_count[t] = type_count.get(t, 0) + 1

        cards = [
            ("🔗", "Total Nodes", len(proxies), "#6366f1", "#8b5cf6"),
            ("⚡", "VLESS", type_count.get("VLESS", 0), "#3b82f6", "#60a5fa"),
            ("🛡️", "Trojan / VMess",
             type_count.get("TROJAN", 0) + type_count.get("VMESS", 0),
             "#f59e0b", "#f97316"),
            ("🧩", "SS / SSR / Hysteria2",
             type_count.get("SS", 0) + type_count.get("SSR", 0) + type_count.get("HYSTERIA2", 0),
             "#10b981", "#34d399"),
        ]
        cols = st.columns(4)
        for col, (icon, label, value, c1, c2) in zip(cols, cards):
            col.markdown(
                f"""<div class="stat-card" style="--c1:{c1};--c2:{c2}">
                        <div class="stat-value">{value}</div>
                        <div class="stat-label">{icon} &nbsp;{label}</div>
                    </div>""",
                unsafe_allow_html=True,
            )

        st.markdown('<hr class="divider">', unsafe_allow_html=True)

        head_col, btn_col = st.columns([0.72, 0.28])
        head_col.markdown(
            f'### 📄 Clash YAML <span class="count-pill">{len(proxies)}</span>',
            unsafe_allow_html=True,
        )
        btn_col.download_button(
            "⬇️  Download config.yaml", clash_yaml,
            "config.yaml", "text/yaml", use_container_width=True,
        )
        st.code(clash_yaml, language="yaml")
        st.info(
            "Import this YAML into Clash Meta / Mihomo, or convert it back to share links "
            "using the other tabs.", icon="💡",
        )

        if parse_errors:
            st.warning(f"{len(parse_errors)} link(s) could not be parsed.", icon="⚠️")
            with st.expander("🔍 Unparsed / unsupported links"):
                for e in parse_errors:
                    st.write(f"- {e}")

        with st.expander(f"🔍 Parsed nodes ({len(proxies)})", expanded=len(proxies) <= 6):
            for i, p in enumerate(proxies, 1):
                ptype = str(p.get("type", "unknown")).lower()
                badge = (
                    f'<span class="badge badge-{ptype}">{str(p.get("type", "unknown")).upper()}</span>'
                    if show_type_badge else ""
                )
                name = (
                    f'<span class="node-name">{html.escape(str(p.get("name", "Unknown")))}</span>'
                    if show_names else ""
                )
                st.markdown(
                    f'<div class="node-card"><div class="node-head">'
                    f'<span class="node-idx">#{i:02d}</span>{badge}{name}'
                    f"</div></div>",
                    unsafe_allow_html=True,
                )
                st.code(yaml.safe_dump([p], allow_unicode=True, sort_keys=False), language="yaml")

    except (ValueError, yaml.YAMLError) as e:
        st.error(f"Subscription error: `{e}`")
    except Exception as e:
        st.error(f"Unexpected error: `{e}`")

elif yaml_content:
    try:
        data = yaml.safe_load(yaml_content)
        if not isinstance(data, dict):
            st.error("Invalid YAML structure. Expected a dictionary (Clash config).")
            st.stop()

        proxies = data.get("proxies") or []
        if not proxies:
            st.warning("No `proxies` section found in the YAML.", icon="⚠️")
            st.stop()

        if not selected_types:
            st.warning("Select at least one protocol type in the sidebar.", icon="⚠️")
            st.stop()

        results = convert_proxies(proxies, selected_types)
        if not results:
            st.warning("No matching proxies found for the selected types.", icon="🔍")
            st.stop()

        # ---- Stat cards ----
        type_count: Dict[str, int] = {}
        for r in results:
            type_count[r["type"]] = type_count.get(r["type"], 0) + 1

        cards = [
            ("🔗", "Total Nodes", len(results), "#6366f1", "#8b5cf6"),
            ("⚡", "VLESS", type_count.get("VLESS", 0), "#3b82f6", "#60a5fa"),
            ("🛡️", "anytls", type_count.get("ANYTLS", 0), "#10b981", "#34d399"),
            ("🔒", "Trojan / VMess",
             type_count.get("TROJAN", 0) + type_count.get("VMESS", 0),
             "#f59e0b", "#f97316"),
            ("🌐", "Hysteria2",
             type_count.get("HYSTERIA2", 0),
             "#ec4899", "#f472b6"),
        ]
        cols = st.columns(5)
        for col, (icon, label, value, c1, c2) in zip(cols, cards):
            col.markdown(
                f"""<div class="stat-card" style="--c1:{c1};--c2:{c2}">
                        <div class="stat-value">{value}</div>
                        <div class="stat-label">{icon} &nbsp;{label}</div>
                    </div>""",
                unsafe_allow_html=True,
            )

        st.markdown('<hr class="divider">', unsafe_allow_html=True)

        all_links = "\n".join(r["link"] for r in results)

        if output_mode == "🔗 Share Links":
            head_col, btn_col = st.columns([0.72, 0.28])
            head_col.markdown(
                f'### 📋 Share Links <span class="count-pill">{len(results)}</span>',
                unsafe_allow_html=True,
            )
            btn_col.download_button(
                "⬇️  Download all (.txt)", all_links,
                "share_links.txt", "text/plain", use_container_width=True,
            )

            st.code(all_links, language="text")

            with st.expander(f"🔍 Individual nodes ({len(results)})", expanded=len(results) <= 6):
                for i, r in enumerate(results, 1):
                    badge = (
                        f'<span class="badge badge-{r["type"].lower()}">{r["type"]}</span>'
                        if show_type_badge else ""
                    )
                    name = (
                        f'<span class="node-name">{html.escape(str(r["name"]))}</span>'
                        if show_names else ""
                    )
                    st.markdown(
                        f'<div class="node-card"><div class="node-head">'
                        f'<span class="node-idx">#{i:02d}</span>{badge}{name}'
                        f"</div></div>",
                        unsafe_allow_html=True,
                    )
                    st.code(r["link"], language="text")

        else:  # Base64 Subscription
            b64 = base64.b64encode(all_links.encode("utf-8")).decode("utf-8")

            head_col, btn_col = st.columns([0.72, 0.28])
            head_col.markdown("### 📦 Base64 Subscription", unsafe_allow_html=True)
            btn_col.download_button(
                "⬇️  Download subscription", b64,
                "subscription.txt", "text/plain", use_container_width=True,
            )

            st.code(b64, language="text")
            st.info(
                "Paste this Base64 string into any client that supports subscription imports "
                "(v2rayN, NekoBox, Hiddify, Clash Meta…).", icon="💡",
            )

            with st.expander("🔍 Preview decoded links"):
                st.code(all_links, language="text")

    except yaml.YAMLError as e:
        st.error(f"YAML parsing error:\n\n```\n{e}\n```")
    except Exception as e:
        st.error(f"Unexpected error: `{e}`")

else:
    # ---------- Empty state ----------
    st.info("Import a subscription, upload a Clash YAML file, or paste YAML content in a tab above to get started.", icon="✨")

    st.markdown("""
    <div class="fade-in">
        <div class="feature-grid">
            <div class="feature-card">
                <div class="feature-icon">📁</div>
                <div class="feature-title">1 · Provide Config</div>
                <div class="feature-desc">Upload your <b>Clash / Mihomo</b> <code>config.yaml</code> or paste the <code>proxies:</code> section directly.</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🎛️</div>
                <div class="feature-title">2 · Pick Protocols</div>
                <div class="feature-desc">Choose VLESS, anytls, Trojan and/or VMess in the sidebar — only matching nodes are converted.</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🔗</div>
                <div class="feature-title">3 · Copy &amp; Import</div>
                <div class="feature-desc">Grab plain share links or a Base64 subscription and import into v2rayN, NekoBox, Hiddify…</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    with st.expander("📖 Example YAML"):
        st.code(EXAMPLE_YAML, language="yaml")

st.markdown('<hr class="divider">', unsafe_allow_html=True)
st.caption("🔒 All processing happens locally in your browser · Built with Streamlit")