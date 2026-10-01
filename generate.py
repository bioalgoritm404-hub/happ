import base64
import json
import re
import socket
import urllib.parse
import uuid
import requests

SUBS_FILE = "my_subs.json"
MAX_NODES_PER_FILE = 80
ALLOWED_NETWORKS = {"tcp", "raw", "grpc", "ws", "websocket", "xhttp", "splithttp"}

def is_valid_uuid(val):
    try:
        uuid.UUID(str(val))
        return True
    except Exception:
        return False

def clean(val):
    if not val:
        return ""
    return re.sub(r"\s+", "", str(val))

def get_clean_links():
    with open(SUBS_FILE, "r", encoding="utf-8") as f:
        subs = json.load(f).get("subscriptions", [])

    raw_links = []
    headers = {"User-Agent": "Happ/1.3.0"}

    for url in subs:
        try:
            r = requests.get(url, headers=headers, timeout=12)
            if r.status_code == 200:
                content = r.text.strip()
                if not any(content.startswith(p) for p in ["vless://", "vmess://"]):
                    try:
                        content = base64.b64decode(content).decode("utf-8", errors="ignore")
                    except Exception:
                        pass
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("vless://"):
                        raw_links.append(line)
        except Exception as e:
            print(f"Ошибка загрузки {url}: {e}")

    return list(dict.fromkeys(raw_links))

def resolve_ip(host):
    try:
        socket.inet_aton(host)
        return host
    except socket.error:
        try:
            return socket.gethostbyname(host)
        except Exception:
            return None

def fetch_countries(ips):
    ip_to_country = {}
    unique_ips = list(set(filter(None, ips)))
    for i in range(0, len(unique_ips), 100):
        chunk = unique_ips[i:i+100]
        payload = [{"query": ip, "fields": "query,countryCode"} for ip in chunk]
        try:
            res = requests.post("http://ip-api.com/batch", json=payload, timeout=10)
            if res.status_code == 200:
                for item in res.json():
                    ip_to_country[item.get("query")] = item.get("countryCode", "UNKNOWN")
        except Exception:
            pass
    return ip_to_country

def parse_node(link, tag):
    try:
        u = urllib.parse.urlsplit(link)
        uid = clean(u.username)
        host = clean(u.hostname)
        port = int(u.port or 443)

        if not uid or not is_valid_uuid(uid) or not host:
            return None, None

        params = dict(urllib.parse.parse_qsl(u.query))
        raw_net = clean(params.get("type", "tcp")).lower()
        if raw_net not in ALLOWED_NETWORKS:
            return None, None

        if raw_net in ["tcp", "raw"]:
            network = "raw"
        elif raw_net == "grpc":
            network = "grpc"
        elif raw_net in ["xhttp", "splithttp"]:
            network = "xhttp"
        elif raw_net in ["ws", "websocket"]:
            network = "ws"
        else:
            return None, None

        sec = clean(params.get("security", "none")).lower()
        flow = clean(params.get("flow", ""))

        if sec == "reality":
            pbk = clean(params.get("pbk", ""))
            if not pbk or len(pbk) < 42 or len(pbk) > 45:
                return None, None

        user_entry = {"id": uid, "encryption": "none"}
        if flow:
            user_entry["flow"] = flow
        elif sec == "reality" and network == "raw":
            user_entry["flow"] = "xtls-rprx-vision"

        sockopt = {"tcpKeepAliveIdle": 300, "tcpKeepAliveInterval": 60}
        if network in ["raw", "ws"]:
            sockopt["dialerProxy"] = "fragment"

        outbound = {
            "protocol": "vless",
            "tag": tag,
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [user_entry]
                }]
            },
            "streamSettings": {
                "network": network,
                "security": sec,
                "sockopt": sockopt
            }
        }

        if sec == "reality":
            outbound["streamSettings"]["realitySettings"] = {
                "fingerprint": clean(params.get("fp", "chrome")),
                "publicKey": clean(params.get("pbk", "")),
                "serverName": clean(params.get("sni", host)),
                "shortId": clean(params.get("sid", ""))
            }
        elif sec == "tls":
            outbound["streamSettings"]["tlsSettings"] = {
                "fingerprint": clean(params.get("fp", "chrome")),
                "serverName": clean(params.get("sni", host))
            }
            if params.get("alpn"):
                outbound["streamSettings"]["tlsSettings"]["alpn"] = [
                    clean(x) for x in params.get("alpn").split(",") if clean(x)
                ]

        if network == "grpc":
            outbound["streamSettings"]["grpcSettings"] = {
                "multiMode": False,
                "serviceName": clean(params.get("serviceName", "grpc-tunnel"))
            }
        elif network == "xhttp":
            p = params.get("path", "/")
            outbound["streamSettings"]["xhttpSettings"] = {
                "mode": clean(params.get("mode", "auto")),
                "path": p if p.startswith("/") else f"/{p}"
            }
        elif network == "ws":
            p = params.get("path", "/")
            outbound["streamSettings"]["wsSettings"] = {
                "path": p if p.startswith("/") else f"/{p}",
                "headers": {"Host": clean(params.get("host", host))}
            }
        elif network == "raw":
            outbound["streamSettings"]["rawSettings"] = {"header": {"type": "none"}}

        return outbound, host
    except Exception:
        return None, None

def build_full_config(nodes, config_name):
    first_node = nodes[0]["tag"]

    return {
        "_meta": {
            "client": "Happ",
            "generator": "Clean Balancer Generator",
            "name": config_name
        },
        "dns": {
            "disableCache": False,
            "queryStrategy": "UseIPv4",
            "serveStale": True,
            "servers": [
                {
                    "address": "77.88.8.8",
                    "port": 53,
                    "domains": ["domain:ru", "domain:su", "domain:xn--p1ai"],
                    "skipFallback": True
                },
                "1.1.1.1",
                "8.8.8.8"
            ],
            "tag": "dns-remote"
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True},
                "tag": "socks-in"
            },
            {
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {},
                "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True},
                "tag": "http-in"
            },
            {
                "listen": "127.0.0.1",
                "port": 10853,
                "protocol": "dokodemo-door",
                "settings": {"address": "1.1.1.1", "network": "tcp,udp", "port": 53},
                "tag": "dns-in"
            }
        ],
        "log": {"loglevel": "warning"},
        "observatory": {
            "enableConcurrency": True,
            "probeInterval": "3m",
            "probeURL": "https://www.gstatic.com/generate_204",
            "subjectSelector": ["node-"]
        },
        "outbounds": nodes + [
            {
                "protocol": "freedom",
                "tag": "fragment",
                "settings": {
                    "fragment": {
                        "interval": "10-20",
                        "length": "50-100",
                        "maxSplit": "10",
                        "packets": "1-3"
                    },
                    "noises": [{"delay": "10-50", "packet": "50-150", "type": "rand"}]
                }
            },
            {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "UseIPv4"}},
            {"protocol": "blackhole", "tag": "block", "settings": {"response": {"type": "http"}}},
            {"protocol": "dns", "tag": "dns-out", "settings": {"network": "tcp,udp"}}
        ],
        "routing": {
            "domainMatcher": "hybrid",
            "domainStrategy": "IPIfNonMatch",
            "balancers": [
                {
                    "fallbackTag": first_node,
                    "selector": ["node-"],
                    "strategy": {"type": "leastPing"},
                    "tag": "auto-balancer"
                }
            ],
            "rules": [
                {"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"},
                {"inboundTag": ["dns-remote"], "outboundTag": "direct", "type": "field"},
                {"domain": ["full:localhost", "domain:local", "domain:lan", "regexp:^[^.]+$"], "outboundTag": "direct", "type": "field"},
                {"ip": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"], "outboundTag": "direct", "type": "field"},
                {"balancerTag": "auto-balancer", "network": "tcp,udp", "type": "field"}
            ]
        }
    }

def main():
    links = get_clean_links()
    parsed = []
    hosts = []

    for link in links:
        node, host = parse_node(link, "temp")
        if node and host:
            parsed.append((node, host))
            hosts.append(host)

    host_to_ip = {}
    for h in set(hosts):
        ip = resolve_ip(h)
        if ip:
            host_to_ip[h] = ip

    ip_to_country = fetch_countries(list(host_to_ip.values()))

    world_nodes = []
    ru_nodes = []

    for node, host in parsed:
        ip = host_to_ip.get(host)
        country = ip_to_country.get(ip, "UNKNOWN")

        if country == "RU":
            if len(ru_nodes) < MAX_NODES_PER_FILE:
                n = dict(node)
                n["tag"] = f"node-{len(ru_nodes)+1:03d}"
                ru_nodes.append(n)
        else:
            if len(world_nodes) < MAX_NODES_PER_FILE:
                n = dict(node)
                n["tag"] = f"node-{len(world_nodes)+1:03d}"
                world_nodes.append(n)

    if world_nodes:
        cfg = build_full_config(world_nodes, "Зарубежные — Auto Select GLOBAL")
        with open("happ_auto.json", "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        print(f"Зарубежные: {len(world_nodes)} нод.")

    if ru_nodes:
        cfg = build_full_config(ru_nodes, "Россия — Auto Select WhiteLists")
        with open("happ_ru.json", "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        print(f"Россия: {len(ru_nodes)} нод.")

if __name__ == "__main__":
    main()
