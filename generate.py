import base64
import json
import re
import urllib.parse
import uuid
import requests

SUBS_FILE = "my_subs.json"
OUTPUT_FILE = "happ_auto.json"
MAX_NODES = 90

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
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                content = r.text.strip()
                if not content.startswith("vless://"):
                    try:
                        content = base64.b64decode(content).decode("utf-8", errors="ignore")
                    except Exception:
                        pass
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("vless://"):
                        raw_links.append(line)
        except Exception:
            pass

    return list(dict.fromkeys(raw_links))

def parse_node(link, tag):
    try:
        u = urllib.parse.urlsplit(link)
        uid = clean(u.username)
        host = clean(u.hostname)
        port = int(u.port or 443)

        # Отсекаем невалидные UUID и пустые хосты
        if not uid or not is_valid_uuid(uid) or not host:
            return None

        params = dict(urllib.parse.parse_qsl(u.query))
        net = clean(params.get("type", "tcp")).lower()
        sec = clean(params.get("security", "none")).lower()
        flow = clean(params.get("flow", ""))

        # ЖЕСТКИЙ ФИЛЬТР: Никакого старого http/h2, quic или kcp!
        if net in ["tcp", "raw"]:
            network = "raw"
        elif net == "grpc":
            network = "grpc"
        elif net in ["xhttp", "splithttp"]:
            network = "xhttp"
        elif net in ["ws", "websocket"]:
            network = "ws"
        else:
            return None  # Любой старый транспорт сразу бракуется

        # Проверка Reality ключа
        if sec == "reality":
            pbk = clean(params.get("pbk", ""))
            # Валидный X25519 ключ строго от 42 до 44 символов без пробелов
            if not pbk or len(pbk) < 42 or len(pbk) > 45:
                return None

        user_entry = {"id": uid, "encryption": "none"}
        if flow:
            user_entry["flow"] = flow
        elif sec == "reality" and network == "raw":
            user_entry["flow"] = "xtls-rprx-vision"

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
                "sockopt": {
                    "tcpKeepAliveIdle": 300,
                    "tcpKeepAliveInterval": 60
                }
            }
        }

        # Fragment подключаем только для TCP и WS (для gRPC и xhttp он ломает стрим)
        if network in ["raw", "ws"]:
            outbound["streamSettings"]["sockopt"]["dialerProxy"] = "fragment"

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
            outbound["streamSettings"]["rawSettings"] = {
                "header": {"type": "none"}
            }

        return outbound
    except Exception:
        return None

def build_full_config(nodes):
    first_node = nodes[0]["tag"]

    return {
        "_meta": {
            "client": "Happ",
            "generator": "Clean Balancer Generator",
            "name": "Auto-Select Balancer"
        },
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": [
                "https+local://common.dot.dns.yandex.net/dns-query",
                "tcp+local://77.88.8.8:53",
                "https://dns.google/dns-query",
                "https://cloudflare-dns.com/dns-query"
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
                {
                    "inboundTag": ["dns-remote"],
                    "balancerTag": "auto-balancer",
                    "type": "field"
                },
                {
                    "domain": ["full:localhost", "domain:local", "domain:lan", "regexp:^[^.]+$"],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "ip": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "balancerTag": "auto-balancer",
                    "network": "tcp,udp",
                    "type": "field"
                }
            ]
        }
    }

def main():
    raw_links = get_clean_links()
    valid_nodes = []

    for link in raw_links:
        tag = f"node-{len(valid_nodes)+1:03d}"
        node = parse_node(link, tag)
        if node:
            valid_nodes.append(node)
        if len(valid_nodes) >= MAX_NODES:
            break

    if not valid_nodes:
        print("Не найдено подходящих нод.")
        return

    config = build_full_config(valid_nodes)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    print(f"Готово: отобрано {len(valid_nodes)} валидных серверов.")

if __name__ == "__main__":
    main()
