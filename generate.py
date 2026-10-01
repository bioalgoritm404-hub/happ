import base64
import json
import re
import urllib.parse
import uuid
import requests

SUBS_FILE = "my_subs.json"
OUTPUT_FILE = "happ_auto.json"
MAX_NODES = 100

def is_valid_uuid(val):
    try:
        uuid.UUID(str(val))
        return True
    except Exception:
        return False

def clean_str(s):
    """Убирает пробелы, переносы строк и спецсимволы, ломающие base64"""
    if not s:
        return ""
    return re.sub(r"\s+", "", s)

def get_links():
    with open(SUBS_FILE, "r", encoding="utf-8") as f:
        subs = json.load(f).get("subscriptions", [])

    raw_links = []
    headers = {"User-Agent": "Happ/1.3.0"}

    for url in subs:
        try:
            resp = requests.get(url, headers=headers, timeout=12)
            if resp.status_code == 200:
                text = resp.text.strip()
                if not any(text.startswith(p) for p in ["vless://", "vmess://"]):
                    try:
                        text = base64.b64decode(text).decode("utf-8", errors="ignore")
                    except Exception:
                        pass
                
                for line in text.splitlines():
                    line = line.strip()
                    # Берем ТОЛЬКО чистый VLESS (Hysteria отсекаем, так как Xray её не поддерживает)
                    if line.startswith("vless://"):
                        raw_links.append(line)
        except Exception as e:
            print(f"Ошибка загрузки {url}: {e}")

    return list(dict.fromkeys(raw_links))

def parse_vless(url_str, tag):
    try:
        u = urllib.parse.urlsplit(url_str)
        user_id = clean_str(u.username)
        host = u.hostname
        port = int(u.port or 443)

        if not user_id or not is_valid_uuid(user_id) or not host:
            return None

        params = dict(urllib.parse.parse_qsl(u.query))
        net_type = params.get("type", "tcp")
        security = params.get("security", "none")
        flow = clean_str(params.get("flow", ""))

        user_obj = {"id": user_id, "encryption": "none"}
        if flow:
            user_obj["flow"] = flow
        elif security == "reality" and net_type in ["tcp", "raw"]:
            # Для TCP Reality в Xray обязательно нужен flow vision
            user_obj["flow"] = "xtls-rprx-vision"

        outbound = {
            "protocol": "vless",
            "tag": tag,
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [user_obj]
                }]
            },
            "streamSettings": {
                "network": "raw" if net_type == "tcp" else net_type,
                "security": security,
                "sockopt": {
                    "dialerProxy": "fragment",
                    "tcpKeepAliveIdle": 300,
                    "tcpKeepAliveInterval": 60
                }
            }
        }

        if security == "reality":
            pbk = clean_str(params.get("pbk", ""))
            # Валидный X25519 публичный ключ должен быть ровно 43 или 44 символа
            if not pbk or len(pbk) < 42 or len(pbk) > 45:
                return None

            outbound["streamSettings"]["realitySettings"] = {
                "fingerprint": clean_str(params.get("fp", "chrome")),
                "publicKey": pbk,
                "serverName": clean_str(params.get("sni", host)),
                "shortId": clean_str(params.get("sid", ""))
            }
        elif security == "tls":
            outbound["streamSettings"]["tlsSettings"] = {
                "fingerprint": clean_str(params.get("fp", "chrome")),
                "serverName": clean_str(params.get("sni", host))
            }

        if net_type == "grpc":
            outbound["streamSettings"]["grpcSettings"] = {
                "multiMode": False,
                "serviceName": clean_str(params.get("serviceName", ""))
            }
        elif net_type == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": params.get("path", "/"),
                "headers": {"Host": clean_str(params.get("host", host))}
            }
        elif net_type == "xhttp":
            outbound["streamSettings"]["xhttpSettings"] = {
                "mode": clean_str(params.get("mode", "auto")),
                "path": params.get("path", "/")
            }
        elif net_type in ["tcp", "raw"]:
            outbound["streamSettings"]["rawSettings"] = {
                "header": {"type": "none"}
            }

        return outbound
    except Exception:
        return None

def build_config(outbounds):
    first_node = outbounds[0]["tag"] if outbounds else "direct"
    
    extra = [
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
    ]

    return {
        "_meta": {
            "client": "Happ",
            "generator": "Clean Balancer Generator",
            "name": "Auto-Select Balancer"
        },
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": [
                "https://dns.google/dns-query",
                "https://cloudflare-dns.com/dns-query",
                "https://77.88.8.8/dns-query"
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
        "outbounds": outbounds + extra,
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
                    "domain": [
                        "full:localhost",
                        "domain:local",
                        "domain:lan",
                        "regexp:^[^.]+$"
                    ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "ip": [
                        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
                        "192.168.0.0/16", "100.64.0.0/10"
                    ],
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
    links = get_links()
    outbounds = []
    
    for link in links:
        tag = f"node-{len(outbounds)+1:03d}"
        parsed = parse_vless(link, tag)
        if parsed:
            outbounds.append(parsed)
        if len(outbounds) >= MAX_NODES:
            break

    if not outbounds:
        print("Не найдено рабочих VLESS нод.")
        return

    full_cfg = build_config(outbounds)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(full_cfg, f, ensure_ascii=False, indent=2)

    print(f"Готово! Собрано {len(outbounds)} чистых VLESS серверов.")

if __name__ == "__main__":
    main()
