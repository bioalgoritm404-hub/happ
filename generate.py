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
    except (ValueError, AttributeError, TypeError):
        return False

def get_links():
    with open(SUBS_FILE, "r", encoding="utf-8") as f:
        subs = json.load(f).get("subscriptions", [])

    raw_links = []
    headers = {"User-Agent": "Happ/1.3.0 (Windows NT 10.0; Win64; x64)"}

    for url in subs:
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                text = resp.text.strip()
                # Раскодируем base64, если подписка закодирована целиком
                if not any(text.startswith(p) for p in ["vless://", "vmess://", "trojan://", "ss://", "hy2://", "hysteria2://"]):
                    try:
                        text = base64.b64decode(text).decode("utf-8", errors="ignore")
                    except Exception:
                        pass
                
                for line in text.splitlines():
                    line = line.strip()
                    if line.startswith("vless://"):
                        raw_links.append(line)
        except Exception as e:
            print(f"Ошибка загрузки {url}: {e}")

    # Удаляем дубликаты
    return list(dict.fromkeys(raw_links))

def parse_vless(url_str, tag):
    try:
        u = urllib.parse.urlsplit(url_str)
        user_id = u.username
        host = u.hostname
        port = int(u.port or 443)

        # Отсекаем ссылки с битым UUID (из-за которого падало ядро)
        if not user_id or not is_valid_uuid(user_id):
            return None

        if not host:
            return None

        params = dict(urllib.parse.parse_qsl(u.query))
        net_type = params.get("type", "tcp")
        security = params.get("security", "none")
        flow = params.get("flow", "")

        user_obj = {
            "id": user_id,
            "encryption": "none"
        }
        if flow:
            user_obj["flow"] = flow

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
            pbk = params.get("pbk", "")
            if not pbk:
                return None
            outbound["streamSettings"]["realitySettings"] = {
                "fingerprint": params.get("fp", "chrome"),
                "publicKey": pbk,
                "serverName": params.get("sni", host),
                "shortId": params.get("sid", "")
            }
        elif security == "tls":
            tls = {
                "fingerprint": params.get("fp", "chrome"),
                "serverName": params.get("sni", host)
            }
            if params.get("alpn"):
                tls["alpn"] = params.get("alpn").split(",")
            outbound["streamSettings"]["tlsSettings"] = tls

        if net_type == "grpc":
            outbound["streamSettings"]["grpcSettings"] = {
                "multiMode": False,
                "serviceName": params.get("serviceName", "")
            }
        elif net_type == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": params.get("path", "/"),
                "headers": {"Host": params.get("host", params.get("sni", host))}
            }
        elif net_type == "xhttp":
            outbound["streamSettings"]["xhttpSettings"] = {
                "mode": params.get("mode", "auto"),
                "path": params.get("path", "/")
            }
        elif net_type == "tcp":
            outbound["streamSettings"]["rawSettings"] = {
                "header": {"type": params.get("headerType", "none")}
            }

        return outbound
    except Exception:
        return None

def build_config(outbounds):
    first_node_tag = outbounds[0]["tag"] if outbounds else "direct"
    
    extra_outbounds = [
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
                "noises": [
                    {"delay": "10-50", "packet": "50-150", "type": "rand"}
                ]
            }
        },
        {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "UseIPv4"}},
        {"protocol": "blackhole", "tag": "block", "settings": {"response": {"type": "http"}}},
        {"protocol": "dns", "tag": "dns-out", "settings": {"network": "tcp,udp"}}
    ]

    return {
        "_meta": {
            "client": "Happ",
            "generator": "Custom Balancer Generator",
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
        "outbounds": outbounds + extra_outbounds,
        "routing": {
            "domainMatcher": "hybrid",
            "domainStrategy": "IPIfNonMatch",
            "balancers": [
                {
                    "fallbackTag": first_node_tag,
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
        print("Ошибка: не найдено ни одного валидного VLESS сервера.")
        return

    full_cfg = build_config(outbounds)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(full_cfg, f, ensure_ascii=False, indent=2)

    print(f"Готово! Собрано {len(outbounds)} валидных серверов.")

if __name__ == "__main__":
    main()
