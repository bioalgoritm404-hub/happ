import base64
import json
import re
import urllib.parse
import uuid
import requests

SUBS_FILE = "my_subs.json"
OUTPUT_FILE = "happ_auto.json"
MAX_NODES = 100

# Разрешаем ТОЛЬКО проверенные и актуальные для Xray 26+ транспорты
ALLOWED_NETWORKS = {"tcp", "raw", "grpc", "ws", "websocket", "xhttp", "splithttp"}

def is_valid_uuid(val):
    try:
        uuid.UUID(str(val))
        return True
    except Exception:
        return False

def clean_str(s):
    if not s:
        return ""
    return re.sub(r"\s+", "", str(s))

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
                    if line.startswith("vless://"):
                        raw_links.append(line)
        except Exception as e:
            print(f"Ошибка загрузки {url}: {e}")

    return list(dict.fromkeys(raw_links))

def parse_vless(url_str, tag):
    try:
        u = urllib.parse.urlsplit(url_str)
        user_id = clean_str(u.username)
        host = clean_str(u.hostname)
        port = int(u.port or 443)

        if not user_id or not is_valid_uuid(user_id) or not host:
            return None

        params = dict(urllib.parse.parse_qsl(u.query))
        raw_net = clean_str(params.get("type", "tcp")).lower()

        # Блокируем древний HTTP transport (H2), quic и kcp
        if raw_net not in ALLOWED_NETWORKS:
            return None

        # Нормализация названий транспортов для Xray
        if raw_net in ["tcp", "raw"]:
            net_type = "raw"
        elif raw_net in ["ws", "websocket"]:
            net_type = "ws"
        elif raw_net in ["xhttp", "splithttp"]:
            net_type = "xhttp"
        elif raw_net == "grpc":
            net_type = "grpc"
        else:
            return None

        security = clean_str(params.get("security", "none"))
        flow = clean_str(params.get("flow", ""))

        user_obj = {"id": user_id, "encryption": "none"}
        if flow:
            user_obj["flow"] = flow
        elif security == "reality" and net_type == "raw":
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
                "network": net_type,
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
            if not pbk or len(pbk) < 42 or len(pbk) > 45:
                return None

            outbound["streamSettings"]["realitySettings"] = {
                "fingerprint": clean_str(params.get("fp", "chrome")),
                "publicKey": pbk,
                "serverName": clean_str(params.get("sni", host)),
                "shortId": clean_str(params.get("sid", ""))
            }
        elif security == "tls":
            tls = {
                "fingerprint": clean_str(params.get("fp", "chrome")),
                "serverName": clean_str(params.get("sni", host))
            }
            if params.get("alpn"):
                tls["alpn"] = [clean_str(x) for x in params.get("alpn").split(",") if clean_str(x)]
            outbound["streamSettings"]["tlsSettings"] = tls

        if net_type == "grpc":
            outbound["streamSettings"]["grpcSettings"] = {
                "multiMode": False,
                "serviceName": clean_str(params.get("serviceName", ""))
            }
        elif net_type == "ws":
            ws_path = params.get("path", "/")
            if not ws_path.startswith("/"):
                ws_path = "/" + ws_path
            outbound["streamSettings"]["wsSettings"] = {
                "path": ws_path,
                "headers": {"Host": clean_str(params.get("host", host))}
            }
        elif net_type == "xhttp":
            x_path = params.get("path", "/")
            if not x_path.startswith("/"):
                x_path = "/" + x_path
            outbound["streamSettings"]["xhttpSettings"] = {
                "mode": clean_str(params.get("mode", "auto")),
                "path": x_path
            }
        elif net_type == "raw":
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
        print("Не найдено серверов, совместимых с Xray 26.")
        return

    full_cfg = build_config(outbounds)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(full_cfg, f, ensure_ascii=False, indent=2)

    print(f"Готово! Собрано {len(outbounds)} совместимых нод.")

if __name__ == "__main__":
    main()
