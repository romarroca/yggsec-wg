#!/usr/bin/env python3
# monitor.py
import json, subprocess, re, collections, os
from datetime import datetime
from collections import deque  # <-- added
from src.utils.utils import run_priv  # <-- added

# Map common ports to friendly names (extend as needed)
KNOWN_SERVICES = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    123: "NTP",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5000: "internal-flask",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    51820: "WireGuard",
}

NFT_TABLE = "vpnfw"
FORWARD_CHAIN = "forward"
INPUT_CHAIN = "input"  # make sure you create this chain in your nft table
INTERFACES_WATCH = ["wg0", "eth0"]  # adjust if needed


def _run(cmd):
    try:
        cp = run_priv(cmd, text=True, capture_output=True)
        return True, (cp.stdout or "")
    except subprocess.CalledProcessError as e:
        return False, (e.stderr or "").strip() or str(e)


def _nft_list_chain_json(chain):
    ok, out = _run(["nft", "--json", "list", "chain", "inet", NFT_TABLE, chain])
    if not ok:
        return {}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {}


def _extract_rule_counters(nft_json):
    """Return list of dicts: [{handle, comment, pkts, bytes, expr(list)}]"""
    results = []
    try:
        rules = nft_json["nftables"][1]["chain"]["rules"]
    except Exception:
        return results

    for r in rules:
        rule = r.get("rule", {})
        handle = rule.get("handle")
        comment = None
        pkts = bytes_ = 0
        expr = rule.get("expr", [])
        for e in expr:
            if "counter" in e:
                pkts = e["counter"].get("packets", 0)
                bytes_ = e["counter"].get("bytes", 0)
            if "comment" in e:
                comment = e["comment"]
        results.append(
            {
                "handle": handle,
                "comment": comment,
                "pkts": pkts,
                "bytes": bytes_,
                "expr": expr,
            }
        )
    return results


def _port_from_expr(expr):
    """Find L4 dport if present (tcp/udp). Return int or None."""
    for e in expr:
        m = e.get("match")
        if not m:
            continue
        left = m.get("left", {})
        payload = left.get("payload") or {}
        if payload.get("field") == "dport":
            return int(m.get("right"))
    return None


def _proto_from_expr(expr):
    """Return 'tcp'/'udp'/'icmp'/None if detectable."""
    for e in expr:
        m = e.get("match")
        if m and isinstance(m.get("left"), dict):
            payload = m["left"].get("payload") or {}
            proto = payload.get("protocol")
            if proto in ("tcp", "udp"):
                return proto
        if m and m.get("left", {}).get("meta", {}).get("key") == "l4proto":
            right = str(m.get("right")).lower()
            if right in ("tcp", "udp", "icmp"):
                return right
    return None


def _iface_from_expr(expr):
    """Extract iifname if present."""
    for e in expr:
        m = e.get("match")
        if m and m.get("left", {}).get("meta", {}).get("key") == "iifname":
            return m.get("right")
    return None


def get_service_counters():
    """
    Combine counters from FORWARD and INPUT chains.
    Return: { "services":[{service,port,proto,iface,pkts,bytes}], "unknown_totals":{pkts,bytes} }
    """
    svc_rows = []
    unknown_pkts = unknown_bytes = 0

    for chain in (FORWARD_CHAIN, INPUT_CHAIN):
        j = _nft_list_chain_json(chain)
        for r in _extract_rule_counters(j):
            if r["pkts"] == 0 and r["bytes"] == 0:
                continue
            expr = r["expr"]
            dport = _port_from_expr(expr)
            proto = _proto_from_expr(expr) or "-"
            iface = _iface_from_expr(expr) or "-"
            if dport is not None:
                service = KNOWN_SERVICES.get(dport, "Unknown")
                row = {
                    "service": service,
                    "port": dport,
                    "proto": proto,
                    "iface": iface,
                    "pkts": r["pkts"],
                    "bytes": r["bytes"],
                    "chain": chain,
                    "label": r["comment"] or "",
                }
                svc_rows.append(row)
            else:
                unknown_pkts += r["pkts"]
                unknown_bytes += r["bytes"]

    # Aggregate by (service,port,proto,iface)
    agg = {}
    for x in svc_rows:
        key = (x["service"], x["port"], x["proto"], x["iface"])
        cur = agg.get(key, {"pkts": 0, "bytes": 0})
        cur["pkts"] += x["pkts"]
        cur["bytes"] += x["bytes"]
        agg[key] = cur

    rows = []
    for (svc, port, proto, iface), v in sorted(
        agg.items(), key=lambda kv: kv[1]["pkts"], reverse=True
    ):
        rows.append(
            {
                "service": svc,
                "port": port,
                "proto": proto,
                "iface": iface,
                "pkts": v["pkts"],
                "bytes": v["bytes"],
            }
        )

    return {
        "services": rows,
        "unknown_totals": {"pkts": unknown_pkts, "bytes": unknown_bytes},
    }


def get_ips_seen(limit=20):
    """
    Summarize IPs from active conntrack table (very lightweight).
    Returns top talkers by flows seen, plus quick port hints.
    """
    ok, out = _run(["conntrack", "-L"])
    if not ok:
        return {"sources": [], "destinations": []}

    src_count = collections.Counter()
    dst_count = collections.Counter()
    dst_ports = collections.Counter()

    # Example line:
    # tcp      6 431999 ESTABLISHED src=10.250.250.2 dst=192.168.1.10 sport=51234 dport=443 ...
    for line in out.splitlines():
        src = re.search(r"\bsrc=([0-9.]+)", line)
        dst = re.search(r"\bdst=([0-9.]+)", line)
        dpt = re.search(r"\bdport=(\d+)", line)
        if src:
            src_count[src.group(1)] += 1
        if dst:
            dst_count[dst.group(1)] += 1
        if dpt:
            try:
                dst_ports[int(dpt.group(1))] += 1
            except ValueError:
                pass

    top_src = [{"ip": ip, "flows": c} for ip, c in src_count.most_common(limit)]
    top_dst = [{"ip": ip, "flows": c} for ip, c in dst_count.most_common(limit)]

    # quick “services seen” hint from conntrack dports
    top_ports = []
    for port, c in dst_ports.most_common(10):
        top_ports.append(
            {"port": port, "service": KNOWN_SERVICES.get(port, "Unknown"), "flows": c}
        )

    return {
        "sources": top_src,
        "destinations": top_dst,
        "top_ports_by_flows": top_ports,
    }


def get_interface_totals():
    """
    Read /proc/net/dev for simple RX/TX per interface (bytes/packets).
    """
    stats = []
    if not os.path.exists("/proc/net/dev"):
        return stats
    with open("/proc/net/dev") as f:
        for line in f:
            if ":" not in line:
                continue
            name, rest = [x.strip() for x in line.split(":", 1)]
            if name not in INTERFACES_WATCH:
                continue
            parts = rest.split()
            rx_bytes, rx_pkts = int(parts[0]), int(parts[1])
            tx_bytes, tx_pkts = int(parts[8]), int(parts[9])
            stats.append(
                {
                    "iface": name,
                    "rx_bytes": rx_bytes,
                    "rx_pkts": rx_pkts,
                    "tx_bytes": tx_bytes,
                    "tx_pkts": tx_pkts,
                }
            )
    return stats


def monitor_snapshot():
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "services": get_service_counters(),
        "ips_seen": get_ips_seen(),
        "interfaces": get_interface_totals(),
    }


# -------- Suricata fast.log helper (added) --------
def read_suricata_fast(path="/var/log/suricata/fast.log", n=200):
    """
    Return the last n lines of Suricata fast.log as a list of strings.
    Missing file -> empty list. Errors -> empty list.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = deque(f, maxlen=int(n))
        return [ln.rstrip("\n") for ln in lines]
    except FileNotFoundError:
        return []
    except Exception:
        return []
