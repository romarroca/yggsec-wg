#!/usr/bin/env python3
# suricata.py
import os, glob, gzip, json, subprocess, time
from collections import deque
from pathlib import Path

EVE_DIR   = "/var/log/suricata"
EVE_FILE  = f"{EVE_DIR}/eve.json"
EVE_GLOB  = f"{EVE_DIR}/eve.json.*.gz"
TAIL_BYTES = 2 * 1024 * 1024  # read only last 2MB of live file

# Simple alert cache to persist across rotations
CACHE_DIR = Path("/opt/yggsec/cache")
ALERT_CACHE = CACHE_DIR / "suricata_alerts.json"
MAX_CACHED_ALERTS = 1000

def _parse_alerts(lines, limit):
    out = []
    for ln in reversed(lines):  # newest lines last → parse newest-first
        try:
            ev = json.loads(ln)
        except Exception:
            continue
        if ev.get("event_type") != "alert":
            continue
        al = ev.get("alert", {})
        out.append({
            "time":  ev.get("timestamp"),
            "sig":   al.get("signature"),
            "cat":   al.get("category"),
            "sev":   al.get("severity"),
            "proto": ev.get("proto"),
            "src":   f'{ev.get("src_ip")}{":" + str(ev.get("src_port")) if ev.get("src_port") else ""}',
            "dst":   f'{ev.get("dest_ip")}{":" + str(ev.get("dest_port")) if ev.get("dest_port") else ""}',
            "action": al.get("action"),
            "sid":   al.get("signature_id"),
        })
        if len(out) >= limit:
            break
    return list(reversed(out))  # oldest→newest for UI

def _load_cached_alerts():
    """Load cached alerts from persistent storage"""
    try:
        if ALERT_CACHE.exists():
            with open(ALERT_CACHE, 'r') as f:
                data = json.load(f)
                return data.get('alerts', [])
    except Exception:
        pass
    return []

def _save_cached_alerts(alerts):
    """Save alerts to persistent storage"""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        # Keep only the most recent alerts
        recent_alerts = alerts[-MAX_CACHED_ALERTS:] if len(alerts) > MAX_CACHED_ALERTS else alerts
        with open(ALERT_CACHE, 'w') as f:
            json.dump({
                'alerts': recent_alerts,
                'updated': time.time()
            }, f, indent=2)
    except Exception:
        pass

def _merge_and_dedupe_alerts(new_alerts, cached_alerts):
    """Merge new alerts with cached ones and remove duplicates"""
    # Use signature_id + timestamp as unique key
    seen = set()
    merged = []
    
    # Process all alerts (new + cached) by timestamp descending
    all_alerts = sorted(new_alerts + cached_alerts, 
                       key=lambda x: x.get('time', ''), reverse=True)
    
    for alert in all_alerts:
        # Create unique key from signature ID and timestamp  
        key = f"{alert.get('sid', '')}:{alert.get('time', '')}"
        if key not in seen:
            seen.add(key)
            merged.append(alert)
            
        if len(merged) >= MAX_CACHED_ALERTS:
            break
            
    return merged

def read_eve(n=200, history=True):
    """
    Read Suricata alerts from eve.json, rotated logs, and persistent cache.
    Default history=True to prevent disappearing alerts during log rotation.
    """
    # 1) Load cached alerts first
    cached_alerts = _load_cached_alerts()
    
    buf = deque(maxlen=n*5)  # Larger buffer for better coverage
    alerts_found = 0

    # 2) Read current eve.json first (most recent)
    try:
        with open(EVE_FILE, "r", encoding="utf-8", errors="ignore") as f:
            try:
                size = os.fstat(f.fileno()).st_size
                if size > TAIL_BYTES:
                    f.seek(size - TAIL_BYTES)
                    f.readline()  # drop partial line
            except Exception:
                pass
            for ln in f:
                buf.append(ln)
    except FileNotFoundError:
        pass

    # 3) Always check rotated files if we don't have enough alerts or history=True
    alerts_in_current = len([ln for ln in buf if '"event_type":"alert"' in ln])
    
    if history or alerts_in_current < n:
        rotated_files = sorted(glob.glob(EVE_GLOB), key=lambda x: os.path.getctime(x), reverse=True)
        
        for path in rotated_files:
            try:
                with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as g:
                    # Read rotated file in reverse for newest first
                    lines = []
                    for ln in g:
                        lines.append(ln)
                    
                    # Add newest lines first from this file
                    for ln in reversed(lines):
                        buf.append(ln)
                        if '"event_type":"alert"' in ln:
                            alerts_found += 1
                            if alerts_found >= n*2:  # Stop when we have enough
                                break
                                
            except Exception:
                continue
            
            if alerts_found >= n*2:
                break

    # 4) Parse alerts from log files
    new_alerts = _parse_alerts(buf, n*2)
    
    # 5) Merge with cached alerts and dedupe
    all_alerts = _merge_and_dedupe_alerts(new_alerts, cached_alerts)
    
    # 6) Update cache with merged results
    _save_cached_alerts(all_alerts)
    
    # 7) Return requested number of alerts
    return all_alerts[:n]


def get_suricata_mode():
    """Check if Suricata IPS is ON or OFF"""
    try:
        result = subprocess.run(['systemctl', 'is-active', 'suricata'], 
                              capture_output=True, text=True, shell=False)
        return 'ON' if result.stdout.strip() == 'active' else 'OFF'
    except Exception:
        return 'OFF'


def get_suricata_status():
    """Get Suricata service status"""
    try:
        result = subprocess.run(['systemctl', 'is-active', 'suricata'], 
                              capture_output=True, text=True, shell=False)
        return result.stdout.strip()
    except Exception:
        return 'unknown'


def clear_alert_cache():
    """Clear the persistent alert cache"""
    try:
        if ALERT_CACHE.exists():
            ALERT_CACHE.unlink()
            return True
    except Exception:
        pass
    return False

# Control functions removed due to NoNewPrivileges=true security constraint  
# Suricata service control must be done manually via SSH/console:
# sudo systemctl start/stop/restart suricata
# sudo suricata-update

