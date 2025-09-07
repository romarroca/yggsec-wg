# /opt/yggsec/utils.py
from pathlib import Path
import shutil, subprocess, tempfile, os, json
from typing import Iterable, List, Dict

BINMAP: Dict[str, str] = {
    "wg": "/usr/bin/wg",
    "wg-quick": "/usr/bin/wg-quick",
    "ip": "/usr/bin/ip",
    "nft": "/usr/sbin/nft",
    "iptables": "/usr/sbin/iptables",
    "ip6tables": "/usr/sbin/ip6tables",
    "conntrack": "/usr/sbin/conntrack",
    "systemctl": "/usr/bin/systemctl",
    "suricata-update": "/usr/bin/suricata-update",
}


def _resolve(argv: Iterable[str]) -> List[str]:
    a = list(argv)
    if not a:
        raise ValueError("empty argv")
    exe = a[0]
    path = BINMAP.get(exe) or shutil.which(exe) or exe
    return [path] + a[1:]


def run_priv(args, **kw):
    """
    Execute a command needed for wg/ip/nft/etc. We do NOT use sudo.
    The systemd unit grants the needed capabilities.
    """
    cmd = _resolve(args)
    # apply safe defaults without clashing with explicit stdout/stderr
    if "capture_output" not in kw and "stdout" not in kw and "stderr" not in kw:
        kw["capture_output"] = True
    kw.setdefault("check", True)
    if kw.get("capture_output", False):
        kw.setdefault("text", True)
    # Explicitly set shell=False for security (Bandit B603)
    kw.setdefault("shell", False)
    return subprocess.run(cmd, **kw)


def run(args: Iterable[str], **kw) -> subprocess.CompletedProcess:
    """Alias kept for callers that use run()."""
    return run_priv(args, **kw)


def run_text(args: Iterable[str], **kw) -> str:
    """Return stdout text; raise on non-zero unless check=False."""
    cp = run_priv(args, **kw)
    return cp.stdout


def run_json(args: Iterable[str], **kw):
    """Parse stdout as JSON or raise with stderr context."""
    try:
        out = run_text(args, **kw)
        return json.loads(out) if out else {}
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or e.stdout or str(e)).strip()
        raise RuntimeError(f"{_resolve(args)[0]} failed: {msg}") from e


# Atomic file helpers (used by core/app)
def ensure_dir(p: str | Path, mode: int = 0o700) -> None:
    Path(p).mkdir(parents=True, exist_ok=True)
    os.chmod(p, mode)


def write_text_atomic(p: str | Path, data: str, mode: int = 0o600) -> None:
    """Atomically write text with secure permissions."""
    p = Path(p)
    ensure_dir(p.parent)
    with tempfile.NamedTemporaryFile(
        "w", dir=str(p.parent), delete=False, prefix=f".{p.name}.tmp."
    ) as tmp:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
        os.fchmod(tmp.fileno(), mode)
        name = tmp.name
    os.replace(name, p)


def read_text(p: str | Path) -> str:
    return Path(p).read_text()


def write_json_atomic(p: str | Path, obj, mode: int = 0o600) -> None:
    write_text_atomic(p, json.dumps(obj, indent=2, sort_keys=True), mode)


def read_json(p: str | Path):
    q = Path(p)
    return json.loads(q.read_text()) if q.exists() else {}
