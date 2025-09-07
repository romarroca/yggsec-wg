#!/usr/bin/env python3
import subprocess
import re
import ipaddress
import json
from src.utils.utils import run_priv, run_text
from src.utils.error_handler import handle_service_error
from src.core.exceptions import FirewallError, ValidationError

NFT_TABLE = "vpnfw"
NFT_CHAIN = "forward"
VPN_IFACE = "wg0"  # VPN interface
BASELINE_COUNT = 0  # baseline ct rules are skipped in parsing

# ---- minimal field parser for UI ----
_FIELD_RE = {
    "src": re.compile(r"\bip\s+saddr\s+([0-9./]+)"),
    "dst": re.compile(r"\bip\s+daddr\s+([0-9./]+)"),
    "dport": re.compile(r"\b(?:tcp|udp)\s+dport\s+(\d{1,5})"),
    "proto": re.compile(r"\b(ip\s+protocol\s+icmp|tcp|udp)\b"),
}


def _parse_nft_fields(rule_str: str):
    if not rule_str:
        return {"src": None, "dst": None, "proto": "ANY", "dport": None}
    src = _FIELD_RE["src"].search(rule_str)
    dst = _FIELD_RE["dst"].search(rule_str)
    dport = _FIELD_RE["dport"].search(rule_str)
    pm = _FIELD_RE["proto"].search(rule_str)
    if pm:
        t = pm.group(0)
        proto = "ICMP" if "icmp" in t else ("TCP" if "tcp" in t else "UDP")
    else:
        proto = "ANY"
    return {
        "src": src.group(1) if src else None,
        "dst": dst.group(1) if dst else None,
        "proto": proto,
        "dport": dport.group(1) if dport else None,
    }


def validate_nft_output(output):
    """Validate nftables output for safe persistence."""
    if not output or not isinstance(output, str):
        return False

    # Basic sanity checks
    if len(output) > 1024 * 1024:  # Max 1MB
        return False

    # Must contain expected table declaration
    if f"table inet {NFT_TABLE}" not in output:
        return False

    # Check for potentially dangerous content
    dangerous_patterns = [
        r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]",  # Control characters
        r";\s*rm\s+",  # Command injection attempts
        r";\s*curl\s+",
        r";\s*wget\s+",
        r"\$\(",  # Command substitution
        r"`[^`]*`",  # Backticks
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, output):
            return False

    return True


def validate_nft_json_structure(nft_data):
    """Validate nftables JSON structure for expected format."""
    if not isinstance(nft_data, dict):
        return False

    # Check for nftables root structure
    if "nftables" not in nft_data:
        return False

    nftables_list = nft_data["nftables"]
    if not isinstance(nftables_list, list):
        return False

    # Validate each element in the nftables array
    has_target_table = False
    for item in nftables_list:
        if not isinstance(item, dict):
            return False

        # Check for table declaration
        if "table" in item:
            table_def = item["table"]
            if (
                isinstance(table_def, dict)
                and table_def.get("family") == "inet"
                and table_def.get("name") == NFT_TABLE
            ):
                has_target_table = True

        # Validate chain structure if present
        elif "chain" in item:
            chain_def = item["chain"]
            if not isinstance(chain_def, dict):
                return False
            # Basic chain validation - must have family, table, name
            required_fields = ["family", "table", "name"]
            if not all(field in chain_def for field in required_fields):
                return False

        # Validate rule structure if present
        elif "rule" in item:
            rule_def = item["rule"]
            if not isinstance(rule_def, dict):
                return False
            # Basic rule validation
            required_fields = ["family", "table", "chain"]
            if not all(field in rule_def for field in required_fields):
                return False

    return has_target_table


def get_nft_json_config():
    """Get nftables configuration in JSON format for validation testing."""
    import json

    ok, json_output = run_cmd(["nft", "-j", "list", "table", "inet", NFT_TABLE])
    if not ok:
        return None, "Failed to get JSON configuration"

    try:
        nft_data = json.loads(json_output)
        if not validate_nft_json_structure(nft_data):
            return None, "Invalid nftables JSON structure"
        return nft_data, "Valid JSON configuration"
    except json.JSONDecodeError as e:
        return None, f"JSON parsing error: {str(e)}"


def generate_nft_config_from_json(nft_data):
    """Generate nftables configuration text from validated JSON structure."""
    if not nft_data or "nftables" not in nft_data:
        return ""

    config_lines = []

    # Process each nftables element
    for item in nft_data["nftables"]:
        if "table" in item:
            table_def = item["table"]
            family = table_def.get("family", "inet")
            name = table_def.get("name", "")
            config_lines.append(f"table {family} {name} {{")

        elif "chain" in item:
            chain_def = item["chain"]
            name = chain_def.get("name", "")
            chain_type = chain_def.get("type", "")
            hook = chain_def.get("hook", "")
            prio = chain_def.get("prio", 0)
            policy = chain_def.get("policy", "")

            if chain_type and hook:
                config_lines.append(f"  chain {name} {{")
                config_lines.append(
                    f"    type {chain_type} hook {hook} priority {prio};"
                )
                if policy:
                    config_lines.append(f"    policy {policy};")

        elif "rule" in item:
            rule_def = item["rule"]
            expr = rule_def.get("expr", [])
            comment = rule_def.get("comment", "")

            # Parse rule expressions into components
            rule_parts = []
            has_counter = False
            action = ""

            for expression in expr:
                if not isinstance(expression, dict):
                    continue

                # Handle match expressions
                if "match" in expression:
                    match = expression["match"]
                    left = match.get("left", {})
                    right = match.get("right")
                    op = match.get("op", "==")

                    # Connection tracking matching
                    if "ct" in left and left["ct"].get("key") == "state":
                        if isinstance(right, list):
                            # Multiple states: ["established", "related"]
                            states = ",".join(right)
                            rule_parts.append(f"ct state {states}")
                        else:
                            # Single state: "invalid"
                            rule_parts.append(f"ct state {right}")

                    # Interface matching
                    elif "meta" in left and left["meta"].get("key") == "iifname":
                        rule_parts.append(f'iifname "{right}"')

                    # IP payload matching
                    elif "payload" in left:
                        protocol = left["payload"].get("protocol")
                        field = left["payload"].get("field")

                        if protocol == "ip":
                            if field == "saddr":
                                if isinstance(right, dict) and "prefix" in right:
                                    # CIDR notation
                                    addr = right["prefix"]["addr"]
                                    length = right["prefix"]["len"]
                                    rule_parts.append(f"ip saddr {addr}/{length}")
                                else:
                                    # Single IP
                                    rule_parts.append(f"ip saddr {right}")
                            elif field == "daddr":
                                if isinstance(right, dict) and "prefix" in right:
                                    # CIDR notation
                                    addr = right["prefix"]["addr"]
                                    length = right["prefix"]["len"]
                                    rule_parts.append(f"ip daddr {addr}/{length}")
                                else:
                                    # Single IP
                                    rule_parts.append(f"ip daddr {right}")
                            elif field == "protocol":
                                rule_parts.append(f"ip protocol {right}")

                        elif protocol in ["tcp", "udp"]:
                            if field == "dport":
                                rule_parts.append(f"{protocol} dport {right}")

                # Handle counter
                elif "counter" in expression:
                    has_counter = True

                # Handle actions
                elif "accept" in expression:
                    action = "accept"
                elif "drop" in expression:
                    action = "drop"
                elif "queue" in expression:
                    queue_info = expression["queue"]
                    num = queue_info.get("num", 0)
                    flags = queue_info.get("flags", "")
                    if flags:
                        action = f"queue flags {flags} to {num}"
                    else:
                        action = f"queue to {num}"

            # Build complete rule line
            if rule_parts or has_counter or action:
                rule_line = "    "
                if rule_parts:
                    rule_line += " ".join(rule_parts) + " "
                if has_counter:
                    rule_line += "counter "
                if action:
                    rule_line += action
                if comment:
                    rule_line += f' comment "{comment}"'

                config_lines.append(rule_line.rstrip())

    # Close any open table/chain properly
    if config_lines:
        # Close chain if we have one
        chain_started = False
        for line in config_lines:
            if "chain " in line and "{" in line:
                chain_started = True
                break

        if chain_started:
            config_lines.append("  }")

        # Close table if we have one
        if config_lines and config_lines[0].startswith("table"):
            config_lines.append("}")

    return "\n".join(config_lines)


def debug_json_structure():
    """Debug function to see the actual JSON structure from nftables."""
    ok, json_output = run_cmd(["nft", "-j", "list", "table", "inet", NFT_TABLE])
    if ok:
        try:
            nft_data = json.loads(json_output)
            print("Raw JSON structure:")
            print(json.dumps(nft_data, indent=2))
            return nft_data
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
    return None


def test_json_config_parsing():
    """Test function to validate JSON parsing without affecting current persistence."""
    print("Testing nftables JSON configuration parsing...")

    # Test JSON retrieval and validation
    json_data, message = get_nft_json_config()
    if json_data is None:
        print(f"❌ JSON parsing failed: {message}")
        return False

    print(f"✅ JSON parsing successful: {message}")

    # Debug: Show actual JSON structure
    print("\n🔍 Debug: Showing actual JSON structure...")
    debug_data = debug_json_structure()
    print("-" * 40)

    # Test config generation from JSON
    try:
        generated_config = generate_nft_config_from_json(json_data)
        if generated_config:
            print("✅ Config generation from JSON successful")
            print("Generated config preview:")
            print("-" * 40)
            print(
                generated_config[:500] + "..."
                if len(generated_config) > 500
                else generated_config
            )
            print("-" * 40)
        else:
            print("❌ Config generation produced empty result")
            return False
    except Exception as e:
        print(f"❌ Config generation failed: {str(e)}")
        return False

    # Compare with current text-based method
    try:
        ok, text_output = run_cmd(["nft", "-s", "list", "table", "inet", NFT_TABLE])
        if ok:
            print("✅ Text-based method still working")
            print(f"Text config length: {len(text_output)} chars")
            print(f"JSON-generated config length: {len(generated_config)} chars")
        else:
            print("❌ Text-based method failed")
            return False
    except Exception as e:
        print(f"❌ Text-based comparison failed: {str(e)}")
        return False

    return True


def persist_vpnfw_table():
    """Dump inet:vpnfw and persist to /etc/nftables.d/vpnfw.nft atomically."""
    import tempfile
    import os

    ok, output = run_cmd(["nft", "-s", "list", "table", "inet", NFT_TABLE])
    if not ok:
        return False, "Failed to dump firewall table"

    # Validate nft output before persisting
    if not validate_nft_output(output):
        return False, "Invalid firewall configuration data"

    dst = "/etc/nftables.d/vpnfw.nft"
    tmp_name = None

    # Use secure temporary file with proper permissions
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir="/etc/nftables.d", prefix=".vpnfw.nft.tmp.", delete=False
        ) as tmp_file:
            # Set secure permissions before writing
            os.fchmod(tmp_file.fileno(), 0o644)
            tmp_file.write(output)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
            tmp_name = tmp_file.name

        # Atomic move
        os.replace(tmp_name, dst)
        return True, "persisted"

    except (OSError, IOError):
        # Clean up temp file on error
        if tmp_name and os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass  # Best effort cleanup
        return False, "Failed to persist firewall configuration"


def validate_ip(value):
    """Validate IPv4 or IPv4/CIDR with comprehensive checks."""
    if not value or not isinstance(value, str):
        return False

    value = value.strip()
    if not value:
        return False

    # Check for basic format issues
    if len(value) > 18:  # Max IPv4 CIDR length
        return False

    # Only allow IPv4 addresses/networks
    try:
        # Try as single IP first
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        pass

    try:
        # Try as network/CIDR
        network = ipaddress.IPv4Network(value, strict=False)
        # Ensure reasonable prefix lengths
        if network.prefixlen < 8 or network.prefixlen > 32:
            return False
        return True
    except ValueError:
        return False


def validate_port(value):
    """Validate TCP/UDP port (1-65535) with enhanced checks."""
    if not value:
        return True

    if not isinstance(value, (str, int)):
        return False

    try:
        port = int(str(value).strip())
        return 1 <= port <= 65535
    except (ValueError, AttributeError):
        return False


def run_cmd(cmd, input_text=None):
    """Run a command via run_priv. Returns (success, output_or_error)."""
    try:
        if input_text is None:
            cp = run_priv(cmd, text=True, capture_output=True)
        else:
            cp = run_priv(cmd, text=True, capture_output=True, input=input_text)
        return True, (cp.stdout or "").strip()
    except subprocess.CalledProcessError:
        # Don't leak detailed error information
        return False, "Command execution failed"
    except Exception:
        return False, "System error occurred"


def _flush_all_conntrack():
    """
    Flush all connection tracking entries when resetting firewall.
    This ensures fresh start with no lingering connections.
    """
    try:
        result = run_priv(
            ["conntrack", "-F"], check=False, capture_output=True, text=True
        )

        if result.returncode == 0:
            print("✅ All connection tracking entries cleared")
        else:
            # Conntrack may not have entries to clear, which is normal
            if "No such file or directory" not in (result.stderr or ""):
                print("ℹ️ Connection tracking flush completed")

    except Exception as e:
        # Don't fail the firewall reset if conntrack flush fails
        print(f"⚠️ Connection tracking flush failed: {e}")


def reset_firewall(policy="drop"):
    """Reset firewall with base table/chain and flush all connection tracking."""
    run_cmd(["nft", "delete", "table", "inet", NFT_TABLE])
    run_cmd(["nft", "add", "table", "inet", NFT_TABLE])

    run_cmd(
        [
            "nft",
            "add",
            "chain",
            "inet",
            NFT_TABLE,
            NFT_CHAIN,
            "{",
            "type",
            "filter",
            "hook",
            "forward",
            "priority",
            "0",
            ";",
            "policy",
            policy,
            ";",
            "}",
        ]
    )

    if policy == "drop":
        run_cmd(
            [
                "nft",
                "add",
                "rule",
                "inet",
                NFT_TABLE,
                NFT_CHAIN,
                "ct",
                "state",
                "established,related",
                "accept",
            ]
        )
        run_cmd(
            [
                "nft",
                "add",
                "rule",
                "inet",
                NFT_TABLE,
                NFT_CHAIN,
                "ct",
                "state",
                "invalid",
                "drop",
            ]
        )

    # Flush all connection tracking entries on firewall reset
    _flush_all_conntrack()

    persist_vpnfw_table()
    return True, f"{NFT_TABLE} reset with policy {policy.upper()}"


def add_rule(
    src_ip=None,
    dst_ip=None,
    dst_port=None,
    proto=None,
    action="TRUST",
    position="append",
    index=None,
    name=None,
):
    """
    Add custom rule with action:
    - TRUST: allow traffic, bypass Suricata (accept)
    - ALLOW: allow traffic, inspected by Suricata (NFQUEUE 0 with bypass)
    - DROP : block traffic

    Proto behavior:
    - proto == "any"/"all"/"": match ALL protocols (no port allowed)
    - proto in ("tcpudp","tcp+udp","both"): add two rules (TCP and UDP)
    """
    if not validate_rule_name(name):
        return (
            False,
            "Rule name is required and must contain only alphanumeric characters, spaces, dashes, underscores (max 50 chars)",
        )

    if src_ip and not validate_ip(src_ip):
        return False, f"Invalid source IP/subnet: {src_ip}"
    if dst_ip and not validate_ip(dst_ip):
        return False, f"Invalid destination IP/subnet: {dst_ip}"

    if dst_port and not validate_port(dst_port):
        return False, f"Invalid port: {dst_port}"

    proto = (proto or "").lower().strip()
    act = (action or "TRUST").upper().strip()

    def _build_and_run(one_proto: str | None, suffix_name: str = ""):
        """Build a single nft rule for a specific proto (or None for ANY) and execute."""
        cmd = ["nft", "add", "rule", "inet", NFT_TABLE, NFT_CHAIN]

        # Insert position
        if position == "insert":
            cmd += ["index", "1"]
        elif position == "index" and index is not None:
            try:
                cmd += ["index", str(int(index))]
            except ValueError:
                pass

        # Base matches
        cmd += ["iifname", VPN_IFACE]
        if src_ip:
            cmd += ["ip", "saddr", src_ip]
        if dst_ip:
            cmd += ["ip", "daddr", dst_ip]

        # L4 protocol / port
        if one_proto and dst_port:
            cmd += [one_proto, "dport", str(dst_port)]
        elif one_proto:
            if one_proto == "icmp":
                cmd += ["ip", "protocol", "icmp"]
            else:
                cmd += [one_proto]
        else:
            # ANY protocol
            if dst_port:
                return (
                    False,
                    "Port filter requires TCP or UDP. Choose TCP, UDP, or TCP+UDP.",
                )

        # Counter for visibility
        cmd += ["counter"]

        # Action
        if act == "TRUST":
            cmd += ["accept"]
        elif act == "ALLOW":
            cmd += ["queue", "flags", "bypass", "to", "0"]
        elif act == "DROP":
            cmd += ["drop"]
        else:
            return False, f"Invalid action: {action}. Use TRUST, ALLOW, DROP."

        # Label
        rule_name = name if not suffix_name else f"{name}{suffix_name}"
        cmd += ["comment", f'"{rule_name}"']

        return run_cmd(cmd)

    if proto in ("any", "all", ""):
        ok, msg = _build_and_run(None)
        persist_vpnfw_table()
        return ok, msg

    if proto in ("tcpudp", "tcp+udp", "both"):
        ok1, msg1 = _build_and_run("tcp", " (tcp)")
        if not ok1:
            return False, msg1
        ok2, msg2 = _build_and_run("udp", " (udp)")
        if not ok2:
            return False, msg2
        persist_vpnfw_table()
        return True, "TCP+UDP rules added"

    ok, msg = _build_and_run(proto)
    persist_vpnfw_table()
    return ok, msg


def list_rules(with_handles=False):
    """List current rules in the chain."""
    if with_handles:
        cmd = ["nft", "-a", "list", "chain", "inet", NFT_TABLE, NFT_CHAIN]
    else:
        cmd = ["nft", "list", "chain", "inet", NFT_TABLE, NFT_CHAIN]
    return run_cmd(cmd)


def list_rules_table():
    """Return rules parsed into clean list for the web UI."""
    success, output = list_rules(with_handles=True)
    if not success or not output:
        return []

    rules, line_num = [], 1
    for line in output.splitlines():
        line = line.strip()
        if (
            not line
            or line.startswith(("chain", "table", "type filter", "ct state"))
            or line in ("{", "}")
        ):
            continue

        handle, rule_text, rule_name, action_type = "-", line, None, "UNKNOWN"

        if "# handle" in line:
            parts = line.split("# handle")
            rule_text = parts[0].strip()
            handle = parts[1].strip()

        if "comment" in rule_text:
            parts = rule_text.split("comment")
            rule_text = parts[0].strip()
            rule_name = parts[1].strip().strip('"')

        if "queue" in rule_text:
            action_type = "ALLOW"
        elif "accept" in rule_text:
            action_type = "TRUST"
        elif "drop" in rule_text:
            action_type = "DROP"

        fields = _parse_nft_fields(rule_text)

        rules.append(
            {
                "line": line_num,
                "rule": rule_text,
                "name": rule_name or f"rule_{line_num}",
                "handle": handle,
                "action": action_type,
                "src": fields["src"],
                "dst": fields["dst"],
                "proto": fields["proto"],
                "dport": fields["dport"],
            }
        )
        line_num += 1
    return rules


def validate_handle(handle):
    """Validate nftables rule handle - must be positive integer."""
    if not handle:
        return False

    try:
        handle_int = int(str(handle).strip())
        return handle_int > 0
    except (ValueError, AttributeError):
        return False


def validate_rule_name(name):
    """Validate firewall rule name for safe use in comments."""
    if not name or not isinstance(name, str):
        return False

    name = name.strip()
    if not name:
        return False

    # Only allow alphanumeric, dash, underscore, space
    if not re.match(r"^[A-Za-z0-9_\s-]{1,50}$", name):
        return False

    # Prevent command injection characters
    forbidden = ['"', "'", "\n", "\r", "\t", ";", "&", "|", "`", "$"]
    if any(char in name for char in forbidden):
        return False

    return True


def get_rule_by_handle(handle):
    """Get rule details by handle for connection tracking cleanup."""
    success, output = list_rules(with_handles=True)
    if not success or not output:
        return None

    target_handle = str(int(handle))
    for line in output.splitlines():
        line = line.strip()
        if not line or "# handle" not in line:
            continue

        parts = line.split("# handle")
        rule_text = parts[0].strip()
        rule_handle = parts[1].strip()

        if rule_handle == target_handle:
            # Skip system rules (ct state, etc.)
            if "ct state" in rule_text:
                return None

            # Parse rule fields
            fields = _parse_nft_fields(rule_text)
            return {
                "src": fields["src"],
                "dst": fields["dst"],
                "proto": fields["proto"],
                "dport": fields["dport"],
                "rule_text": rule_text,
            }

    return None


def _flush_conntrack_for_rule(rule_info):
    """
    Flush connection tracking entries that match the deleted rule.
    Uses YggSec's run_priv() instead of sudo for proper capabilities.
    """
    if not rule_info:
        return

    try:
        # Build conntrack delete command
        cmd = ["conntrack", "-D"]

        # Add source IP if specified
        if rule_info.get("src"):
            cmd.extend(["-s", rule_info["src"]])

        # Add destination IP if specified
        if rule_info.get("dst"):
            cmd.extend(["-d", rule_info["dst"]])

        # Add protocol if specified (convert from parsed format)
        proto = rule_info.get("proto", "").upper()
        if proto in ["TCP", "UDP", "ICMP"]:
            cmd.extend(["-p", proto.lower()])

            # Add destination port for TCP/UDP
            if proto in ["TCP", "UDP"] and rule_info.get("dport"):
                cmd.extend(["--dport", rule_info["dport"]])

        # Only proceed if we have meaningful selectors
        if len(cmd) > 2:  # More than just ["conntrack", "-D"]
            result = run_priv(cmd, check=False, capture_output=True, text=True)

            if result.returncode == 0:
                # Count deleted entries from stdout
                deleted_count = result.stdout.strip()
                if deleted_count.isdigit() and int(deleted_count) > 0:
                    print(
                        f"✅ Cleared {deleted_count} connection tracking entries for rule"
                    )
                else:
                    print(
                        "✅ Connection tracking cleanup completed (no active connections)"
                    )
            else:
                # Return code 1 usually means "no matching entries found" - this is normal
                if "No such file or directory" not in (result.stderr or ""):
                    print("ℹ️ No matching connection tracking entries found")

    except Exception as e:
        # Don't fail the rule deletion if conntrack cleanup fails
        print(f"⚠️ Connection tracking cleanup failed: {e}")


def delete_rule(handle):
    """Delete specific rule by handle ID with validation and clear related connection tracking."""
    if not validate_handle(handle):
        return False, "Invalid handle: must be a positive integer"

    # Get rule details before deletion for conntrack flushing
    rule_info = get_rule_by_handle(handle)

    ok, msg = run_cmd(
        [
            "nft",
            "delete",
            "rule",
            "inet",
            NFT_TABLE,
            NFT_CHAIN,
            "handle",
            str(int(handle)),
        ]
    )

    if ok:
        persist_vpnfw_table()

        # Clear connection tracking entries for the deleted rule
        if rule_info:
            _flush_conntrack_for_rule(rule_info)

    return ok, msg


def edit_rule(
    handle,
    src_ip=None,
    dst_ip=None,
    dst_port=None,
    proto=None,
    action="TRUST",
    position="append",
    index=None,
    name=None,
):
    """
    Edit a rule by handle:
    - deletes the existing rule
    - re-adds it with provided parameters (can also move position)
    """
    if not validate_handle(handle):
        return False, "Invalid handle: must be a positive integer"

    ok, msg = delete_rule(handle)
    if not ok:
        return False, f"Failed to remove existing rule (handle {handle}): {msg}"
    return add_rule(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
        action=action,
        position=position,
        index=index,
        name=name,
    )
