#!/usr/bin/python3
import ipaddress
import json
import shutil
import subprocess
import sys
from datetime import datetime

NAME = "soc-firewall-drop"
COMMENT = "WAZUH_AR_110502"
LOG = "/var/ossec/logs/active-responses.log"
IPTABLES4 = shutil.which("iptables") or "/usr/sbin/iptables"
IPTABLES6 = shutil.which("ip6tables") or "/usr/sbin/ip6tables"
# Preserve the existing source-IP protection.
WHITELIST = {
    "127.0.0.1",
    "127.0.0.53",
    "192.168.50.10",
    "192.168.50.20",
    "192.168.50.30",
}


def log(message):
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(
                f"{datetime.now().astimezone().isoformat()} "
                f"{NAME}: {message}\n"
            )
    except OSError:
        pass


def find_source(obj):
    """Find source IP recursively in the Wazuh active response message."""
    if isinstance(obj, dict):
        for key in (
            "src_ip",
            "srcip",
            "source_ip",
            "sourceAddress",
            "ipAddress",
        ):
            value = obj.get(key)

            if isinstance(value, str):
                try:
                    return str(ipaddress.ip_address(value.strip()))
                except ValueError:
                    pass

        for value in obj.values():
            if isinstance(value, (dict, list)):
                result = find_source(value)
                if result:
                    return result

    elif isinstance(obj, list):
        for value in obj:
            result = find_source(value)
            if result:
                return result

    return None
def run_firewall(version, args):
    executable = IPTABLES4 if version == 4 else IPTABLES6
    try:
        return subprocess.run(
            [executable, *args],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"ERROR: firewall execution failed: {exc}")
        return None

def check_keys(source):
    """Required Wazuh stateful-response handshake before adding a block."""
    request = {
        "version": 1,
        "origin": {"name": NAME, "module": "active-response"},
        "command": "check_keys",
        "parameters": {"keys": [source]},
    }

    print(json.dumps(request), flush=True)
    response_line = sys.stdin.readline()

    if not response_line:
        log("ERROR: no response to check_keys")
        return False

    try:
        response = json.loads(response_line)
    except ValueError:
        log("ERROR: invalid JSON response to check_keys")
        return False

    decision = response.get("command")
    if decision != "continue":
        log(f"check_keys denied or failed: {decision!r}")
        return False

    return True


def main():
    line = sys.stdin.readline()
    if not line:
        log("ERROR: empty input")
        return 1

    try:
        message = json.loads(line)
    except ValueError:
        log("ERROR: invalid JSON input")
        return 1

    command = message.get("command")
    log(f"RECEIVED: command={command!r}")

    if command not in ("add", "delete"):
        log(f"ERROR: unsupported command: {command!r}")
        return 1

    source = find_source(message)
    if not source:
        log("ERROR: source IP not found in alert JSON")
        return 1

    ip = ipaddress.ip_address(source)
    log(f"SOURCE: {source}")

    if source in WHITELIST or ip.is_loopback:
        log(f"REFUSED: protected IP {source}")
        return 0

    rule = [
        "-s", source,
        "-m", "comment", "--comment", COMMENT,
        "-j", "DROP",
    ]

    if command == "add":
        if not check_keys(source):
            return 0

        exists = run_firewall(ip.version, ["-C", "INPUT", *rule])
        if exists is None:
            return 1

        if exists.returncode == 0:
            log(f"ALREADY BLOCKED: {source}")
            return 0

        result = run_firewall(ip.version, ["-I", "INPUT", "1", *rule])
        if result is None or result.returncode != 0:
            detail = result.stderr.strip() if result else "execution failed"
            log(f"ERROR adding block for {source}: {detail}")
            return 1

        log(f"BLOCKED: {source}")
        return 0

    # delete: remove every matching rule created by this script only.
    removed = False
    while True:
        exists = run_firewall(ip.version, ["-C", "INPUT", *rule])
        if exists is None:
            return 1
        if exists.returncode != 0:
            break

        result = run_firewall(ip.version, ["-D", "INPUT", *rule])
        if result is None or result.returncode != 0:
            detail = result.stderr.strip() if result else "execution failed"
            log(f"ERROR removing block for {source}: {detail}")
            return 1

        removed = True

    if removed:
        log(f"UNBLOCKED: {source}")
    else:
        log(f"UNBLOCKED: {source} (rule was already absent)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
