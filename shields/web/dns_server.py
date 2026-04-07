"""
ThreatShield AI — Local DNS Server
Runs on 127.0.0.1:53 (standard DNS port)
Windows is configured to use this as DNS resolver.

How it works:
1. Windows sends ALL DNS queries to us first
2. We check if domain is blocked
3. If blocked → return 127.0.0.1 (our local block page server)
4. If safe   → forward to real DNS (8.8.8.8) and return real answer
5. Block page server on port 80 shows the "Access Blocked" page

This is exactly how Pi-hole and OpenDNS work.
"""
import socket
import struct
import threading
import subprocess
import ctypes
import time
from core.logger import get_logger
from core.storage import Storage

log = get_logger("dns_server")

DNS_PORT       = 53
BLOCK_PAGE_IP  = "127.0.0.1"       # our local block page
UPSTREAM_DNS   = "8.8.8.8"         # Google DNS for forwarding
UPSTREAM_PORT  = 53
LOCAL_IP       = "127.0.0.1"

_storage: Storage = None


def _is_blocked(domain: str) -> bool:
    """Check if domain is on the block list."""
    if not _storage:
        return False
    domain  = domain.lower().rstrip(".")
    blocked = _storage.learned_patterns.get("blocked_senders", [])
    # check exact match and parent domain
    parts  = domain.split(".")
    parent = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    return domain in blocked or parent in blocked


def _parse_dns_query(data: bytes):
    """Extract domain name from DNS query packet."""
    try:
        # skip 12-byte header
        idx    = 12
        labels = []
        while idx < len(data):
            length = data[idx]
            if length == 0:
                break
            idx   += 1
            labels.append(data[idx:idx+length].decode("utf-8", errors="ignore"))
            idx   += length
        domain = ".".join(labels)
        # get query ID (first 2 bytes)
        qid = struct.unpack("!H", data[:2])[0]
        return domain, qid, idx + 1  # +1 for the null terminator
    except Exception:
        return None, None, None


def _build_block_response(data: bytes, qid: int) -> bytes:
    """
    Build a DNS response that points the domain to 127.0.0.1
    so the user sees our custom block page.
    """
    try:
        # DNS response header
        # QID | flags(response+authoritative) | QDCOUNT=1 | ANCOUNT=1 | NSCOUNT=0 | ARCOUNT=0
        flags    = 0x8400  # response, authoritative
        header   = struct.pack("!HHHHHH", qid, flags, 1, 1, 0, 0)

        # copy question section from query (everything after 12-byte header)
        question = data[12:]

        # answer section: pointer to question name + type A + class IN + TTL + IP
        answer = (
            b"\xc0\x0c"                     # pointer to question name
            + struct.pack("!HH", 1, 1)      # type A, class IN
            + struct.pack("!I", 60)          # TTL 60 seconds
            + struct.pack("!H", 4)           # rdlength = 4 bytes
            + socket.inet_aton(BLOCK_PAGE_IP) # 127.0.0.1
        )
        return header + question + answer
    except Exception:
        return None


def _forward_to_upstream(data: bytes) -> bytes:
    """Forward DNS query to real DNS server and return response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(data, (UPSTREAM_DNS, UPSTREAM_PORT))
        response, _ = sock.recvfrom(4096)
        sock.close()
        return response
    except Exception:
        return None


def _handle_query(data: bytes, addr: tuple, sock: socket.socket):
    """Process a single DNS query."""
    domain, qid, _ = _parse_dns_query(data)
    if not domain or not qid:
        return

    if _is_blocked(domain):
        # return our local IP — user will see block page
        response = _build_block_response(data, qid)
        if response:
            sock.sendto(response, addr)
            log.info(f"DNS blocked: {domain} → {BLOCK_PAGE_IP}")
    else:
        # forward to real DNS
        response = _forward_to_upstream(data)
        if response:
            sock.sendto(response, addr)


def start_dns_server(storage: Storage):
    """Start the DNS server on port 53."""
    global _storage
    _storage = storage

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LOCAL_IP, DNS_PORT))
        log.info(f"DNS server listening on {LOCAL_IP}:{DNS_PORT}")

        def _serve():
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    t = threading.Thread(
                        target=_handle_query,
                        args=(data, addr, sock),
                        daemon=True)
                    t.start()
                except Exception as e:
                    log.debug(f"DNS server error: {e}")

        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        return True

    except PermissionError:
        log.warning(
            "DNS server needs Administrator rights (port 53). "
            "Run ThreatShield as Administrator to enable DNS filtering.")
        return False
    except Exception as e:
        log.error(f"DNS server start failed: {e}")
        return False


def configure_windows_dns(enable: bool = True):
    """
    Set Windows DNS to use our local server (127.0.0.1)
    or restore to automatic (DHCP).
    Requires Administrator.
    """
    try:
        if enable:
            # set DNS to our local server on all interfaces
            cmd = (
                'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | '
                'ForEach-Object { '
                '  Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex '
                '  -ServerAddresses ("127.0.0.1","8.8.8.8") '
                '}'
            )
            log.info("Configuring Windows DNS to use ThreatShield DNS server")
        else:
            # restore to DHCP/automatic
            cmd = (
                'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | '
                'ForEach-Object { '
                '  Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex '
                '  -ResetServerAddresses '
                '}'
            )
            log.info("Restoring Windows DNS to automatic")

        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, timeout=15)

        if result.returncode == 0:
            # flush DNS cache
            subprocess.run(["ipconfig", "/flushdns"],
                           capture_output=True, timeout=5)
            log.info("Windows DNS configured successfully")
            return True
        else:
            log.warning(
                f"DNS configuration failed: "
                f"{result.stderr.decode(errors='ignore')}")
            return False

    except Exception as e:
        log.error(f"DNS configuration error: {e}")
        return False
