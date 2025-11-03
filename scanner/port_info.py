import time
from functools import lru_cache

PORT_DETAILS  = {
    20: "FTP Data Transfer — used to transfer files; often paired with port 21.",
    21: "FTP Control — file transfer protocol control channel (plain text).",
    22: "SSH — Secure remote login; supports key-based auth; common for admin access.",
    23: "Telnet — plaintext remote login; insecure and rarely used in modern infra.",
    25: "SMTP — Mail transfer; servers accepting outbound mail or relays.",
    53: "DNS — Domain Name System; UDP/TCP for queries and zone transfers.",
    67: "DHCP Server - assigns IP addresses to clients.",
    68: "DHCP Client - receives IP configuration from server.",
    80: "HTTP — Web traffic, unencrypted; often indicates web servers.",
    110: "POP3 - retrieves emails from mail servers.",
    123: "NTP - Network Time Protocol for clock synchronization.",
    143: "IMAP - Internet Message Access Protocol for email retrieval.",
    161: "SNMP - Simple Network Management Protocol for device monitoring.",
    389: "LDAP - Lightweight Directory Access Protocol for directory services.",
    443: "HTTPS — Encrypted web traffic using TLS/SSL.",
    445: "SMB - Server Message Block for file sharing on Windows.",
    5432: "PostgreSQL - default port for PostgreSQL databases.",
    3306: "MySQL — Database server default port.",
    3389: "RDP — Windows Remote Desktop; sensitive if exposed to internet.",
    8080: "HTTP Alternate — commonly used for web proxies or alternative web services.",
}

# Simple local cache wrapper (LRU). Use persistent DB caching for production.
@lru_cache(maxsize=1024)
def get_static_description(port: int):
    return PORT_DETAILS_STATIC.get(port)

