import time
from functools import lru_cache
from .utils import get_port_description

# scanner/port_details.py

PORT_DETAILS = {
    # Well-Known Ports (0-1023)
    20: {
        "name": "FTP Data Transfer",
        "description": "Used to transfer file data using the File Transfer Protocol (FTP). Works in conjunction with port 21.",
        "risk_level": "Medium/High",
        "usage": "Legacy file transfer. Should be avoided or secured with FTPS/SFTP due to plain text data transfer.",
    },
    21: {
        "name": "FTP Control",
        "description": "Used for sending FTP commands, authentication, and managing file transfer sessions (plain text).",
        "risk_level": "High",
        "usage": "Legacy control channel. Highly vulnerable to sniffers and brute-force attacks. Use SSH/SFTP or FTPS instead.",
    },
    22: {
        "name": "SSH",
        "description": "Secure Shell protocol for secure remote login, command execution, and file transfers (SFTP).",
        "risk_level": "Low/Medium",
        "usage": "Standard for remote server administration. Access should be limited by IP and secured with key-based authentication.",
    },
    23: {
        "name": "Telnet",
        "description": "Unencrypted protocol for text-based remote login. Transmits credentials and data in plain text.",
        "risk_level": "Critical",
        "usage": "Obsolete; strictly avoid in modern infrastructure. Use SSH (port 22).",
    },
    25: {
        "name": "SMTP",
        "description": "Simple Mail Transfer Protocol used for sending outgoing emails between mail servers (mail routing).",
        "risk_level": "Medium",
        "usage": "Common for mail servers and relays. Use encryption (STARTTLS or SMTPS on 465/587) and restrict relaying.",
    },
    53: {
        "name": "DNS",
        "description": "Domain Name System, resolves domain names to IP addresses (TCP for zone transfers, UDP for queries).",
        "risk_level": "Low",
        "usage": "Essential for all networking. Public DNS servers need protection against DNS amplification attacks.",
    },
    67: {
        "name": "DHCP Server",
        "description": "Dynamic Host Configuration Protocol server-side. Assigns IP addresses and network configuration to clients.",
        "risk_level": "Medium",
        "usage": "Used within local networks. Needs strict control to prevent rogue DHCP server attacks (starvation, spoofing).",
    },
    68: {
        "name": "DHCP Client",
        "description": "Dynamic Host Configuration Protocol client-side. Receives IP configuration from the DHCP server.",
        "risk_level": "Low",
        "usage": "Used by network clients to get an IP address.",
    },
    69: {
        "name": "TFTP",
        "description": "Trivial File Transfer Protocol, a simple UDP-based protocol for transferring configuration or boot files.",
        "risk_level": "High",
        "usage": "Used for diskless workstations and network booting. Provides no security, so restrict access heavily.",
    },
    80: {
        "name": "HTTP",
        "description": "Hypertext Transfer Protocol for transferring web content in plain text (unencrypted).",
        "risk_level": "High",
        "usage": "Used by web servers. Must be configured to **redirect all traffic to HTTPS** (port 443) for security.",
    },
    110: {
        "name": "POP3",
        "description": "Post Office Protocol v3, used by email clients to retrieve and typically delete emails from a mail server.",
        "risk_level": "Medium/High",
        "usage": "Legacy email retrieval. Use IMAP (143) or a secure version (**POP3S on 995**). Credentials are often unencrypted.",
    },
    123: {
        "name": "NTP",
        "description": "Network Time Protocol for synchronizing computer clocks across the network.",
        "risk_level": "Low",
        "usage": "Essential for logs, security protocols, and system functionality. Public access should be limited to prevent **NTP amplification attacks**.",
    },
    139: {
        "name": "NetBIOS Session",
        "description": "NetBIOS Session Service, used for file and printer sharing in older Windows networks, and for session establishment.",
        "risk_level": "High",
        "usage": "Legacy Windows sharing. Mostly superseded by SMB (445). Must be blocked from external access.",
    },
    143: {
        "name": "IMAP",
        "description": "Internet Message Access Protocol, used by email clients to manage and retrieve emails while keeping them on the server.",
        "risk_level": "Medium/High",
        "usage": "Common email retrieval. Should be secured using **IMAPS (port 993)** to encrypt communication.",
    },
    161: {
        "name": "SNMP",
        "description": "Simple Network Management Protocol, used for monitoring and managing network devices (agent port).",
        "risk_level": "Medium",
        "usage": "Used by network management systems. SNMPv1/v2 are insecure (plaintext community strings); use **SNMPv3**.",
    },
    389: {
        "name": "LDAP",
        "description": "Lightweight Directory Access Protocol, used for querying and modifying directory services (e.g., Active Directory).",
        "risk_level": "Medium",
        "usage": "Used for user authentication and authorization. Must be secured with **LDAPS (port 636)** for transmission of credentials.",
    },
    443: {
        "name": "HTTPS",
        "description": "Secure HTTP using **TLS/SSL encryption** for safe and private web communication.",
        "risk_level": "Low",
        "usage": "Standard for all secure web traffic, APIs, and encrypted tunnels.",
    },
    445: {
        "name": "SMB",
        "description": "Server Message Block protocol (Microsoft-DS), used for file and printer sharing on Windows networks and Active Directory.",
        "risk_level": "Critical",
        "usage": "Critical for Windows networking. Public exposure is extremely dangerous (e.g., EternalBlue). Limit strictly to internal networks.",
    },
    465: {
        "name": "SMTPS (Legacy)",
        "description": "Secure SMTP (Simple Mail Transfer Protocol) over SSL/TLS, often used for email message submission.",
        "risk_level": "Low",
        "usage": "Legacy standard, though still used. **Port 587 (Submission)** is the modern, official replacement for clients.",
    },
    587: {
        "name": "SMTP Submission",
        "description": "SMTP message submission agent, used by email clients to submit outgoing mail to a server, typically with **STARTTLS** encryption.",
        "risk_level": "Low",
        "usage": "The modern, official port for email clients sending mail. Requires authentication and encryption.",
    },
    636: {
        "name": "LDAPS",
        "description": "Lightweight Directory Access Protocol over TLS/SSL, providing secure, encrypted directory services.",
        "risk_level": "Low",
        "usage": "Secure version of LDAP. Essential for securely authenticating users and querying directories across a network.",
    },
    993: {
        "name": "IMAPS",
        "description": "Internet Message Access Protocol over TLS/SSL, providing secure, encrypted email retrieval and management.",
        "risk_level": "Low",
        "usage": "Secure version of IMAP. Recommended standard for email clients.",
    },
    995: {
        "name": "POP3S",
        "description": "Post Office Protocol v3 over TLS/SSL, providing secure, encrypted email retrieval.",
        "risk_level": "Low",
        "usage": "Secure version of POP3. Recommended standard for email clients that download and delete messages.",
    },
    
    # Registered Ports (1024-49151)
    1433: {
        "name": "MS SQL",
        "description": "Default port for Microsoft SQL Server database connections.",
        "risk_level": "Medium",
        "usage": "Used by applications to connect to the MS SQL database. Should be firewalled and limited to internal IPs, often secured with TLS.",
    },
    1723: {
        "name": "PPTP",
        "description": "Point-to-Point Tunneling Protocol, a legacy VPN protocol.",
        "risk_level": "High",
        "usage": "Obsolete VPN protocol with known security flaws. **Do not use**; replace with modern VPN solutions (e.g., OpenVPN, WireGuard).",
    },
    3306: {
        "name": "MySQL Database",
        "description": "Default port for connections to a MySQL or MariaDB database server.",
        "risk_level": "Medium",
        "usage": "Should be firewalled, limited to loopback or internal IPs, and secured with strong credentials and TLS/SSL.",
    },
    3389: {
        "name": "RDP",
        "description": "Remote Desktop Protocol, used for graphical remote access to Windows machines.",
        "risk_level": "High",
        "usage": "Commonly attacked port. Should be protected with **Network Level Authentication (NLA)** and ideally placed behind a VPN or gateway.",
    },
    5432: {
        "name": "PostgreSQL",
        "description": "Default port for PostgreSQL database server connections.",
        "risk_level": "Medium",
        "usage": "Should be firewalled and password-protected, limited to internal IPs only.",
    },
    5900: {
        "name": "VNC",
        "description": "Virtual Network Computing (VNC) protocol, used for remote graphical desktop sharing.",
        "risk_level": "Medium/High",
        "usage": "Used for remote control. Should be secured with strong passwords, encryption (SSH tunneling), and limited access, as traffic is often unencrypted by default.",
    },
    8080: {
        "name": "HTTP Alternate",
        "description": "Alternative port for HTTP, often used for web proxies, testing, or secondary web services/application servers.",
        "risk_level": "Medium",
        "usage": "Used when the primary web server uses port 80/443. Security considerations are the same as for ports 80 and 443.",
    },
    8443: {
        "name": "HTTPS Alternate",
        "description": "Alternative port for HTTPS, often used for secondary secure web interfaces, like administration panels.",
        "risk_level": "Low",
        "usage": "Standard for secure alternative web traffic. Security considerations are the same as for port 443.",
    },
}

def enrich_scan_results(results):
    """
    This function adds detailed information (from PORT_DETAILS or Gemini)
    to the list of scanned ports.
    """
    enriched = []
    for r in results:
        port_info = PORT_DETAILS.get(r['port'], None)
        if port_info:
            r.update(port_info)
        else:
            r['name'] = f"Port {r['port']}"
            r['description'] = get_port_description(r['port'])
            r['risk_level'] = "AI Generated"
            r['usage'] = "Information fetched via Gemini"
        enriched.append(r)
    return enriched
@lru_cache(maxsize=1024)
def get_static_description(port: int):
    return PORT_DETAILS.get(port)

