### CTF Playbook - AD & Network Quick Checks
AD/Kerberos/PKI fast probes:<br>
 - SPNs: `impacket-GetUserSPNs -request -dc-ip <DC> <domain>/<user>`<br>
# Network Vulnerabilities (AD / Kerberos / Protocols)

This file contains network and directory-service vulnerability variants.

- Web + API vulnerabilities (including GraphQL) live in [README.md](README.md).
- OS/container/host vulnerabilities live in [OS_specific.md](OS_specific.md).
- Cloud provider-specific issues (AWS/Azure/GCP) live in [Cloud.md](Cloud.md).

## Active Directory (AD) & Windows Domain
- AS-REP: `impacket-GetNPUsers -dc-ip <DC> <domain>/ -usersfile users.txt`<br>
- NTLM relay prechecks: SMB signing off, EPA/channel binding gaps; try `ntlmrelayx.py -t ldap://<DC> --escalate-user`<br>
- ADCS: enumerate templates/HTTP enrollment; test ESC patterns; relay to HTTP endpoints where viable<br>
- DNS: zone transfer `dig @<ns> <zone> AXFR`; dangling CNAME takeover<br>
- LDAP: StartTLS/signing checks: `ldapsearch -ZZ` vs `-x`; simple binds over cleartext<br>
- BloodHound: ingest, then query shortest paths and RBCD edges<br>

### AD Recon & Enumeration
Anonymous LDAP Bind Enabled<br>
LDAP/GC Enumeration (users, groups, computers)<br>
SMB Null Session Enumeration<br>
NetBIOS/LLMNR/NBNS Enumeration<br>
ADCS/PKI Enumeration (templates, CAs)<br>
LLMNR/NBNS Poisoning (Responder-style credential capture)<br>
Group Policy Enumeration (GPO links, permissions, startup scripts)<br>
SMB Share Enumeration (SYSVOL/NETLOGON/script shares)<br>
SPN Enumeration (service accounts and ticket surface)<br>

### Kerberos Attacks
Kerberoasting (SPN ticket cracking)<br>
AS-REP Roasting (pre-auth disabled)<br>
Kerberos Pre-auth Disabled<br>
Pass-the-Ticket (PTT)<br>
Overpass-the-Hash (OPTH)<br>
Golden Ticket (krbtgt compromise)<br>
Silver Ticket (service ticket forge)<br>
Kerberos Delegation Abuse - Unconstrained<br>
Kerberos Delegation Abuse - Constrained<br>
Kerberos Delegation Abuse - RBCD (Resource-Based Constrained Delegation)<br>
Kerberos PAC Abuse / Privilege Attribute Certificate manipulation<br>
KDC/Service Principal Misconfiguration<br>
Kerberos - RC4/Weak Encryption Enabled (easier cracking)<br>
Kerberos - DES Enabled / Legacy Crypto Allowed<br>
Kerberos - No PAC Validation / Resource PAC Confusion (environment dependent)<br>
Kerberos - Delegation via SPN/Account Control Misconfig (TRUSTED_FOR_DELEGATION flags)<br>
Kerberos S4U2Self / S4U2Proxy Abuse (service impersonation chains)<br>
User-to-User (U2U) Ticket Abuse (edge cases in constrained flows)

### NTLM Attacks
Pass-the-Hash (PTH)<br>
NTLM Relay (SMB/HTTP/LDAP)<br>
NTLM Relay to LDAP (no signing/channel binding)<br>
NTLM Relay to ADCS (ESC-style relay abuse)<br>
NTLMv1 Enabled / Downgrade<br>
LM Hash Enabled<br>
NTLM Signing Disabled (SMB signing off)<br>
Extended Protection for Authentication (EPA) Missing<br>
LDAP Channel Binding Missing (enables relays in some environments)<br>
NTLM Relay Preconditions (SMB signing off, EPA/CB gaps, coercion path exists)<br>
NTLM Coercion Primitives (printer/EFSRPC/DFS/other coercion to force auth)<br>
PrinterBug / MS-RPRN Coercion (Spooler service exposure required)<br>
PetitPotam / EfsRpc / DFSCoerce variants (coerce auth to relay targets)

### ADCS / PKI (Certificate Services)
ADCS Template Misconfiguration (ESC patterns)<br>
ESC1 - Enrollee supplies subject/SAN<br>
ESC2 - Any purpose EKU / weak constraints<br>
ESC3 - Enrollment agent abuse<br>
ESC4 - Weak permissions on templates<br>
ESC5 - Weak permissions on CA/PKI objects<br>
ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 enabled<br>
ESC7 - Vulnerable CA permissions (ManageCA/ManageCertificates)<br>
ESC8 - NTLM relay to HTTP enrollment endpoints<br>
Weak Certificate Mapping (UPN/SID mapping abuse)<br>
Alternate Security Identities (altSecurityIdentities) Misuse / Mapping Confusion<br>
ADCS Web Enrollment / CEP/CES Exposed (auth weaknesses / relay surface)<br>
Certificate Template Manager Approval Disabled (anyone can enroll)<br>
Certificate Template EKU Confusion (client auth allowed unexpectedly)<br>
NTAuth Store Misconfiguration / Trusting Rogue CAs<br>

### AD Replication & Directory Abuse
DCSync (replication rights abuse)<br>
DCShadow (rogue DC object injection)<br>
SIDHistory Abuse<br>
GPO/GPP Abuse (cpassword in SYSVOL)<br>
LAPS Misconfiguration (readable local admin passwords)<br>
LAPS/Windows LAPS Over-Delegation (read passwords broadly)<br>
SYSVOL Script Abuse (writable logon/startup scripts)<br>

### AD Trusts / Forest Boundaries
Insecure Inter-Forest Trusts (SID filtering disabled / trust abuse)<br>
Trust Key Compromise (TDO abuse)<br>
Cross-Domain Privilege via Misconfigured Trust Delegations<br>

### AD Authorization / ACL Abuse
ACL Abuse - GenericAll / GenericWrite on Users/Groups/Computers<br>
ACL Abuse - WriteDACL / WriteOwner / Take Ownership on Privileged Objects<br>
ACL Abuse - AddMember / Self-Membership via Misdelegated Rights<br>
ACL Abuse - RBCD via msDS-AllowedToActOnBehalfOfOtherIdentity Write Access<br>
GPO Permission Abuse (edit GPO linked to privileged OUs)<br>
Computer Account Quota Abuse (MachineAccountQuota pivoting)<br>

## Protocols & Network Services

### Name Resolution / Auto-Discovery
LLMNR/NBNS Poisoning (Responder-style credential capture)<br>
WPAD / Proxy Auto-Discovery Abuse (NTLM capture/relay surface)<br>
DNS Search Suffix Abuse (spoof internal names via suffix/path confusion)<br>
Multicast DNS (mDNS) / Bonjour Spoofing (where used)<br>

### DNS
Zone Transfer Allowed (AXFR)<br>
Dynamic DNS Updates Abuse<br>
DNS Cache Poisoning<br>
DNS Rebinding<br>
Wildcard DNS (*) Misconfiguration<br>
Subdomain Takeover (dangling CNAME)<br>
DNSSEC Misconfiguration / Validation Disabled<br>

### SMB
SMB Signing Disabled<br>
SMBv1 Enabled (legacy)<br>
Anonymous Share Access<br>
Writable Shares (dropper/persistence)<br>
Named Pipe Exposure / Misuse<br>
SMB Signing Not Required on Clients/Servers (relay surface)<br>
SMB Credential Harvesting via UNC Paths (\\attacker\share triggers auth)<br>
SMB Guest Access Enabled / Weak Guest Policies<br>

### LDAP
LDAP Signing Disabled<br>
LDAPS Not Enforced / StartTLS Missing<br>
Anonymous / Weak Bind Policies<br>
LDAP Simple Binds Allowed Over Cleartext (credential exposure)<br>

### RDP
RDP Exposed to Internet<br>
Weak NLA / NLA Disabled<br>
Credential Stuffing on RDP<br>
RDP Gateway Misconfiguration (RDG exposed / weak policies)<br>

### Web Proxies / Auth (HTTP)
Open Proxy / Forward Proxy Exposure<br>
Proxy Authentication Downgrade (Negotiate -> NTLM)<br>
Kerberos/NTLM Auth Reflection via Proxy Misconfig<br>

### VPN / Remote Access
VPN Split Tunneling Misconfiguration (internal routes leak / pivot paths)<br>
Weak MFA / Missing MFA on Remote Access Gateways<br>
Client Config/Profile Credential Exposure (VPN profiles, certs, saved creds)<br>

### SNMP
SNMP v1/v2c Enabled<br>
Default Community Strings (public/private)<br>
SNMP Write Access<br>
SNMPv3 Not Enforced / Weak Auth/Priv Settings<br>

### Management Protocols
IPMI/iDRAC/iLO Exposed (default creds / weak auth)<br>
SSH Weak Ciphers / Password Auth Enabled on Admin Interfaces<br>
VNC Exposed / Weak Authentication<br>
Web Admin Panels Exposed (routers, switches, NAS)<br>

### NTP
NTP Misconfiguration<br>
Time Sync Abuse (auth failures, replay windows)<br>

### Email Protocols
SMTP Open Relay<br>
STARTTLS Downgrade / Missing<br>
IMAP/POP3 Cleartext Auth<br>
SPF/DKIM/DMARC Misconfiguration (spoofing risk)<br>

### Misc Network Protocol Issues
TLS Weak Cipher Suites on Network Services<br>
Insecure Legacy Protocols (Telnet, FTP)<br>
Default Credentials on Network Appliances<br>
Unauthenticated Management Interfaces<br>
IPv6 - Router Advertisement / DHCPv6 Spoofing (MITM / DNS takeover)<br>
DHCP Rogue Server / Option Injection (DNS/WPAD/routers)<br>
802.1X/NAC Misconfiguration (bypass segmentation)<br>
Wireless Enterprise Misconfig (EAP downgrade / weak PEAP/MSCHAPv2)<br>

### Network Pivoting / Segmentation Failures
Flat Network / Over-permissive East-West Access (lateral movement made easy)<br>
Overly Permissive Firewall Rules Between Tiers<br>
Proxy Misconfiguration (open forward proxy / internal-only proxy exposed)<br>
Misconfigured Jump Hosts (credential reuse + broad reach)<br>
