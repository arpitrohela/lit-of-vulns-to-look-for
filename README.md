# list-of-vulns-to-look-for
Vulnerability checklist to go through for each web application.

#### See also
- OS/container/host: [OS_specific.md](OS_specific.md)
- AD/Kerberos/protocols: [Network.md](Network.md)
- Cloud (AWS/Azure/GCP): [Cloud.md](Cloud.md)

## CTF Playbook - Web Quick Checks
#### Enumeration & fast probes for common web surfaces
- Recon: ffuf/feroxbuster for paths; check `.git/`, backups, source maps
- Auth: try default creds, login CSRF/forced login, weak JWT (alg:none, HS/RS confusion)
- IDOR: increment IDs, try tenant headers, bulk endpoints with mixed IDs
- SQLi: error/time/boolean; quick `sqlmap -u <url> --batch` on suspect params
- Command/Code Injection: whitespace/IFS/encoding bypass; force outbound `curl`/DNS callbacks
- XSS: DOM sinks (innerHTML/insertAdjacentHTML), CSP gaps, JSONP callbacks
- Uploads: double extensions, SVG/HTML polyglots, content-sniffing mismatches
- SSRF: metadata URLs, IP encodings (octal/hex), redirect chains to forbidden hosts
- Smuggling/Desync: CL.TE/TE.CL probes; cache poisoning via unkeyed headers

#### Useful one-liners
- Path brute: `ffuf -u https://host/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
- Params diff: `wfuzz -c -z file,/usr/share/wordlists/SecLists/Discovery/WEB-Content/burp-parameter-names.txt --hc 404 https://host/page?FUZZ=1`
- Out-of-band test: embed attacker domain in payloads; monitor dnslog/collaborator

## Injection Vulnerabilities

### Code Injection
- Code Injection (CWE-94)
- Code Injection - PHP eval()
- Code Injection - Python exec/eval
- Code Injection - JavaScript eval
- Code Injection - Java Runtime.exec
- Code Injection - Ruby eval
- Code Injection - ASP.NET Eval
- Code Injection - Template Code Injection
- Code Injection - Dynamic Class Loading
- Code Injection - Reflection-based
- Code Injection - Expression Injection (OGNL/SpEL/MVEL/JEXL/EL)
- Code Injection - Expression Injection via Data Binding (framework binding language quirks)
- Code Injection - Deserialization-to-Exec Chain (type confusion to eval/exec)
- Code Injection - Encoding/Normalization Bypass (payload decoded after validation)
- Code Injection - Polyglot Payloads (works across multiple parsers/contexts)
- Code Injection - Sandbox Escape (template sandbox / restricted eval bypass)

### Command Injection
- Command Injection - Generic (CWE-77)
- Command Injection - Blind (Out-of-band)
- Multiple File Fields with Same Name (unexpected overwrite/merge)
- RFC 5987 `filename*=` Encoding Handling (parser support differences)
- Content-Transfer-Encoding Quirks (base64/quoted-printable acceptance differences)
- Trailing Whitespace in Boundary Lines (accept vs reject)
- Chunked + Multipart Combination Edge Cases (frontend/backend disagreement)
- CRLF Variants Inside Part Headers (\r\n vs \n parsing)
- Command Injection - Space Bypass
- Command Injection - Quote Escape
- Command Injection - Backtick Execution
- Command Injection - Command Substitution $(cmd)
- Command Injection - Variable Expansion Abuse
- WebSocket Message Injection / Lack of server-side validation
- WebSocket `permessage-deflate` Resource Exhaustion (compression bombs / CPU spikes)
- WebSocket Binary/Text Type Confusion (validator assumes one type)
- Command Injection - Encoding Bypass
- Command Injection - Pipe (|) Chaining
- Command Injection - Semicolon (;) Chaining
- Command Injection - AND (&&) Chaining
- Command Injection - OR (||) Chaining
- Command Injection - Wildcard Abuse
- Command Injection - Glob Pattern Abuse
- HTTP/3 / QUIC Misconfiguration (alt-svc upgrades, proxy translation gaps)
- HTTP/3 alt-svc Cache Poisoning (persisted upgrade hints across origins)
- HTTP/3 Pseudo-header Normalization Differences (authority/path handling)
- TLS 1.3 0-RTT Replay Risk (state-changing requests accepted in early data)
- Command Injection - CR Injection (\r / %0d) as Separator
- Command Injection - Tab/IFS Separator Bypass (\t / ${IFS})
- Command Injection - Brace Expansion Abuse (shell-specific)
- Command Injection - Command Concatenation without Spaces (shell parsing quirks)
- WebRTC Peer Connection Trust Issues (origin/permission flows)
- SSE Event ID Reuse / Stream Resumption Mix-up (delivers other users’ events)
- SSE `Cache-Control` / `Vary` Misuse (public caches serving private streams)
- TURN Credential Exposure / Reuse (static creds leaked in client code)
- WebRTC Data Channel AuthZ Missing (unauthenticated peer message acceptance)
- Command Injection - Windows CMD Metacharacters (&, |, ^, %VAR%)
- Command Injection - PowerShell Injection (subexpressions, encoded command, argument parsing)
- Command Injection - PowerShell EncodedCommand Confusion (UTF-16LE base64 / decoding layers)
- Command Injection - Argument Injection (inject flags/args into safe binary execution)
- Command Injection - URL/Double URL Encoding of Metacharacters
- Command Injection - Unicode Normalization Bypass (lookalike separators/quotes)

- OAuth Device Code Flow Misconfiguration (broad device auth, user code reuse, polling endpoint auth gaps)
- Device Flow `user_code` Reuse Across Accounts (phishing + session swap)
- `verification_uri_complete` Open Redirect/Link Spoofing (social engineering vectors)
- Device Flow Polling Endpoint Missing AuthZ (bind to client/user/session)
- Polling Interval Ignored (aggressive polling -> DoS or rate bypass)
- CRLF Injection (CWE-93)
- CRLF Injection - HTTP Header
- CRLF Injection - Email Header
- CRLF Injection - Log Injection
- CRLF Injection - Request Smuggling
- CRLF Injection - Response Splitting (CWE-113 overlap)
- CRLF Injection - Set-Cookie Injection / Cookie Fixation via Header Injection
- CRLF Injection - Location/Header Redirect Manipulation
- CDN/Third-Party Widget Trust (script injection via provider compromise)
- SRI + `crossorigin` Nuance (anonymous vs use-credentials affects integrity checks)
- Registry Substitution/Mirror Attacks (alternate registry serving malicious packages)
- Lockfile Integrity & Pinning (package-lock/shrinkwrap not enforced or absent)
- Self-hosted Library Integrity (hash/pin for internal CDN artifacts)
- CRLF Injection - Encoded Newlines (%0d%0a / %0a / %0d) Bypass
- CRLF Injection - Double-Encoded Newlines (%250d%250a) Bypass
- CRLF Injection - Unicode Newline Variants (U+000A/U+000D equivalents) Confusion
- CRLF Injection - Folding/Obs-Fold Parsing Differences (legacy header folding)
- iOS/Android Keychain/Keystore Misuse (unencrypted storage, broad ACLs)
- iOS Universal Links Misconfiguration (domain association not enforced)
- Android `android:autoVerify` Mismatch (links not verified, attacker-controlled)
- `intent:` Scheme Tricks (parameter injection to launch insecure flows)
- Exported Components Chain (Activities/Services/Receivers reachable unauthenticated)
- WebView SSL Error Handler Override (proceed on certificate errors)

### Injection - Special Elements
- Failure to Sanitize Special Elements into a Different Plane (Special Element Injection) (CWE-75)
- Special Element Injection - HTML Context
- Content Script XSS (DOM injection on arbitrary sites)
- `chrome.storage.sync` Sensitive Data Exposure (synced across accounts/devices)
- Remote Update/Sideload Supply Chain (auto-updates from untrusted sources)
- Relaxed CSP in Extensions (allow-eval/inline enabling code injection)
- Special Element Injection - CSS Context
- Special Element Injection - URL Context
- Special Element Injection - JSON Context (string breakouts / parser differences)
- Special Element Injection - XML Context (attribute/element/entity contexts)
- Special Element Injection - CSV/Spreadsheet Formula Context
- Special Element Injection - Template/Expression Context
- Special Element Injection - Encoding/Normalization Confusion (decode after validate)
- ESI Injection (Edge Side Includes) leading to cache poisoning / content splicing
- Client Hints Unkeyed (Sec-CH-UA, Sec-CH-UA-Platform, viewport) causing variant mix-ups
- Authorization Header Caching Misconfig (caches responses despite auth)
- CDN Cache Key Misconfiguration (missing user/tenant/role dimensions)
### LDAP Injection
- LDAP Injection (CWE-90)
- LDAP Injection - Query Manipulation
- LDAP Injection - Filter Bypass
- LDAP Injection - Wildcard Bypass
- LDAP Injection - Blind LDAP Injection
- LDAP Filter Injection
- LDAP Injection - Unescaped Special Chars (*, (, ), \\, \0) (RFC 4515/4514 issues)
- Content Sniffing at Edge/CDN vs Origin Mismatch (X-Content-Type-Options absent)
- Office Remote Template Injection (DOCX/RTF referencing remote resources)
- Image ICC Profile Injection (metadata parsers code paths)
- LDAP Injection - Attribute Injection (inject additional filter clauses)
- LDAP Injection - Null Byte Truncation (downstream bindings/parsers)
- LDAP Injection - Unicode Normalization / Case Folding Bypass (schema matching quirks)
- LDAP Injection - URL Encoding vs LDAP Escaping Mismatch (decode layer disagreement)

### XPath / XQuery / XML Path Injection
- XPath Injection
- XPath Injection - Predicate Manipulation
- XPath Injection - Encoding/Normalization Bypass (decode after validate)
- XQuery Injection
- XQuery Injection - Function/Module Abuse (where supported)

### ORM / Query Language Injection
- HQL/JPQL Injection (Hibernate/JPA)
- LINQ Injection (dynamic query composition)
- SQL/ORM - ORDER BY / LIMIT / Column Name Injection (string-built query fragments)

#### Evidence to Capture (for quick reporting)
- Screenshots of pivotal responses (admin views, other users’ data)
- Raw request/response pairs showing exploit (headers, body, cookies)
- Cache headers (`Cache-Control`, `Vary`, `Age`) demonstrating poisoning/mix-ups
- Auth artifacts (JWTs, cookies) and validation gaps (missing `aud`/`iss`)
- OOB callback logs (DNS/HTTP hits with correlation IDs)
- Query Language Injection - Encoding/Normalization Confusion (app/ORM/driver mismatch)

### OS Command Injection
- OS Command Injection (CWE-78)
- OS Command Injection - Linux/Unix
- OS Command Injection - Windows
- OS Command Injection - macOS
- OS Command Injection - Shellshock-Style Environment Parsing (if applicable)
- OS Command Injection - Argument Injection into Interpreters (bash/python/perl flags)

#### Evidence to Capture
- Cart/server totals mismatch screenshots (before/after tamper)
- Parallel request logs showing double-spend/duplicate actions
- Webhook replay traces (idempotency keys missing or ignored)
- Audit logs/receipts proving action without proper authorization
- OS Command Injection - Encoding/Decoding Layer Mismatch (proxy/framework/app)

### Reflected File Download
- Reflected File Download (RFD) {json endpoint or json api}
- RFD - CSV Injection
- RFD - JSON Breakout
- RFD - Content-Disposition Bypass

### Remote & Local File Inclusion
- Remote File Inclusion (CWE-98)
- Remote File Inclusion - PHP Wrappers (php://)
- Remote File Inclusion - Input Filters Bypass
- Remote File Inclusion - Null Byte Injection
- Remote File Inclusion - Log File Inclusion
- Remote File Inclusion - URL Scheme Abuse (gopher://, dict://, etc.)
- Local File Inclusion (LFI) via Path Traversal
- LFI - Filter Bypass
- LFI - Encoding Bypass
- LFI - Case Sensitivity Bypass
- LFI - Null Byte Truncation (legacy file APIs / extension checks)
- LFI - Double Decode / Mixed Encoding Traversal
- LFI - Windows/UNC/Device Path Inclusion (platform-specific)
- RFI - Redirect/SSRF-Assisted Inclusion (follow redirects into restricted targets)
- RFI - MIME/Content-Type Confusion in Include Handler (remote content treated as code)

### Resource Injection
- Resource Injection (CWE-99)
- Resource Injection - Credential Injection
- Resource Injection - Connection String Injection

### SQL Injection (CWE-89)
- SQL Injection (CWE-89)
- SQL Injection - Error-based
- SQL Injection - Union-based
- SQL Injection - Blind
- SQL Injection - Time-based Blind
- SQL Injection - Boolean-based Blind
- SQL Injection - Stacked Queries
- SQL Injection - Polyglot
- SQL Injection - Second-order
- SQL Injection - Blind with Out-of-Band
- SQL Injection - OOB via DNS
- SQL Injection - OOB via HTTP
- SQL Injection - OOB via SMB (UNC path injection on MSSQL)
- SQL Injection - Inference via Error Messages (verbose error exploitation)
- SQL Injection - Heavy Query DoS (expensive joins/cartesian products for timing)
- SQL Injection - Comment Bypass (-- / # / /* */)
- SQL Injection - Quote Escape Bypass
- SQL Injection - String Delimiter Bypass
- SQL Injection - Space Bypass (/**/, %09, %0a)
- SQL Injection - Keyword Case Variation
- SQL Injection - Function Alias Bypass
- SQL Injection - Encoding Bypass (Hex, URL, Double)
- SQL Injection - Normalization Bypass
- SQL Injection - UNION Bypass
- SQL Injection - WHERE Clause Abuse
- SQL Injection - ORDER BY Bypass
- SQL Injection - GROUP BY Bypass
- SQL Injection - HAVING Clause Injection
- SQL Injection - LIMIT Bypass
- SQL Injection - Parameter Type Confusion (numeric vs string parsing differences)
- SQL Injection - JSON/Array Parameter SQLi (ORM or query builder quirks)
- SQL Injection - LIKE/ILIKE Wildcard Abuse
- SQL Injection - Collation/Charset Confusion (unicode normalization impacts comparisons)
- SQL Injection - Truncation / Null Byte Effects in DB Driver Layers
- SQL Injection - WAF Bypass via Encoding/Obfuscation (double decode, comments, whitespace)
- SQL Injection - HTTP Parameter Pollution-Assisted SQLi (first/last wins differences)
- SQL Injection - Order By/Sort Parameter Injection (dynamic ORDER BY strings)
- SQL Injection - Identifier Injection (table/column name injection, quoting rules)

### XML Injection & XXE
- XML Entity Expansion (CWE-776)
- XML Entity Expansion - Billion Laughs
- XML Entity Expansion - Quadratic Blowup
- XML External Entities (XXE) (CWE-611)
- XML External Entities (XXE) - Classic
- XML External Entities (XXE) - Blind
- XML External Entities (XXE) - Out-of-band
- XXE - Parameter Entity
- XXE - External DTD
- XXE - File Disclosure via FTP
- XXE - Java XXE Gadgets
- XML Injection (CWE-91)
- XML Injection - Attribute Injection
- XML Injection - Element Injection
- XXE - Encoding/Normalization Bypass (different decoder before XML parser)
- XXE - Protocol Trickery (file://, http(s)://, ftp://, jar:, gopher: where supported)
- XXE - XInclude Injection (if XInclude processing enabled)
- XXE - SSRF via External Entity Resolution

### Template Injection
- Template Injection - Server-Side (SSTI)
- Template Injection - Client-Side (CSTI)
- Server-Side Template Injection (Jinja2, ERB, Twig, etc.)
- Expression Language Injection (EL Injection)
- EL Injection - Spring EL
- EL Injection - OGNL Injection
- EL Injection - MVEL Injection



## Cross-Site Scripting (XSS) (CWE-79)

### XSS - Primary Variants
- Cross-site Scripting (XSS) - DOM (CWE-79)
- Cross-site Scripting (XSS) - Reflected (CWE-79)
- Cross-site Scripting (XSS) - Stored (CWE-79)
- Cross-site Scripting (XSS) - Generic (CWE-79)
- Cross-site Scripting (XSS) - Mutation (mXSS)
- Cross-site Scripting (XSS) - Self XSS
- Cross-site Scripting (XSS) - Universal XSS (UXSS)
- Cross-site Scripting (XSS) - Blind XSS (out-of-band callback / victim is admin tooling)
- Cross-site Scripting (XSS) - Persistent DOM XSS (stored data later used by DOM sinks)

### XSS - Context-Specific
- Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) (CWE-80)
- XSS via HTML Context
- XSS via HTML Attribute Context (quoted/unquoted attributes)
- XSS via HTML URI Attribute Context (href/src/action/poster/srcdoc etc.)
- XSS via JavaScript Context
- XSS via JavaScript Template Literal Context (backticks, ${} interpolation)
- XSS via JSON-in-HTML Context (inline JSON then parsed, quote breaking)
- XSS via CSS Context
- XSS via URL Context
- XSS via Event Handlers
- XSS via HTML5 Events (onload, onerror, etc.)
- XSS via DOM Sink APIs (innerHTML/outerHTML/insertAdjacentHTML/document.write/srcdoc)

### XSS - Vector-Specific
- XSS via SVG
- XSS via HTML Injection (non-script tags that become script via parsing/mutation)
- XSS via Data URIs
- XSS via JavaScript Protocol (javascript:)
- XSS via VBScript Protocol (legacy IE contexts)
- XSS via Canvas
- XSS via Web Workers
- XSS via Service Workers
- XSS via Web Components
- XSS via Iframe
- XSS via Object Tag
- XSS via Embed Tag
- XSS via Markdown/BBCode Rendering
- XSS via JSONP / Script Include Reflection (callback parameter abuse)
- XSS via File Upload (HTML/SVG polyglot served with sniffable Content-Type)
- XSS via postMessage Handling (origin check bypass + DOM sink)
- XSS - Framework Gadgets (AngularJS sandbox escapes, React dangerouslySetInnerHTML, Vue moustache contexts)

### XSS - Encoding Bypass
- XSS via Double Encoding
- XSS via Multiple Decode Passes (double decode across proxy/framework/app)
- XSS via Unicode Encoding
- XSS via HTML Entity Encoding
- XSS via Character Reference
- XSS via Character Reference Edge Cases (no semicolon, mixed hex/dec, overlong sequences)
- XSS via Mixed Encoding
- XSS via UTF-7/UTF-8 Mismatch
- XSS via Legacy/Non-UTF8 Charset Confusion (Shift_JIS / ISO-2022-JP edge cases)
- XSS via JavaScript Escape Confusion (\\xNN, \\uNNNN, \\u{...} decoding differences)
- XSS via CSS Escape Confusion (CSS \HHHHH escapes)

### XSS - Filter Bypass
- XSS Using MIME Type Mismatch (CAPEC-209)
- XSS - Whitelist Bypass
- XSS - Regex Bypass
- XSS - Case Sensitivity Bypass
- XSS - Null Byte Injection
- XSS - Comment Injection
- XSS - Tag/Attribute Balancing (parser differential between filter and browser)
- XSS - Polyglot Payloads (works across multiple contexts)
- XSS - Sanitizer Differential (DOMPurify/bleach/etc. vs browser parsing)

### XSS - Advanced Variants
- Mutated XSS (mXSS)
- DOM Clobbering + XSS
- MathML-based XSS
- PDF XSS
- Flash-based XSS (if Flash exists)
- Encoding Confusion XSS
- Content Security Policy (CSP) Bypass via XSS
- XSS - CSP Gadget Abuse (nonce/hash reuse, JSONP endpoints, allowed script gadgets)
- XSS - Trusted Types Bypass / Missing Trusted Types (sink protections absent)
- XSS via Prototype Pollution -> DOM Sink (polluted config leads to dangerous rendering)



## Authentication & Password Management

### Authentication Bypass
- Authentication Bypass Using an Alternate Path or Channel (CWE-288)
- Authentication Bypass - Direct SQL Injection
- Authentication Bypass - Parameter Pollution
- Authentication Bypass - JWT Flaws
- Authentication Bypass - Cookie Manipulation
- Authentication Bypass - Default Credentials
- Authentication Bypass - Weak Verification
- Authentication Bypass - Logic Flaw
- Authentication Bypass - Client-Side Validation
- Authentication Bypass - Null/Empty Password
- Authentication Bypass - SSO/OIDC Misconfiguration (accept unsigned/none alg tokens, missing aud/iss checks)
- Authentication Bypass - OAuth Misconfiguration (implicit flow issues, code substitution, redirect URI tricks)
- Authentication Bypass - Account Linking Confusion (login with provider A links to victim account)
- Authentication Bypass - Email/Phone Verification Not Enforced (unverified accounts gain access)
- Authentication Bypass - “Remember Device” / Trusted Device Logic Flaw
- Authentication Bypass - Magic Link Reuse / Not Bound to Session/Device

### Brute Force
- Brute Force (CWE-307)
- Brute Force - Credential Stuffing
- Brute Force - Rate Limiting Bypass
- Brute Force - Distributed Attack
- Brute Force - Dictionary Attack
- Brute Force - Rainbow Table
- Brute Force - CAPTCHA Bypass
- Brute Force - CAPTCHA Assistance
- Brute Force - Account Lockout Bypass
- Brute Force - Timing Window Bypass

### Core Authentication Issues
- Improper Authentication - Generic (CWE-287)
- Missing Authentication for Critical Function (CWE-306)
- No Authentication on Admin Panels
- No Authentication on Sensitive APIs
- Auth - Weak Password Policy / No Password Complexity or Length Requirements
- Auth - Password Policy Bypass (Unicode, whitespace trimming, normalization differences)
- Auth - Username/Email Canonicalization Issues (case folding, dots/plus addressing confusion)
- Auth - Login CSRF / Forced Login (attacker logs victim into attacker account)

### Password Reset Attacks
- Password Reset Vulnerability
- Password Reset - Predictable Token
- Password Reset - Token Reuse
- Password Reset - Token Brute Force
- Password Reset - Token Expiration Bypass
- Password Reset - Email Enumeration
- Password Reset - Security Question Bypass
- Password Reset - Account Recovery Abuse
- Password Reset - Link Interception
- Password Reset - Token Not Bound to User/Session (swap token across accounts)
- Password Reset - Host Header Poisoning (reset link generated with attacker-controlled host)

### Account Lockout & Security
- Account Lockout Bypass
- Account Lockout - Timing Window Exploitation
- Account Lockout - Progressive Bypass
- Account Enumeration via Lockout

### Credential Change Issues
- Unverified Password Change (CWE-620)
- Password Change - No Old Password Verification
- Password Change - Session Fixation
- Password Change - CSRF
- Password Change - Does Not Invalidate Other Sessions/Tokens
- Password Change - Old Password Still Valid (race / eventual consistency)

### Password Recovery
- Weak Password Recovery Mechanism for Forgotten Password (CWE-640)
- Password Recovery - Weak Secret Questions
- Password Recovery - Recovery Code Reuse
- Password Recovery - Recovery Token Prediction

### Multi-Factor Authentication
- Two-Factor Authentication Bypass
- 2FA - SMS Interception
- 2FA - TOTP Predictability
- 2FA - Backup Code Reuse
- 2FA - Backup Code Prediction
- 2FA - QR Code Bypass
- 2FA - Push Notification Fatigue
- 2FA - Biometric Bypass
- 2FA - Hardware Token Spoofing
- 2FA - Recovery Code Exposure
- 2FA - Enrollment/Disable Not Re-Authenticated (change MFA settings without password)
- 2FA - Step-Up Auth Missing (sensitive action requires only 1st factor)
- 2FA - Rate Limit Missing on OTP Entry (online brute force)

### WebAuthn / FIDO2 Issues
- WebAuthn - rpId Misconfiguration (origin/domain mismatch bypass)
- WebAuthn - Challenge Reuse / Not Bound to Session/User
- WebAuthn - User Verification vs Presence Confusion (UV required but not enforced)
- WebAuthn - Attestation Trust Misconfigured / Unnecessarily Trusted
- WebAuthn - Duplicate Credential IDs / Account Linking Confusion
- WebAuthn - Resident Keys Handling Bugs (credential discovery and misuse)
- WebAuthn - allowCredentials Manipulation (empty list allows unexpected authenticators)
- WebAuthn - U2F `appid` Extension Confusion (legacy origin scope bypass)
- WebAuthn - `enterpriseAttestation` Misuse (over-trusting enterprise attestations)
- WebAuthn - `credProtect` Level Misconfiguration (credentials readable without UV)
- WebAuthn - CTAP1 vs CTAP2 Fallback Confusion (policy gaps across transports)
- WebAuthn - Passkey Sync Surfaces (cross-device synced credentials trust issues)

### CAPTCHA Issues
- Guessable Captcha (CWE-804)
- CAPTCHA - Image Recognition Bypass
- CAPTCHA - Weak Algorithm
- CAPTCHA - Reuse
- CAPTCHA - Time Window Bypass
- CAPTCHA - Audio CAPTCHA Bypass
- CAPTCHA - Accessibility Bypass

### Other Authentication Issues
- Phishing (CAPEC-98)
- Insecure Password Storage (in session/memory)
- Credential Logging
- Login Timing Attack
- Username Enumeration
- Account Enumeration
- Email Enumeration via Reset Function
- Auth - Session Created Before Full Auth (partial auth state abuse)
- Auth - Multi-tenant Login Confusion (tenant switch via header/param)



## Authorization & Access Control

### Core Authorization Issues
- Improper Access Control - Generic (CWE-284)
- Improper Authorization (CWE-285)
- Incorrect Authorization (CWE-863)
- Missing Authorization (CWE-862)
- Authorization Check Bypass
- Authorization Logic Flaw
- Authorization - Multi-Tenant Isolation Failure (org_id/tenant_id not enforced server-side)
- Authorization - Cache-Based Authorization Bypass (shared cache key missing user/role/tenant)

### Insecure Direct Object Reference (IDOR)
- Insecure Direct Object Reference (IDOR) (CWE-639)
- IDOR - Horizontal Privilege Escalation
- IDOR - Vertical Privilege Escalation
- IDOR - Parameter Pollution
- IDOR - Numeric ID Enumeration
- IDOR - UUID Prediction
- IDOR - Hash Collision
- IDOR - Encoding Bypass
- IDOR - Missing Authorization Check
- IDOR - Indirect Reference Bypass (predictable mapping tables / short links)
- IDOR - Batch/Bulk Endpoints (modify list of IDs to include unauthorized objects)
- IDOR - GraphQL BOLA/BFLA (field-level auth missing)

### Access Control Enforcement
- Client-Side Enforcement of Server-Side Security (CWE-602)
- Access Control - Client-Side Validation Only
- Access Control - Hidden Field Manipulation
- Access Control - Parameter Tampering

### Privilege-Related Issues
- Execution with Unnecessary Privileges (CWE-250)
- Improper Privilege Management (CWE-269)
- Privilege Escalation (CAPEC-233)
- Privilege Escalation - Vertical
- Privilege Escalation - Horizontal
- Privilege Escalation - Sudo/Root
- Privilege Escalation - Kernel Exploit
- Privilege Escalation - SUID Binary Abuse
- Privilege Escalation - Insecure sudo Configuration
- Privilege Escalation - LD_PRELOAD Injection
- Privilege Escalation - DLL Hijacking
- Privilege Escalation - SetUID Bypass

### Permission-Related Issues
- Incorrect Permission Assignment for Critical Resource (CWE-732)
- Improper Handling of Insufficient Permissions or Privileges (CWE-280)
- Overly Permissive File Permissions
- Overly Permissive Directory Permissions

### Function & Object Level Access Control
- Function-Level Access Control Bypass
- Function-Level Authorization (FLAC) Bypass
- Function-Level Access - HTTP Method Bypass
- Function-Level Access - Method Override Header Abuse (X-HTTP-Method-Override)
- Object-Level Access Control Bypass
- Object-Level Authorization (OLAC) Bypass
- Object-Level Access - Parameter Manipulation
- Object-Level Access - Nested Object Injection (child object auth not enforced)
- Object-Level Access - Alternate Identifier Abuse (slug vs id vs uuid uses different checks)

### Role-Based Access Control (RBAC)
- RBAC Misconfiguration
- RBAC - Role Confusion
- RBAC - Role Inheritance Bypass
- RBAC - Default Role Abuse

### Attribute-Based Access Control (ABAC)
- ABAC Bypass
- ABAC - Attribute Injection
- ABAC - Policy Bypass

### Capability-Based Access Control
- Capability-Based Access Control Bypass
- Capability Token Theft
- Capability Token Prediction

### Advanced Authorization Attacks
- Delegation Abuse
- Impersonation Attack
- Permission Escalation via Role Confusion



## Cryptography & Encryption

### Cipher/Algorithm Issues
- Cryptographic Issues - Generic (CWE-310)
- Inadequate Encryption Strength (CWE-326)
- Use of a Broken or Risky Cryptographic Algorithm (CWE-327)
- Use of DES/3DES
- Use of MD5/SHA1
- Use of MD4
- Use of RC4
- Use of RC2
- Use of Insecure Stream Cipher
- Use of Insecure Block Cipher Mode (ECB)

### Hash-Related Issues
- Reversible One-Way Hash (CWE-328)
- Weak Hash Function
- Hash Collision Vulnerability
- Hash Rainbow Table Attack
- Hash - No Salt Used
- Hash - Weak Salt Generation
- Password Hashing - Weak Parameters (low cost factor / iterations / memory)
- Password Hashing - Fast Hash Used for Passwords (SHA* without KDF)

### Key Management Issues
- Key Exchange without Entity Authentication (CWE-322)
- Reusing a Nonce, Key Pair in Encryption (CWE-323)
- Use of a Key Past its Expiration Date (CWE-324)
- Missing Required Cryptographic Step (CWE-325)
- Key Storage in Plaintext
- Key Derivation - Weak Function
- Key Derivation - Insufficient Iterations
- Key Rotation - Missing
- Key Rotation - Improper Implementation
- Key Management - Weak KDF Choice (PBKDF2 params too low / scrypt/Argon2 misconfig)
- Key Management - Predictable/Static IV/Nonce Generation
- Key Management - Key ID / Version Confusion (selecting wrong key for verify/decrypt)

### RNG/Randomness Issues
- Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) (CWE-338)
- Use of Insufficiently Random Values (CWE-330)
- PRNG - Predictable Seed
- PRNG - State Prediction
- PRNG - Insufficient Entropy
- PRNG - Java Random (not SecureRandom)
- PRNG - PHP mt_rand
- PRNG - Weak Random Library
- PRNG - JavaScript Math.random() Used for Tokens/Secrets

### Encryption Mode Issues
- ECB Mode Usage
- ECB Mode - Pattern Leakage
- IV Reuse in Encryption
- CBC Mode - IV Predictability
- CBC Mode - Padding Oracle
- Counter Mode - Nonce Reuse
- GCM Mode - IV Reuse
- GCM Mode - Missing AAD Binding (context not authenticated)

### Password Encryption
- Weak Cryptography for Passwords (CWE-261)
- Password Hashing - No Salt
- Password Hashing - Weak Algorithm (MD5, SHA1)
- Password Hashing - Single Hash Iteration
- Password Hashing - Crackable Function

### Hard-coded Cryptography
- Use of Hard-coded Cryptographic Key (CWE-321)
- Hard-coded Key in Source Code
- Hard-coded Key in Binary
- Hard-coded Key in Configuration

### Advanced Cryptographic Attacks
- Padding Oracle Attack
- Side-Channel Attacks
- Timing Attack (Crypto)
- Cache Timing Attack
- Power Analysis Attack
- Fault Injection Attack
- Meet-in-the-Middle Attack
- Collision Attack on Hash Functions
- Pre-image Attack on Hashes



## Credential Storage & Transmission

### Insecure Storage
- Cleartext Storage of Sensitive Information (CWE-312)
- Password Stored in Plaintext
- API Key Stored in Plaintext
- Database Password in Plaintext
- Private Key Stored in Plaintext
- Secrets in Crash Dumps / Core Dumps
- Secrets in APM/Monitoring Tools (Sentry/NewRelic payload capture)

- Plaintext Storage of a Password (CWE-256)
- Storing Passwords in a Recoverable Format (CWE-257)
- Reversible Password Hashing
- Password Encryption with Weak Cipher

- Insecure Storage of Sensitive Information (CWE-922)
- Sensitive Data in Browser Cache
- Sensitive Data in Application Cache
- Sensitive Data in Backup

- Missing Encryption of Sensitive Data (CWE-311)

### Credential in Files & Configuration
- Password in Configuration File (CWE-260)
- Password in web.config
- Password in .env file
- Password in application.properties
- Password in application.yml
- Password in settings.py (Django)
- Password in config.php
- Secrets in CI/CD Config (GitHub Actions, GitLab CI, Jenkins)
- Secrets in Kubernetes Manifests/Helm Values

- Password in Codebase
- Password Hardcoded in Source Code

- Password in Comments
- Credentials in Code Comments
- Temporary Password in Comments

- Password in Version Control
- Password Committed to Git
- Password in Git History
- Password in .git/config

### Credential in Environment & Memory
- Password in Environment Variables (Unprotected)
- Password Visible in /proc/<pid>/environ
- Password Visible in Process List
- Password in Memory Dump
- Secrets in Command-Line Arguments (ps output)

- Insecure Password Storage (in session/memory)
- Password in Session Variables
- Password in Memory (Plain)

### Hard-coded Credentials
- Use of Hard-coded Credentials (CWE-798)
- Hard-coded Admin Password
- Hard-coded API Key
- Hard-coded Database Password
- Hard-coded Service Account
- Hard-coded Token

- Use of Hard-coded Password (CWE-259)
- Default Hard-coded Password

### Connection Strings & Tokens
- Database Credentials in Connection Strings
- Connection String in Log Files
- Connection String in Error Messages
- Connection String in Source Code

### Client-Side Credentials
- API Keys in Client-Side Code
- API Key Visible in JavaScript
- API Key in HTML Source
- Secret Token in Frontend
- Secrets in Source Maps (exposed .map files)
- Secrets in Mobile/Desktop Client Apps (hardcoded in binaries)

- Tokens in Browser Local Storage
- JWT in localStorage
- Session Token in localStorage
- Refresh Token in localStorage
- Password in localStorage

### Transport Security
- Cleartext Transmission of Sensitive Information (CWE-319)
- HTTP (not HTTPS) for Sensitive Data
- Unencrypted API Communication
- Unencrypted Database Connection

- Insufficiently Protected Credentials (CWE-522)
- Unprotected Transport of Credentials (CWE-523)
- Credentials Over HTTP
- Credentials Over Unencrypted Channel

### Sensitive Data Exposure
- Sensitive Data in Logs
- Password in Application Logs
- Password in Access Logs
- API Key in Logs
- Token in Logs
- PII in Logs
- Secrets in Analytics/Telemetry Events (client->vendor leakage)

- Metadata Leakage
- Excessive Data Exposure



## Session Management

### Session Lifetime Issues
- Insufficient Session Expiration (CWE-613)
- No Session Timeout
- Excessive Session Timeout
- Session Never Expires
- Idle Timeout Not Enforced (activity not tracked server-side)
- Absolute Timeout Missing (only sliding/idle expiration)
- Sliding Expiration Abuse (keepalive endpoint extends session indefinitely)
- Remember-Me / Persistent Session Token Never Expires
- Refresh Token Acts as Long-Lived Session (no rotation / no revocation)
- Logout Does Not Invalidate Server-Side Session

### Session Fixation
- Session Fixation (CWE-384)
- Session Fixation - Cookie Reuse
- Session Fixation - Pre-login Session
- Session Fixation - URL Parameter
- Session Fixation - No Session Regeneration
- Session Fixation - Session ID Accepted from Multiple Locations (Cookie + Header + Param)
- Session Fixation - Login CSRF / Forced Login (attacker forces victim into attacker-controlled session)
- Session Fixation - Cookie Tossing (subdomain sets parent-domain session cookie)
- Session Fixation - Path Confusion Cookie Shadowing (attacker sets more specific Path cookie)
- Session Fixation - Hostname Confusion / Alternate Host Sets Cookie
- Session Fixation - Session Adoption (server accepts attacker-chosen session ID)

### Session Hijacking
- Session Hijacking
- Session Token Theft via XSS
- Session Token Interception
- Session Cookie Theft
- Session Hijacking - Token in URL (Referer leakage, browser history, logs)
- Session Hijacking - Token in Redirect Location Header
- Session Hijacking - Token Leaked via Third-Party Requests (analytics/pixels)
- Session Hijacking - Token Captured via MITM / TLS Downgrade / Bad HTTPS Config
- Session Hijacking - Session Token Reuse After Password Change
- Session Hijacking - Session Token Reuse After Logout

### Session Prediction & Weakness
- Session Prediction
- Predictable Session ID
- Weak Session Token Generation
- Weak Session ID Algorithm
- Weak Session ID Length
- Session ID - Timestamp/Counter-Based Tokens
- Session ID - Low Entropy PRNG / Guessable RNG Seed
- Session ID - Sequential / Incremental IDs
- Session ID - Deterministic Encoding (base64/hex of user id + time)
- Session ID - UUID Misuse (non-random UUID versions / predictable UUIDs)
- Session Token Brute Force (short tokens / weak rate limiting)

### Session Token Encoding / Normalization Confusion
- Session Token - URL Encoding / Double URL Encoding Confusion
- Session Token - Base64 vs Base64URL Confusion (+/ vs -_ and padding)
- Session Token - Mixed Hex/Base64 Parsing Confusion
- Session Token - Unicode Normalization Confusion (NFC/NFD) in token handling
- Session Token - Whitespace/Control Character Truncation (leading/trailing spaces, \t, \r\n)
- Session Token - Null Byte Truncation (%00) in downstream components
- Session Token - Compression/Decompression Confusion (e.g., JWT "zip" handling)

### Cookie-Related Issues
- Reliance on Cookies without Validation and Integrity Checking in a Security Decision (CWE-784)
- Cookie Tampering
- Cookie Forgery
- Cookie Validation Bypass
- Cookie Integrity Check Missing

- Cookie Theft via XSS
- Cookie Exposure in Error Messages
- Cookie in Logs

- Cookie-Based Session Fixation
- Cookie Domain Scope Bypass
- Cookie Path Scope Bypass
- Cookie Scope - Domain Attribute Misuse (overbroad domain, leading dot quirks)
- Cookie Scope - Public Suffix / eTLD+1 Confusion
- Cookie - Secure Flag Missing
- Cookie - HttpOnly Missing
- Cookie - SameSite Missing / Misconfigured (Lax/Strict/None)
- Cookie - SameSite=None Without Secure (dropped by modern browsers)
- Cookie - Max-Age/Expires Confusion (persistence bugs)
- Cookie Prefix Bypass - __Host- Misuse (should be Secure, no Domain, Path=/)
- Cookie Prefix Bypass - __Secure- Misuse (should be Secure)

- Cookie Parsing/Handling Quirks
- Cookie - Duplicate Cookie Names (shadowing / last-wins vs first-wins differences)
- Cookie - Multiple Cookie Headers (proxy/app disagreement)
- Cookie - Case Sensitivity Differences in Cookie Names
- Cookie - Quoted Values / Special Characters Parsing Differences
- Cookie - Semicolon/Comma Delimiter Confusion
- Cookie - Whitespace Normalization Differences around '=' and ';'

### Session Timeout Issues
- Session Timeout Bypass
- Session Timeout - Timing Window
- Session Timeout - Concurrent Request
- Session Timeout - Keepalive/Background Requests Prevent Expiry
- Session Timeout - Timeout Enforced Only Client-Side (UI timer only)
- Session Timeout - Refresh Token Extends Session Beyond Intended Window

### Concurrent Session Issues
- Concurrent Session Usage
- Multiple Active Sessions
- Session Multiplexing
- Concurrent Session Limit Bypass (multiple devices/tokens allowed)
- Logout/Invalidate Race (one session invalidates another incorrectly)

### Session State Issues
- Session State Corruption
- Session State Manipulation
- Session State in URL
- Session State Exposure
- Session State - Cross-App Session Confusion (shared cookie across apps/paths)
- Session State - Environment Confusion (staging/prod share cookie domain)
- Session State - CSRF Token Not Bound to Session (token reuse across sessions)
- Session State - Privilege Change Not Reflected in Session (stale roles)



## Path Traversal & File Access

### Path Traversal - Core
- Path Traversal (CWE-22)
- Path Traversal - Directory Traversal
- Path Traversal - Navigate to Parent Directory
- Path Traversal - Read Arbitrary File
- Path Traversal - Write Arbitrary File
- Path Traversal - Delete/Overwrite File
- Path Traversal - Bypass “Safe Directory” Root (broken chroot/jail logic)

### Path Traversal - Bypass Techniques
- Path Traversal - Null Byte Injection (%00)
- Path Traversal - Encoding Bypass (URL Encoding)
- Path Traversal - Double Encoding (%252e)
- Path Traversal - Unicode Encoding (%u002e)
- Path Traversal - Backslash Bypass (\\)
- Path Traversal - Trailing Slash/Dot (./, ../, ...)
- Path Traversal - Mixed Slash (/ and \\)
- Path Traversal - Case Sensitivity Bypass
- Path Traversal - Extension Bypass
- Path Traversal - Dot-Segment Confusion (./, ../, ././/, ..//)
- Path Traversal - “..” Obfuscation (.%2e, %2e., %2e%2e)
- Path Traversal - Encoded Separator Bypass (%2f, %5c)
- Path Traversal - Double-Encoded Separators (%252f, %255c)
- Path Traversal - Mixed Encodings (URL + Unicode + Double-URL)
- Path Traversal - Overlong UTF-8 / Legacy UTF-8 Decoding Bypass
- Path Traversal - Unicode Slash Variants (normalization of “/” lookalikes)
- Path Traversal - Unicode Dot Variants (normalization of “.” lookalikes)
- Path Traversal - Unicode Normalization (NFC/NFD/NFKC/NFKD) Confusion
- Path Traversal - Path Separator Normalization Differences (app vs framework vs proxy)
- Path Traversal - Path Collapse/Canonicalization Differences (realpath/resolve mismatch)
- Path Traversal - Filter-on-Input / Use-after-Decode (validate before decode, use after decode)
- Path Traversal - Validate-on-Decode / Use-before-Decode (validate after decode, use raw)
- Path Traversal - Multiple Decoding Passes (decode twice in different layers)
- Path Traversal - Partial Decoding (some layers decode %2f, others do not)
- Path Traversal - URL Path vs Query Parameter Differences (path segment traversal vs param traversal)
- Path Traversal - Semicolon/Matrix Param Confusion (`;` in paths)
- Path Traversal - Fragment/Anchor Confusion (`#` stripped/kept inconsistently)
- Path Traversal - Whitespace/Control Character Confusion (\t, \r\n) in path parsing
- Path Traversal - Trailing Space/Dot Handling Differences (Windows-specific trimming)
- Path Traversal - Alternative Data Streams / Suffix Confusion (platform-specific)

### Path Traversal Variants
- Path Traversal: '.../...//' (CWE-35)
- Path Traversal - Absolute Path
- Path Traversal - Relative Path
- Path Traversal - Mixed Absolute/Relative (e.g., `C:..\..` semantics on Windows)
- Path Traversal - Path Prefix Confusion (leading `//` or `\\` treated specially)
- Path Traversal - UNC Path Access (\\\\server\\share\\path)
- Path Traversal - Windows Drive Letter Paths (C:\\Windows\\..., C:/Windows/...)
- Path Traversal - Windows Device Paths (\\\\?\\, \\\\.\\)
- Path Traversal - Windows Short Names (8.3) / Alternate Representation
- Path Traversal - Tilde/Environment Expansion Confusion (server-side expansion bugs)

- Relative Path Traversal (CWE-23)
- Relative Path - Directory Escape
- Relative Path - Prefix Stripping Bypass (remove `../` once, leave rest)
- Relative Path - Allowlist Prefix Bypass (prefix allowed but later segments escape)

### File Inclusion Attacks
- File Inclusion - Local File Inclusion (LFI)
- LFI - /etc/passwd
- LFI - /etc/shadow
- LFI - /etc/hosts
- LFI - /proc/self/environ
- LFI - /proc/self/cmdline
- LFI - /proc/self/fd (file descriptor tricks)
- LFI - Application Secrets (env/config/keys)
- LFI - Config Files
- LFI - Source Code
- LFI - Log Files
- LFI - Session Files
- LFI - Encoding Bypass
- LFI - Path Normalization Bypass (realpath mismatch)
- LFI - Windows Files (win.ini, hosts, IIS/web.config, etc.)

- File Inclusion - Remote File Inclusion (RFI)
- RFI - Remote Code Execution
- RFI - Log Poisoning
- RFI - Protocol Abuse (php://, data://)
- RFI - Redirect-Based Fetch (follow redirects to restricted schemes/hosts)
- RFI - DNS Rebinding-Assisted File Fetch (if hostname allowlist exists)

- File Inclusion - Log Poisoning
- Log Poisoning - Access Log
- Log Poisoning - Error Log
- Log Poisoning - Application Log
- Log Poisoning - User-Agent/Header Injection then Include
- Log Poisoning - Newline/CRLF Injection into Logs then Include

- File Inclusion - Wrapper Abuse
- Wrapper Abuse - php:// Protocol
- Wrapper Abuse - php://filter (transform-based file read)
- Wrapper Abuse - data:// Protocol
- Wrapper Abuse - file:// Protocol (if supported by target language/runtime)
- Wrapper Abuse - glob:// Protocol
- Wrapper Abuse - phar:// Protocol
- Wrapper Abuse - zip:// / jar:file: / archive wrappers (runtime-specific)
- Wrapper Abuse - expect:// / ssh2:// / ftp:// wrappers (runtime-specific)
- Wrapper Abuse - rar:// Protocol
- Wrapper Abuse - ogg:// Protocol

### Path Traversal via Data Conversion / Extraction
- Archive Extraction Traversal (Zip Slip / Tar Slip / 7z Traversal)
- Path Traversal - Filename Normalization Bugs during Unzip/Untar
- Path Traversal - Symlink-in-Archive then Write Outside Root
- Path Traversal - Hardlink-in-Archive then Overwrite Target File
- Path Traversal - Windows Path in Archive (drive letter / UNC) Confusion
- Path Traversal - Mixed Separator Paths in Archives (\\ vs /)
- Path Traversal - Unicode Normalization in Archive Entry Names
- Path Traversal - Double-Decode in Archive Entry Names (%252e%252e etc.)

### Directory & Browsing Issues
- Forced Browsing (CWE-425)
- Directory Traversal via Parameter
- Directory Listing Enabled
- Hidden Directory Discovery
- Admin Directory Exposure
- Backup Directory Exposure
- Forced Browsing - Backup/Temp Extensions (.bak, .old, .swp, .tmp)
- Forced Browsing - Source/VC Paths (.git/, .svn/, .hg/)

### Temporary File Issues
- Insecure Temporary File (CWE-377)
- Temporary File Enumeration
- Temporary File - Predictable Name
- Temporary File - World Readable
- Temporary File - World Writable
- Temporary File - Symlink Swap / TOCTOU (tmp file race)

### Search Path Issues
- Untrusted Search Path (CWE-426)
- Current Directory in PATH
- Executable in Writable Directory
- DLL Hijacking via PATH
- Search Path - Relative Include/Require Path Hijack (runtime-specific)
- Search Path - Library Load Path Hijack (runtime-specific)

### Symlink & Hard Link Issues
- Symbolic Link Following (Symlink Attack)
- Symlink - Race Condition
- Symlink - Directory Escape
- Hard Link Attack
- Hard Link - File Overwrite
- Symlink - Upload then Link to Sensitive Target (file read/write via symlink)



## Request/Response Manipulation

### CSRF Attacks
- Cross-Site Request Forgery (CSRF) (CWE-352)
- CSRF - Token Bypass
- CSRF - Token Reuse
- CSRF - Token Prediction
- CSRF - Double Submit Cookies
- CSRF - SameSite Bypass
- CSRF - SameSite=Lax Bypass via Top-Level Navigation / GET-to-POST Patterns
- CSRF - SameSite=None Cookie Misconfiguration (missing Secure)
- CSRF - GET-based
- CSRF - POST-based
- CSRF - Multipart Form
- CSRF - JSON POST
- CSRF - Content-Type Confusion (form vs json endpoints)
- CSRF - CORS + CSRF Chaining (misconfigured CORS enables credentialed cross-origin writes)
- CSRF - No Token Validation
- CSRF - Weak Token Validation
- CSRF - Token in Body Bypass (via URL)
- CSRF - Token Not Bound to Session/User (swap token across accounts)
- CSRF - Token in Cookie Only (readable by attacker-controlled subdomain)

### HTTP Request Smuggling
- HTTP Request Smuggling (CWE-444)
- HTTP Request Smuggling - CL.TE (Content-Length/Transfer-Encoding)
- HTTP Request Smuggling - TE.CL
- HTTP Request Smuggling - TE.TE
- HTTP Request Smuggling - CL.CL
- HTTP Request Smuggling - Frontend/Backend Mismatch
- HTTP/2 Rapid Reset Attack
- HTTP/2 to HTTP/1.1 Downgrade Smuggling (H2->H1 translation differences)
- Request Smuggling - Header Normalization Differences (duplicate headers, whitespace, obs-fold)
- Request Smuggling - Chunked Parsing Edge Cases (invalid chunk sizes, extensions)

### HTTP Response Manipulation
- HTTP Response Splitting (CWE-113)
- HTTP Response Splitting - Header Injection
- HTTP Response Splitting - Cookie Injection
- HTTP Response Splitting - Cache Poisoning

### Header Injection
- Improper Neutralization of HTTP Headers for Scripting Syntax (CWE-644)
- HTTP Response Header Injection
- HTTP Header Injection
- Host Header Injection
- Host Header - Cache Poisoning
- Host Header - Password Reset Poisoning
- Host Header - Websocket/Absolute URL Generation Poisoning
- X-Forwarded-For Injection
- X-Original-URL Injection
- X-Rewrite-URL Injection
- X-Forwarded-Host / X-Forwarded-Proto Injection
- Forwarded Header Injection (RFC 7239)

### URL & Encoding Issues
- Improper Handling of URL Encoding (Hex Encoding) (CWE-177)
- URL Encoding Bypass
- Double URL Encoding
- Unicode URL Encoding
- URL Parsing Differential (WHATWG vs backend parser) / authority confusion
- Userinfo (@) Tricks / URL Credential Segment Confusion

### HTTP Parameter Pollution
- HTTP Parameter Pollution (HPP)
- HPP - Multiple Parameter Names
- HPP - Case Sensitivity Bypass
- HPP - Encoding Variation
- HPP - Parameter Duplication
- HPP - Array Parameter Confusion (?a=1&a=2 vs a[]=1&a[]=2)
- HPP - JSON vs Query Param Precedence Differences



## Server-Side Request Forgery (SSRF)

### SSRF - Core Variants
- Server-Side Request Forgery (SSRF) (CWE-918)

### SSRF - Target Access
- SSRF - Local File Access (file://)
- SSRF - Local File via /etc/passwd
- SSRF - Local File via /etc/hosts

- SSRF - Internal Service Access
- SSRF - Internal API Access
- SSRF - Internal Database Access

- SSRF - Port Scanning
- SSRF - Service Discovery
- SSRF - Link-local / Loopback Access (127.0.0.1, ::1, 169.254.169.254)
- SSRF - IPv6 Literal / IPv6 Zone ID Handling (parser quirks)
- SSRF - IP Encoding Tricks (decimal/octal/hex, mixed notation)

### SSRF - Cloud/Metadata
- SSRF - Cloud Metadata (AWS, GCP, Azure)
- SSRF - AWS EC2 Metadata
- SSRF - AWS IMDSv1
- SSRF - AWS IMDSv2
- SSRF - GCP Metadata Service
- SSRF - Azure Metadata
- SSRF - DigitalOcean Metadata

### SSRF - Protocol Abuse
- SSRF - Gopher Protocol
- SSRF - Dict Protocol
- SSRF - LDAP Protocol
- SSRF - FTP Protocol
- SSRF - SMTP Protocol

### SSRF - Advanced
- SSRF - DNS Rebinding
- SSRF - Bypass via URL Tricks
- SSRF - Encoding Bypass
- SSRF - Case Sensitivity Bypass
- SSRF - Whitelist Bypass
- SSRF - Redirect Chain Bypass (follow redirects to forbidden targets)
- SSRF - Hostname vs Resolved IP Allowlist Mismatch (DNS pinning issues)
- SSRF - URL Fragment/Query Confusion in Filters (validate one part, request another)

### Advanced SSRF Vectors
- SSRF via PDF Generation
- SSRF via Image Processing (ImageMagick)
- SSRF via Video Processing
- SSRF via Document Conversion
- SSRF via Webhook Systems
- SSRF via Notification Services
- SSRF via GraphQL



## Redirect & Navigation

### Open Redirect
- Unvalidated/Open Redirect (CWE-601)
- Open Redirect - Absolute URL
- Open Redirect - Relative URL
- Open Redirect - Protocol-based (javascript:, data:, vbscript:)
- Open Redirect - Double Encoding Bypass
- Open Redirect - Unicode Encoding Bypass
- Open Redirect - Case Sensitivity Bypass
- Open Redirect - Null Byte Injection
- Open Redirect - Parameter Pollution
- Open Redirect - URL Parser Differential (//evil.com, \\evil.com, mixed slashes)
- Open Redirect - Scheme Confusion (http:\\evil.com in lenient parsers)

### Advanced Redirect Bypass
- Open Redirect - JavaScript
- Open Redirect - Meta Refresh
- Open Redirect - Header Injection
- Open Redirect - Whitelist Bypass
- Open Redirect - Partial Match Bypass
- Open Redirect - Domain Confusion
- Open Redirect - Subdomain Bypass

### CORS Misconfiguration
- Overly Permissive Cross-domain Whitelist (CWE-942)
- CORS Misconfiguration
- CORS - Wildcard Allow
- CORS - Null Origin
- CORS - Credential Leak
- CORS - Dynamic Origin Based on Input
- CORS - Regex Bypass in Origin Check
- CORS - Subdomain Wildcard Bypass
- CORS - Reflect Origin with Credentials (Access-Control-Allow-Origin echoes attacker origin)
- CORS - Insecure Preflight Caching (Access-Control-Max-Age too long / varies missing)
- CORS - Missing Vary: Origin (cache serves permissive ACAO to other origins)

### DOM-Based Navigation
- DOM-Based Open Redirect (CWE-1024)
- window.location Manipulation
- window.open Manipulation
- iframe.src Manipulation
- DOM-Based Open Redirect -> XSS (untrusted navigation target reaches an executable URL scheme or script-capable sink)
- DOM-Based Open Redirect -> Client-Side Request Forgery (same-origin navigation reaches an unintended authenticated endpoint)
- Client-Side Navigation Target Parser Differential (browser, router, and application disagree on a URL's origin, scheme, or path)

## Deserialization & Code Execution

### Language-Specific Deserialization
- Deserialization of Untrusted Data (CWE-502)
- Deserialization - TypeName/Polymorphic Type Handling Enabled (gadget instantiation)
- Deserialization - Signed/Encrypted Token Confusion (accepts unsigned serialized blobs)

- Java Deserialization (RCE)
- Java Serialization - Gadget Chain
- Java - commons-collections
- Java - Spring Framework Gadgets
- Java - JNDI Injection

- Python Pickle Deserialization
- Python Pickle - Arbitrary Code Execution
- Python - yaml.load(unsafe)
- Python - Unsafe JSON Deserialization to Objects (custom object_hook)

- PHP Unserialization
- PHP - __wakeup() Bypass
- PHP - __destruct() Exploitation
- PHP - POP Chain

- NodeJS Deserialization
- NodeJS - Function Constructor
- NodeJS - Unsafe Object Merge

- YAML Deserialization
- YAML - Arbitrary Code Execution
- YAML - Object Construction

- JSON Deserialization with Type Confusion
- JSON - Type Juggling
- JSON Schema/Validation Confusion
- JSON Schema - additionalProperties misuse (accepts attacker-supplied fields)
- JSON Merge-Patch Prototype Pollution ({"__proto__": {"polluted": true}})
- JSON Parser Differential (duplicate keys first/last wins impacting authz)

- Ruby Marshal Deserialization
- Go Serialization Issues
- C# BinaryFormatter RCE
- C# / .NET - TypeNameHandling (Json.NET) / polymorphic deserialization gadgets
- Java - Jackson Default Typing / polymorphic deserialization gadgets

### Code Execution Related
- Remote Code Execution (RCE) - General
- Command Execution via Expression Language

- Download of Code Without Integrity Check (CWE-494)
- Code Integrity Verification Missing

- Embedded Malicious Code (CWE-506)
- Malicious Code in Dependencies
- Malicious Code in Library

- Replicating Malicious Code (Virus or Worm) (CWE-509)

### Backdoors & Debug Code
- Leftover Debug Code (Backdoor) (CWE-489)
- Debug Endpoints Exposed
- Test Code in Production

- Malware (CAPEC-549)



## Input Validation

### Core Input Validation
- Improper Input Validation (CWE-20)
- No Input Validation
- Whitelist Missing
- Blacklist Bypass
- Input Validation - Type Confusion (string vs number vs boolean vs null)
- Input Validation - JSON Parser Differential (duplicate keys, NaN/Infinity handling)
- Input Validation - Content-Type Confusion (treat JSON as form or vice versa)
- Input Validation - Unicode Normalization / Case Folding Confusion

### Escape/Control Sequence Issues
- Improper Neutralization of Escape, Meta, or Control Sequences (CWE-150)
- Escape Character Bypass
- Control Character Injection

### Blacklist Issues
- Incomplete Blacklist (CWE-184)
- Blacklist Bypass - Encoding
- Blacklist Bypass - Case Sensitivity
- Blacklist Bypass - Homograph
- Blacklist Bypass - Null Byte
- Blacklist Bypass - Unicode

### Format String Attacks
- Use of Externally-Controlled Format String (CWE-134)
- Format String Attack - %x (Read)
- Format String Attack - %n (Write)
- Format String Attack - Information Disclosure
- Format String Attack - Arbitrary Write

### Error Handling
- Improper Check or Handling of Exceptional Conditions (CWE-703)
- Unchecked Error Condition (CWE-391)
- Missing Error Handling
- Insufficient Error Handling
- Exception Handling - Fail-Open on Parser Errors (invalid input accepted on error path)



## Memory Safety Issues

### Buffer Overflow
- Buffer Overflow (CWE-120)
- Stack Buffer Overflow
- Stack Buffer Overflow - Return Address Overwrite
- Stack Buffer Overflow - ROP Chain
- Heap Buffer Overflow
- Heap Buffer Overflow - Heap Metadata Corruption
- Off-by-one Buffer Overflow

### Buffer Over-read/Under-read
- Buffer Over-read (CWE-126)
- Information Disclosure via Buffer Over-read
- Buffer Under-read (CWE-127)

### Buffer Underflow
- Buffer Underflow (CWE-124)

### Double Free & Heap Issues
- Double Free (CWE-415)
- Double Free - Heap Corruption
- Heap Overflow (CWE-122)
- Heap Overflow - Metadata Corruption
- Heap Overflow - Use After Free Chain
- Memory Corruption - Generic (CWE-119)

### Null Pointer Issues
- NULL Pointer Dereference (CWE-476)
- NULL Pointer Dereference - Crash (DoS)
- NULL Pointer Dereference - Code Execution

### Stack Overflow
- Stack Overflow (CWE-121)
- Stack Overflow - Recursion
- Stack Overflow - Deep Nesting

### Use After Free
- Use After Free (CWE-416)
- Use After Free - Information Disclosure
- Use After Free - Code Execution
- Use After Free - Double Free Chain

### Array Index Issues
- Array Index Underflow (CWE-129)
- Out-of-bounds Read (CWE-125)
- Out-of-bounds Write

### Integer Issues
- Integer Overflow (CWE-190)
- Integer Overflow - Arithmetic
- Integer Overflow - Allocation
- Integer Overflow - Buffer Size Calculation

- Integer Underflow (CWE-191)
- Integer Underflow - Negative Size

- Wrap-around Error (CWE-128)
- Integer Wrap-around

### Off-by-one Errors
- Off-by-one Error (CWE-193)
- Off-by-one - Array Access
- Off-by-one - Loop Condition

### Buffer Size Issues
- Incorrect Calculation of Buffer Size (CWE-131)
- Buffer Size Miscalculation
- Buffer Size Underestimation

### String/Null Termination
- Improper Null Termination (CWE-170)
- Missing Null Terminator
- Null Termination Bypass

### Arbitrary Write Primitive
- Write-what-where Condition (CWE-123)
- Arbitrary Memory Write
- Arbitrary Function Pointer Write
- Arbitrary VTable Write



## Type Safety & Logic Issues

### Type Confusion
- Type Confusion (CWE-843)
- Type Confusion - JavaScript
- Type Confusion - PHP
- Type Confusion - Python
- Type Confusion - Java Generics
- Type Confusion - Loose Typing

### Type Coercion
- Type Coercion Bypass
- String to Number Coercion
- String to Boolean Coercion
- NULL Type Confusion
- Numeric Truncation / Rounding Issues (float->int, locale decimals)

### Comparison Issues
- Incorrect Comparison (CWE-697)
- Loose Comparison (== vs ===)
- Weak Comparison in JavaScript
- String Number Comparison
- Boolean Comparison Bypass

### Immutability Issues
- Modification of Assumed-Immutable Data (MAID) (CWE-471)
- Constant Modification
- Final Field Modification
- Immutable Object Mutation

- Object Mutation
- Object Property Modification
- Object State Corruption



## Information Disclosure

### Generic Information Disclosure
- Information Disclosure (CWE-200)

### Directory/File Exposure
- File and Directory Information Exposure (CWE-538)
- Directory Listing Enabled
- Backup File Exposure
- Hidden File Disclosure (.git, .env, .swp, .bak)
- Source Code Disclosure
- Configuration File Disclosure
- Private Key Disclosure

### Debug Information Exposure
- Information Exposure Through Debug Information (CWE-215)
- Debug Mode Enabled
- Stack Traces Exposed
- Debug Variables Exposed
- Debug Endpoints Accessible
- Debug Console Enabled
- Source Maps Exposed
- Profiling Endpoints Accessible (`/prof`, `pprof`, `/flame`)
- Metrics Endpoints Leaking Internal State (`/metrics`, `/actuator`, `/health`)
- Coverage Reports Exposed (`/__coverage__`, `/coverage`)
- Test Endpoints in Production (`/__tests__`, `/test`, `/e2e`)
- Swagger UI / API Docs in Production (`/swagger`, `/api-docs`, `/redoc`)

### Error Message Disclosure
- Information Exposure Through an Error Message (CWE-209)
- Verbose Error Messages
- SQL Error Messages (Table/Column Names)
- Database Error Details
- Framework Error Messages
- File Path Disclosure in Errors

### Directory Listing
- Information Exposure Through Directory Listing (CWE-548)
- Apache Directory Listing
- Nginx Directory Listing

### Timing-Based Leaks
- Information Exposure Through Discrepancy (CWE-203)
- Timing Attack
- Response Time Discrepancy
- Processing Time Analysis

- Information Exposure Through Timing Discrepancy (CWE-208)
- Timing-based Information Leak
- Constant-Time Comparison Missing

### Data in Transit/Storage
- Information Exposure Through Sent Data (CWE-201)
- Data in Logs
- Data in Cookies
- Data in Response Headers
- Data in Error Messages
- Secrets in Client-Side Error Reports (stack traces/telemetry)

### Privacy & Excessive Exposure
- Privacy Violation (CWE-359)
- PII in Logs
- PII Exposure via API
- PII in Cookies

- Metadata Leakage
- File Metadata Exposure
- Image EXIF Data
- Document Metadata

- Excessive Data Exposure
- API Returning Unnecessary Data
- Bulk Data Extraction



## Certificate & Transport Security

### Certificate Validation
- Improper Certificate Validation (CWE-295)
- Certificate Validation - Missing
- Certificate Validation - Hostname Mismatch
- Certificate Validation - Wildcard Certificate Bypass
- Certificate Validation - Self-Signed Certificate
- Certificate Validation - Expired Certificate

### Certificate Pinning
- Certificate Pinning Bypass
- Certificate Pinning - Hardcoded Pin Extraction
- Certificate Pinning - Dynamic Pin Bypass

### Certificate Chain
- Improper Following of a Certificate's Chain of Trust (CWE-296)
- Certificate Chain - Intermediate Compromise
- Certificate Chain - Root CA Bypass
- Certificate Chain - Revocation Bypass

### TLS/SSL Issues
- Man-in-the-Middle (CWE-300)
- SSL/TLS Downgrade Attack
- SSL/TLS - Protocol Downgrade (to SSLv3, TLSv1.0)
- TLS - Weak Diffie-Hellman Parameters / Logjam-Style Issues
- TLS - Missing HSTS (Strict-Transport-Security) / HSTS Misconfiguration
- TLS - Mixed Content (HTTPS page loads HTTP subresources)
- TLS - Heartbleed
- TLS - CRIME Attack
- TLS - BEAST Attack
- TLS - POODLE Attack

### MITM Attacks
- MITM - Certificate Spoofing
- MITM - Proxy Attack
- MITM - ARP Spoofing

### DNS Security
- Reliance on Reverse DNS Resolution for a Security-Critical Action (CWE-350)
- DNS Spoofing
- DNS Cache Poisoning
- DNS Hijacking
- DNS Rebinding
- DNS Tunneling (exfiltration)

### Encryption Channel Issues
- Inadequate Encryption Strength
- Encryption - Weak Cipher Suite
- Encryption - RC4
- Encryption - DES/3DES

## Business Logic & Configuration

### CTF Playbook - Business Logic Quick Checks
#### Focus on server-side validation vs client trust
- Tamper prices/quantities/discount fields in intercepted requests (Burp) and hidden inputs
- Try out-of-range values (negative, fractional, huge) and boundary tests (0/1/max)
- Concurrency: redeem same gift card/coupon in parallel tabs; double-submit checkout
- Change currency/region/shipping params; observe tax/VAT/shipping threshold logic
- Webhooks: replay payment/refund events; test idempotency keys presence/enforcement
- State machine: call steps out of order (confirm before pay, ship before confirm)
- Multi-tenant edges: apply actions across tenants/orgs; header/param-based tenant switching

### Price & Quantity Manipulation
- Business Logic Errors (CWE-840)
- Price Manipulation - Direct Price Change
- Price Manipulation - Cart Manipulation
- Price Manipulation - Coupon Stacking
- Price Calculation Order-of-Operations Bugs (discount after tax vs before)
- Client-side Price Anchoring (computed only in browser; server trusts client total)
- Quantity Bypass - Negative Quantities
- Quantity Bypass - Fractional Quantities
- Quantity Bypass - Zero Quantity
- Quantity Bypass - Decimal Quantities
- Quantity Rounding / Floating-Point Errors (0.1+0.2 edge cases)

### Transaction & Payment Bypass
- Workflow Bypass - Payment Step Skip
- Workflow Bypass - Order Confirmation Skip
- Transaction Replay
- Transaction Reversal
- Partial Payment Bypass
- Double Charging Prevention Bypass
- Payment Intent/Status Confusion (mark paid via client parameter)
- Refund Without Payment / Over-refund via multiple partial refunds
- Webhook Idempotency Missing (replay creates duplicate orders/credits)

### Coupon & Discount Abuse
- Coupon Code Reuse
- Coupon Code Enumeration
- Coupon - Applied to Unauthorized Items
- Coupon - Stack Multiple Coupons
- Coupon - Expired Coupon Acceptance
- Coupon Scope Misconfiguration (applies across tenants or excluded categories)
- Coupon Minimum Threshold Manipulation (decimal rounding to meet free shipping/discount)

### Reward & Currency Manipulation
- Gift Card Exploitation
- Gift Card Balance Manipulation
- Gift Card Transfer Bypass
- Loyalty Points Manipulation
- In-Game Currency Manipulation
- Gift Card Double-Spend via Race Condition (redeem same code concurrently)
- Self-Referral / Referral Abuse (multi-account loops, cookie tampering)
- Currency Conversion Manipulation (change currency param for lower price)

### Inventory & Availability
- Inventory System Bypass
- Inventory Negative Balance
- Out-of-Stock Item Purchase
- Stock Reservation Bypass
- Flash Sale Exploitation
- Hold-to-Purchase Window Exploitation (reservation time extension loop)
- Backorder Logic Abuse (force shipment despite no stock)

### Misconfiguration
- Misconfiguration (CWE-16)
- Debug Mode Enabled
- Default Credentials
- Overly Permissive Permissions
- Admin Panel Exposed
- Test/Staging Exposed to Production

### DNS Misconfiguration
- DNS misconfiguration
- DNS Wildcard (*)
- Subdomain Takeover
- Subdomain Enumeration
- Zone Transfer (AXFR) Allowed

### Security Through Obscurity
- Security Through Obscurity (CWE-656)
- Relying on Hidden Files for Security
- Hidden Client Flags for Premium Features (enable via param)
- Feature Flag Misconfiguration (beta features accessible without auth)
- Obscured Admin Paths
- Hidden API Endpoints

### Design Principles Violation
- Violation of Secure Design Principles (CWE-657)
- Missing Authentication Check
- Missing Authorization Check
- Missing Input Validation
- Missing Error Handling

## File Upload & Content Processing

### Upload Validation & Storage
- Unrestricted File Upload (CWE-434)
- Content-Type Trust / MIME Sniffing Confusion
- File Extension Validation Bypass (double extensions, trailing dots/spaces, case folding)
- Unicode Normalization / Homoglyph Extension Bypass
- Null Byte Truncation in Filename/Path (legacy components)
- Path Traversal in Upload Filename / Storage Key ("../" in name or metadata)
- Overwrite Existing Files (same name/key) / Race Conditions in Upload Finalize
- Direct Object Reference to Uploaded Files (IDOR on download endpoints)

### Parser Differentials & Polyglots
- File Polyglots (valid in multiple formats; content-based detection bypass)
- Archive Smuggling (ZIP slip, TAR traversal, symlink/hardlink in archives)
- Decompression Bombs (ZIP/GZIP/7z) / Resource Exhaustion via Parsing
- Image Processing RCE Surface (ImageMagick/FFmpeg/libvips/ghostscript class issues)
- Office/PDF Processing Surface (macros/embedded objects, PDF actions, parser bugs)
- Metadata/EXIF Injection (downstream rendering/templating consumers)
- Polyglot Payload Details (SVG+HTML, PDF+JS, GIF with JavaScript) for stored XSS/RCE surfaces
- Content Sniffing at Edge/CDN vs Origin Mismatch (X-Content-Type-Options absent)
- Office Remote Template Injection (DOCX/RTF referencing remote resources)
- Image ICC Profile Injection (metadata parsers code paths)

### Multipart Parser Differentials
- Boundary Obfuscation / Malformed Boundary Handling (accepts invalid boundaries)
- Conflicting Filename/Content-Type Fields (last-wins vs first-wins)
- Mixed Case Header Names / Duplicate Headers in Parts
- Null Byte / Encoding Tricks Inside Part Headers
- Multiple File Fields with Same Name (unexpected overwrite/merge)
- RFC 5987 `filename*=` Encoding Handling (parser support differences)
- Content-Transfer-Encoding Quirks (base64/quoted-printable acceptance differences)
- Trailing Whitespace in Boundary Lines (accept vs reject)
- Chunked + Multipart Combination Edge Cases (frontend/backend disagreement)
- CRLF Variants Inside Part Headers (\r\n vs \n parsing)

## SSO / Identity Provider Integrations (SAML / OIDC / OAuth)

### OIDC / OAuth Integration Issues
- redirect_uri Parsing Differences (scheme/host/path normalization confusion)
- Missing/Weak state Validation (login CSRF / session swapping)
- PKCE Missing / PKCE Downgrade (public clients)
- Issuer Confusion / JWKS Confusion (accepting tokens from wrong issuer/JWKS)
- Nonce Missing / Weak Nonce Validation (replay)
- Over-broad Scopes / Consent Misuse (least privilege failure)
- OAuth Device Code Flow Misconfiguration (broad device auth, user code reuse, polling endpoint auth gaps)
- Device Flow `user_code` Reuse Across Accounts (phishing + session swap)
- `verification_uri_complete` Open Redirect/Link Spoofing (social engineering vectors)
- Device Flow Polling Endpoint Missing AuthZ (bind to client/user/session)
- Polling Interval Ignored (aggressive polling -> DoS or rate bypass)

### SAML Integration Issues
- SAML Signature Wrapping (XSW) / XML canonicalization quirks
- SAML Response/Assertion Signature Validation Gaps (partial validation)
- Insecure IdP-Initiated Flow Handling (unsolicited responses)
- Audience/Recipient/ACS URL Validation Gaps (accepting for wrong SP)

## Caching / CDN / Edge

### Cache Key & Normalization Issues
- Cache Key Normalization Bugs (path/query/header canonicalization differences)
- Vary Header Misuse / Missing Vary (user-specific content cached)
- Authenticated Responses Cached as Public (session leakage)
- Host Header / X-Forwarded-Host Cache Poisoning
- Stale-While-Revalidate / Race Conditions Returning Other Users' Data
- Unkeyed Header Gadgets (Accept-Language, Accept-Encoding, X-Forwarded-Proto) poisoning preconditions
- ESI Injection (Edge Side Includes) leading to cache poisoning / content splicing
- Client Hints Unkeyed (Sec-CH-UA, Sec-CH-UA-Platform, viewport) causing variant mix-ups
- Authorization Header Caching Misconfig (caches responses despite auth)
- CDN Cache Key Misconfiguration (missing user/tenant/role dimensions)

### Edge Rewrites & Routing
- CDN/Reverse Proxy Rewrite Differentials (proxy vs app routing disagreement)
- Private Origin Exposed Directly (bypass WAF/CDN/auth at edge)

## Observability / Telemetry Leakage

### Logging, Tracing, Analytics
- Secrets in Server Logs (Authorization headers, cookies, tokens)
- Secrets in Client-Side Error Reports (stack traces/telemetry)
- Secrets in Analytics/Telemetry Events (client->vendor leakage)
- Trace Header Abuse (traceparent/baggage) leading to log injection / data leakage
- Debug Endpoints in Production (metrics, profiling, health checks with sensitive info)

## Denial of Service

### Rate Limiting & Throttling Bypass
- Allocation of Resources Without Limits or Throttling (CWE-770)
- Rate Limiting Bypass - IP Spoofing
- Rate Limiting Bypass - X-Forwarded-For
- Rate Limiting Bypass - Client Rotation
- Rate Limiting Bypass - Thread Pool Exhaustion
- Rate Limiting Bypass - Endpoint/Route Variations (same action on multiple paths)
- Rate Limiting Bypass - Per-User vs Per-IP Mismatch (shared IP environments)
- Resource Exhaustion - Memory
- Resource Exhaustion - CPU
- Resource Exhaustion - Disk
- Resource Exhaustion - Bandwidth
- Resource Exhaustion - Connections

### DDoS Attacks
- Denial of Service (CWE-400)
- DDoS - Volumetric - UDP Flood
- DDoS - Volumetric - ICMP Flood
- DDoS - Volumetric - DNS Query Flood
- DDoS - Protocol-based - SYN Flood
- DDoS - Protocol-based - Fragmented IP
- DDoS - Protocol-based - Ping of Death
- DDoS - Application-layer - HTTP Flood
- DDoS - Application-layer - SlowLoris

### Data Amplification Attacks
- Improper Handling of Highly Compressed Data (Data Amplification) (CWE-409)
- Zip Bomb - Nested Compression
- Zip Bomb - Zero-byte Files
- XML Bomb - Billion Laughs Attack
- XML Bomb - Quadratic Blowup
- Gzip Bomb
- Brotli Bomb

### Algorithmic Complexity
- Uncontrolled Recursion (CWE-674)
- Algorithmic Complexity Attack - Regular Expression ReDoS
- Algorithmic Complexity Attack - Sorting Algorithm
- Algorithmic Complexity Attack - Hash Collision
- Algorithmic Complexity Attack - Database Query
- Algorithmic Complexity - GraphQL Depth/Complexity Abuse

### Slowdown Attacks
- Slowloris Attack
- Slow HTTP POST
- Slow Read Attack
- Slow Headers
- Slow Body

### Resource Depletion
- Connection Exhaustion
- Memory Allocation Loop
- CPU Utilization Attack
- Disk Space Exhaustion

## UI & User Interaction

### Clickjacking & UI Redressing
- UI Redressing (Clickjacking) (CAPEC-103)
- Clickjacking - Button Hijacking
- Clickjacking - Drag & Drop
- Clickjacking - with Transparency
- Clickjacking - Form Field Overlay
- Clickjacking - Frame Busting Bypass
- Clickjacking - X-Frame-Options Bypass
- Clickjacking - frame-ancestors CSP Misconfiguration / Missing

### Visual Spoofing
- User Interface (UI) Misrepresentation of Critical Information (CWE-451)
- Visual Spoofing - URL Bar
- Visual Spoofing - SSL Certificate
- Visual Spoofing - Domain Names
- Visual Spoofing - Favicon Manipulation
- Visual Spoofing - Look-alike Domains

### HTML Injection & UI Manipulation
- HTML Injection for UI Manipulation
- UI Injection - Popup/Alert Spoofing
- UI Injection - Content Insertion
- UI Injection - Form Hijacking

### CSS-based Attacks
- CSS Injection
- CSS - Input Validation Bypass
- CSS - Event Handler

## Race Conditions & Synchronization

### TOCTOU Vulnerabilities
- Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') (CWE-362)
- Time-of-check Time-of-use (TOCTOU) Race Condition (CWE-367)
- TOCTOU - File Operations (symlink, stat/open)
- TOCTOU - File Permissions
- TOCTOU - Account Operations (check balance, withdraw)
- TOCTOU - Resource Allocation
- TOCTOU - Authentication State

### Asynchronous Race Conditions
- Async Race Condition
- Promise Race Condition
- Event Handler Race Condition
- Database Transaction Race Condition
- Cache Coherency Race Condition

### Lock & Synchronization Issues
- Double Lock
- Lock-Order Deadlock
- Missing Lock
- Stale Lock

### State Management Races
- State Machine Race Condition
- Initialization Race Condition
- Finalization Race Condition
- Webhook/Callback Replay (idempotency missing)
- Payment/Order Race (double-spend via concurrent checkout)
- Coupon/Gift Card Redemption Race (redeem same code in parallel)
- Inventory Reservation Race (overselling limited stock)

## Data Control & State Management

### State Data Manipulation
- External Control of Critical State Data (CWE-642)
- State Variable Tampering
- Session State Manipulation
- Application State Manipulation
- Workflow State Bypass

### Resource Reference Control
- Externally Controlled Reference to a Resource in Another Sphere (CWE-610)
- Insecure Direct Object Reference (IDOR) - Reference Manipulation
- Path Traversal via Resource Reference
- Cross-context Reference

### Exposed Functionality
- Exposed Dangerous Method or Function (CWE-749)
- Exposed Admin Methods
- Exposed Debug Methods
- Exposed Internal APIs

### Component & Module Security
- Improper Export of Android Application Components (CWE-926)
- Exposed Broadcast Receiver
- Exposed Content Provider
- Exposed Service
- Exported Activity

### Supply Chain & Dependencies
- Inclusion of Functionality from Untrusted Control Sphere (CWE-829)
- Supply Chain Attack
- Dependency Confusion - NPM
- Dependency Confusion - PyPI
- Typosquatting Attack
- Dependency Hijacking
- Subresource Integrity (SRI) Missing / Bypass (third-party scripts tamper risk)
- CDN/Third-Party Widget Trust (script injection via provider compromise)
- SRI + `crossorigin` Nuance (anonymous vs use-credentials affects integrity checks)
- Registry Substitution/Mirror Attacks (alternate registry serving malicious packages)
- Lockfile Integrity & Pinning (package-lock/shrinkwrap not enforced or absent)
- Self-hosted Library Integrity (hash/pin for internal CDN artifacts)

### Untrusted Input Reliance
- Trust of System Event Data (CWE-360)
- Reliance on Untrusted Inputs in a Security Decision (CWE-807)
- Use of Inherently Dangerous Function (CWE-242)

### File Upload Vulnerabilities
- Unrestricted Upload of File with Dangerous Type (CWE-434)
- File Upload - Extension Bypass (.php.jpg)
- File Upload - MIME Type Bypass
- File Upload - Double Extension (.php.png)
- File Upload - Null Byte Injection (.php%00.jpg)
- File Upload - Polyglot Files (PDF + PHP)
- File Upload - Content Validation Bypass
- File Upload - SVG Injection
- File Upload - GIF with JavaScript
- File Upload - Filename Path Traversal (../ in upload name)
- File Upload - Stored XSS via Uploaded HTML/SVG Served Inline
- File Upload - Archive Bomb / Decompression Bomb
- File Upload - Zip Slip (Path Traversal)
- File Upload - Archive Bomb

## API & Web Service Vulnerabilities

### API Authentication & Authorization
- API Key Exposure
- API Key Hardcoded
- API Key in URL
- API - Broken User Authentication
- API - Broken Function Level Authorization
- API - Broken Object Level Authorization (BOLA)
- API - BOLA - ID Enumeration
- API - BOLA - Sequential ID Prediction
- API - BOLA - UUID Bypass
- API - AuthZ via Header Trust (X-User/X-Role headers accepted from client)
- API - Tenant Header Confusion (X-Tenant/Org header not validated)

### API Rate Limiting & DoS
- API - Missing Rate Limiting
- API - Rate Limiting Bypass
- API - Lack of Resources & Rate Limiting
- API - Slow Rate Limit
- API - DoS - Bulk Operations

### API Data Exposure
- API - Excessive Data Exposure
- API - Unintended Data Exposure
- API - Debug Data Exposure
- API - GraphQL Introspection Leaking Schema (even when disabled via workarounds)
- API - WADL/WSDL Exposure (SOAP service definitions)
- API - OPTIONS Method Disclosure (reveals allowed methods/headers)
- API - Trace/Track Method Enabled (HTTP TRACE reflects request incl headers)

### API Input Validation
- API - Mass Assignment
- API - Parameter Pollution
- API - Content-Type Confusion
- API - Improper JSON Parsing
- API - Duplicate JSON Keys (last-wins vs first-wins authz/input differences)
- API - Unknown Field Handling (silently accepted dangerous fields)

### GraphQL Attacks
- GraphQL - Introspection Enabled
- GraphQL - Query Depth Abuse
- GraphQL - Fragment Abuse
- GraphQL - Alias Abuse
- GraphQL - DoS via Complexity
- GraphQL - Circular Reference
- GraphQL - Field Duplication
- GraphQL - Batching/Multipart Requests Abuse
- GraphQL - Authorization Missing on Resolvers (BOLA/BFLA)
- GraphQL - Persisted Query Bypass (tamper hash/id to run arbitrary query)
- GraphQL - Federation Edge Cases (entity resolution auth gaps across services)
- GraphQL - File Upload Spec Abuse (multipart handling quirks, auth bypass via uploads)
- GraphQL - Router/Proxy Rate Limit & Cache Key Bugs (per-user keys missing)

### WebSockets
- WebSocket Auth Confusion (missing auth on upgrade, cookie-only trust)
- WebSocket Origin Check Missing / Weak
- WebSocket CSRF via auto-connect in victim browser
- WebSocket Header Injection / Protocol Mismatch (Sec-WebSocket-Protocol abuse)
- WebSocket Message Injection / Lack of server-side validation
- WebSocket `permessage-deflate` Resource Exhaustion (compression bombs / CPU spikes)
- WebSocket Binary/Text Type Confusion (validator assumes one type)
- WebSocket CORS/CSP Misconfig at handshake (edge proxies trusting Origin)

### HTTP/2 & gRPC
- HTTP/2 to HTTP/1 Desync (proxy/backend parsing differences)
- H2C (cleartext upgrade) Exposure / Misconfig
- gRPC Reflection Abuse (enumerate services/methods)
- gRPC Message Fuzzing / Type Confusion (weak validation on protobuf fields)
- HTTP/2 Trailer/Header Quirks (cache/keying and auth filters bypass)
- Reverse proxy h2/h1 translation smuggling vectors (CL/TE mismatches across layers)
- HTTP/3 / QUIC Misconfiguration (alt-svc upgrades, proxy translation gaps)

### Real-time Channels
- Server-Sent Events (SSE) Exposure (auth/caching issues on event streams)
- SSE - Cache Poisoning / Unkeyed Stream Responses (mix user streams)
- SSE Event ID Reuse / Stream Resumption Mix-up (delivers other users' events)
- SSE `Cache-Control` / `Vary` Misuse (public caches serving private streams)
- WebRTC STUN/TURN Misconfiguration (leak internal IPs / relay exfil paths)
- TURN Credential Exposure / Reuse (static creds leaked in client code)
- WebRTC Peer Connection Trust Issues (origin/permission flows)
- WebRTC Data Channel AuthZ Missing (unauthenticated peer message acceptance)

### REST API Issues
- REST API - HTTP Method Bypass (PUT, DELETE, PATCH)
- REST API - Inconsistent HTTP Method Handling
- REST API - Header-based Authentication Bypass
- REST API - Content Negotiation
- REST API - Version Bypass (v1/v2 endpoint authorization differences)
- REST API - Pagination Limit Bypass (negative/huge offset or limit values)
- REST API - Pagination Cursor Manipulation (base64/JWT cursor tampering)
- REST API - Filter Injection (ORM/query builder injection via filter params)
- REST API - Sorting Column Injection (ORDER BY injection via sort parameter)
- REST API - Field Selection Bypass (requesting restricted fields via include/fields param)
- REST API - Bulk Operations Authorization Gaps (batch endpoints skip per-item checks)
- REST API - Swagger/OpenAPI Spec Exposure (reveals internal endpoints/schemas)
- REST API - Debug/Profiling Endpoints (`/debug`, `/metrics`, `/__coverage__`)
- REST API - Health Check Information Leakage (version/dependency info in responses)

## Encoding & Escaping Issues

### Double/Triple Encoding Bypasses
- Double Encoding Attack
- Double Encoding - %.252e (..)
- Double Encoding - %252f (/) Bypass
- Double Encoding - %252e%252e Path Traversal
- Triple Encoding
- Mixed Encoding (URL + HTML + Unicode)

### Character Encoding Confusion
- Charset Confusion (CWE-176)
- UTF-8/UTF-16 Mismatch
- UTF-7 Encoding Bypass
- UTF-32 Bypass
- Shift_JIS Encoding Bypass
- Unicode Normalization (NFC vs NFD)
- Overlong UTF-8 / Legacy UTF-8 Decoding Bypass

### Escape Sequence Bypasses
- HTML Entity Encoding Bypass
- JavaScript String Escaping Bypass
- URL Encoding Bypass
- Base64 Encoding Bypass
- Hex Encoding Bypass

### Context-Specific Encoding Issues
- Encoding Confusion - JavaScript Context
- Encoding Confusion - URL Context
- Encoding Confusion - SQL Context
- Encoding Confusion - XML Context
- Encoding Confusion - CSS Context (CSS escapes vs HTML escapes)
- Encoding Confusion - LDAP Context (RFC 4515/4514 escape mismatches)
- Encoding Confusion - JSON Context (unicode escapes, control char handling)
- Encoding Confusion - CSV Context (formula injection via =, +, -, @)
- Encoding Layer Mismatch (decode at proxy, use raw at app or vice versa)
- Partial Encoding (encode dangerous chars but miss edge cases / normalization)
- Nested Encoding Contexts (JSON in HTML in URL; innermost wins)

## NoSQL Injection

### MongoDB Attacks
- NoSQL Injection (CWE-943)
- MongoDB Injection
- MongoDB - Operator Injection ($ne, $gt, $regex)
- MongoDB - $ne Bypass ({"password": {"$ne": null}})
- MongoDB - $regex Bypass
- MongoDB - $where JavaScript Injection
- MongoDB - JavaScript Map-Reduce Injection

### CouchDB Attacks
- CouchDB Injection
- CouchDB - Selector Injection
- CouchDB - View Query Injection

### ElasticSearch Attacks
- ElasticSearch Injection
- ElasticSearch - Query Injection
- ElasticSearch - Query DSL Injection

### Firebase & Realtime Database
- Firebase - Insecure Rules
- Firebase - Wildcard Rules

### Cassandra & Other NoSQL
- Cassandra Injection
- Redis Injection
- Redis - Blind Injection
- Redis - Command Injection via EVAL/EVALSHA (Lua scripting abuse)

### Generic NoSQL Attacks
- NoSQL - Error-based Detection
- NoSQL - Time-based Blind Injection
- NoSQL - Boolean-based Blind
- NoSQL - Out-of-Band Exfiltration
- NoSQL - Aggregation Pipeline Injection (MongoDB $lookup/$merge/$graphLookup abuse)
- NoSQL - Type Confusion in Queries (string vs number vs object comparison bugs)
- NoSQL - Index Hinting Abuse (force inefficient queries via hint parameter)

## JWT & Token Issues

### JWT Vulnerabilities
- JWT - Algorithm Confusion
- JWT - No Signature Verification
- JWT - Weak Secret
- JWT - Key Confusion (RS256 to HS256 downgrade)
- JWT - Algorithm Downgrade (RS256 to none)
- JWT - Token Prediction
- JWT - Expired Token Acceptance
- JWT - Claims Manipulation (payload editing)
- JWT - Kid Injection (key ID)
- JWT - Jti Replay (no claim validation)
- JWT - JWKS Injection / JWK Header Abuse (jku/jwk/x5u where supported)
- JWT - Missing aud/iss/nbf Validation (accept tokens for other apps)
- JWT - Base64 vs Base64URL Confusion / Padding Handling Differences

### Token Management Issues
- OAuth 2.0 - Authorization Code Disclosure
- OAuth 2.0 - Token Theft
- OAuth 2.0 - Code Substitution
- OAuth 2.0 - State Parameter Bypass
- OAuth 2.0 - Redirect URI Bypass

### Refresh Token Issues
- Refresh Token - Prediction
- Refresh Token - No Rotation
- Refresh Token - No Expiration

## Web Cache Poisoning

### Cache Poisoning Attacks
- Web Cache Poisoning
- Cache Poisoning - Host Header Injection
- Cache Poisoning - X-Forwarded-Host Injection
- Cache Poisoning - X-Original-URL Injection
- Cache Poisoning - Query String Injection
- Cache Poisoning - Missing Vary Headers (cache key missing Origin/Host/Accept-Encoding)
- Cache Poisoning - Unkeyed Headers (X-Forwarded-Host, X-Original-URL, X-Host)

### Cache Deception
- Cache Deception Attack
- Cache Deception - Static Resource Confusion
- Cache Deception - Path Normalization
- Cache Deception - File Extension Confusion

### Cache Splitting
- HTTP Cache Splitting
- Cache Splitting - CRLF Injection
- Cache Splitting - Request Smuggling via Cache

## XXE Advanced

### XXE Exploitation Techniques
- XXE - Parameter Entity
- XXE - External DTD (SYSTEM/PUBLIC)
- XXE - Billion Laughs Attack (XML Bomb)
- XXE - Exfiltration via OOB (DNS/HTTP)
- XXE - Blind XXE with Out-of-Band Data
- XXE - Error-based Exfiltration
- XXE - File Wrapper Abuse
- XXE - Expect Module Exploitation

## Subdomain & DNS
- Moved to [Network.md](Network.md)

## Server-Side Template Injection (SSTI) - Language Specific

### Python Template Engines
- Jinja2 Template Injection
- Jinja2 - Payload: {{7*7}}
- Jinja2 - Filter Bypass
- Jinja2 - Attribute Access Bypass

### JavaScript/Node.js Template Engines
- Pug/Jade Template Injection
- Pug - Code Execution
- EJS Template Injection
- Handlebars Template Injection

### Java Template Engines
- Freemarker Template Injection
- Freemarker - API Bypass
- Velocity Template Injection
- Velocity - Directive Abuse

### PHP/Ruby Template Engines
- Twig Template Injection
- Twig - Payload Bypass
- ERB Template Injection
- Thymeleaf Template Injection (Spring)

### Generic SSTI
- SSTI - Expression Language Injection
- SSTI - SpEL (Spring Expression Language)
- SSTI - OGNL (Object-Graph Navigation Language)
- SSTI - MVEL (MVFLEX Expression Language)
- SSTI - Sandbox Escape (template engine sandbox bypass)
- SSTI - Server-Side Template Injection via Email/PDF Rendering Pipelines
- SSTI - Nunjucks Template Injection (Node.js)
- SSTI - Liquid Template Injection (Ruby/Jekyll)
- SSTI - Smarty Template Injection (PHP)
- SSTI - Go Template Injection (text/template, html/template)
- SSTI - Python f-string Injection (runtime format string evaluation)

## Prototype Pollution & Object Manipulation

### Prototype Pollution Techniques
- Prototype Pollution (JavaScript)
- Prototype Pollution - __proto__ Injection
- Prototype Pollution - Constructor.prototype Injection
- Prototype Pollution - Bypass via Encoding
- Prototype Pollution - Bypass via Case Variation
- Prototype Pollution - Bypass via Null Character
- Prototype Pollution - JSON Parse + Merge (pollution from request bodies)
- Prototype Pollution - Querystring Parser Pollution (a[__proto__][x]=1)

### Object Injection
- Object Property Injection
- Property Descriptor Pollution
- Accessor Property Injection

### Merge/Extend Function Vulnerabilities
- Merge/Extend Function Abuse
- Deep Merge Vulnerability
- Recursive Merge Bypass

### Advanced Prototype Pollution
- Prototype Pollution - Constructor Confusion
- Prototype Pollution - Function Property Pollution
- Prototype Pollution - Array Pollution

## HTTP Parameter Pollution & Request Issues

### HTTP Parameter Pollution
- HTTP Parameter Pollution (HPP)
- HPP - Case Sensitivity Variation
- HPP - Encoding Variation
- HPP - Multiple Parameters with Same Name
- HPP - Null Byte Injection
- HPP - Duplicate Parameter Handling

### Host Header & Forwarding Headers
- Host Header Attack
- Host Header - Password Reset Poisoning
- Host Header - Cache Poisoning
- Host Header - Redirect Poisoning

### Forwarding Header Abuse
- X-Forwarded-For Spoofing
- X-Forwarded-Host Injection
- X-Forwarded-Proto Abuse
- X-Original-URL/X-Rewrite-URL Bypass
- X-HTTP-Method-Override

## Advanced Business Logic Attacks

### Pricing & Transaction Manipulation
- Integer Overflow in Price Calculation
- Negative Price Processing
- Price Calculation Race Condition

### Discount & Coupon Abuse
- Discount Stacking
- Discount Percentage Manipulation
- Stacking Multiple Coupon Types

### Refund & Payment Manipulation
- Refund/Chargeback Abuse
- Partial Refund Bypass
- Refund Without Purchase
- Double Refund

### Order Processing Bypass
- Incomplete Transaction Processing
- Order State Manipulation
- Order Duplication
- Duplicate Order Processing

### Shipping & Tax Bypass
- Tax/Shipping Bypass
- Free Shipping Manipulation
- Zone/Region Manipulation

### Account & Membership Exploitation
- Loyalty Points Abuse
- Membership Downgrade Bypass
- Account Upgrade Manipulation

## Advanced Authentication Attacks

### Enumeration Attacks
- Login Timing Attack
- Timing-based Enumeration
- Username Enumeration
- Account Enumeration
- Email Enumeration via Reset Function
- Phone Number Enumeration

### Session & Token Attacks
- Weak Session Tokens
- Predictable Session IDs
- Session Token Entropy Analysis
- Session Token Collision

### Concurrent Access & Abuse
- Concurrent Login Abuse
- Simultaneous Session Abuse
- Device Fingerprinting Bypass
- Geo-location Check Bypass
- GPS Spoofing Bypass

### Advanced Brute Force
- Credential Stuffing - Account Takeover
- Distributed Brute Force
- Slow Brute Force (Rate Limit Bypass)

## Client-Side Security Issues

### Browser Storage Issues
- Local Storage/SessionStorage Injection
- LocalStorage - Sensitive Data Storage
- SessionStorage - Session Data Exposure
- Web Storage - XSS Exploitation

### IndexedDB & Advanced Storage
- IndexedDB Abuse
- IndexedDB - Unencrypted Sensitive Data
- IndexedDB - Cross-Tab Data Leakage (same origin different contexts)
- IndexedDB - Quota Exhaustion DoS (fill storage to block legitimate app)
- Web Storage Exploitation
- LocalForage Vulnerability
- Cache Storage API Poisoning (service worker caches attacker content)
- Persistent Storage Misconfiguration (sensitive data in persistent vs temporary)
- Storage Access API Bypass (partitioned storage access without user consent)

### DOM Manipulation Issues
- Insecure DOM Methods (eval, innerHTML, dangerouslySetInnerHTML)
- DOM Clobbering
- DOM Pollution via Prototype Pollution
- Dynamic Code Execution in DOM

### Client-Side URL Construction & Routing
- Client-Side Path Traversal (CSPT) - attacker-controlled data becomes part of a browser-generated same-origin request path and escapes its intended prefix or scope
- CSPT - DOM-Based (URL, fragment, or browser storage input reaches a fetch/AJAX path builder)
- CSPT - Reflected (server-reflected input is later used by client code to construct a request path)
- CSPT - Stored (persisted user-controlled data is later used by client code to construct a request path)
- CSPT - Route/Path Join Normalization Mismatch (router, URL API, and backend normalize dot segments, encoded separators, or backslashes differently)
- CSPT - Base URL / Relative-URL Resolution Confusion (a controllable relative URL resolves outside the expected client-side API or route prefix)
- CSPT -> Client-Side Request Forgery (a path-traversal-controlled request reaches an unintended authenticated endpoint)
- XSS Through Redirect + Client-Side Path Traversal (CSPT reaches a same-origin redirect or fetch path that supplies attacker-controlled content to a DOM/script sink)

### JavaScript Execution Risks
- eval() Code Execution
- Function() Constructor Abuse
- setTimeout/setInterval Code Injection
- JSON.parse() with User Input

### Mobile & WebView Surfaces
- Android Deep Link Intent Injection / URI Handler Abuse
- WebView JavaScript Bridge Injection / Insecure addJavascriptInterface
- SSL Pinning Bypass Surfaces (weak/no pinning in apps)
- iOS/Android Keychain/Keystore Misuse (unencrypted storage, broad ACLs)
- iOS Universal Links Misconfiguration (domain association not enforced)
- Android `android:autoVerify` Mismatch (links not verified, attacker-controlled)
- `intent:` Scheme Tricks (parameter injection to launch insecure flows)
- Exported Components Chain (Activities/Services/Receivers reachable unauthenticated)
- WebView SSL Error Handler Override (proceed on certificate errors)

### Browser Extensions
- Extension Messaging Injection / Origin Trust Gaps
- Insecure Extension Storage (tokens/secrets in local storage)
- Over-broad Permissions (file://, history, tabs) leading to data exfiltration
- Content Script XSS (DOM injection on arbitrary sites)
- `chrome.storage.sync` Sensitive Data Exposure (synced across accounts/devices)
- Remote Update/Sideload Supply Chain (auto-updates from untrusted sources)
- Relaxed CSP in Extensions (allow-eval/inline enabling code injection)

### Modern Web Platform Surfaces
- Progressive Web App (PWA) Manifest Injection (scope/start_url manipulation)
- Service Worker Scope Hijacking (register broader scope, intercept all traffic)
- Service Worker Cache Poisoning (attacker-controlled cache serving malicious responses)
- Service Worker Update Bypass (stale worker persists despite code changes)
- WebAssembly Module Injection / Untrusted WASM (side-channel/spectre risks)
- SharedArrayBuffer + Timing Attacks (high-resolution timer for side-channels)
- COOP/COEP Misconfiguration (cross-origin isolation bypass/downgrade)
- COOP `same-origin-allow-popups` Downgrade (popup reference leakage)
- COEP `credentialless` Misuse (resource loading without proper checks)
- PWA Installation Prompt Spoofing (beforeinstallprompt event abuse)
- Web Manifest `protocol_handlers` Abuse (register custom schemes for phishing)

## Advanced File Operations

### Archive Traversal & Extraction
- Zip Slip (Archive Traversal)
- Zip Slip - Path Traversal in Zip Extraction
- Tar Slip
- RAR Archive Slip
- 7z Archive Slip

### Symbolic & Hard Link Attacks
- Symbolic Link Following (Symlink Attack)
- Symlink Attack - Race Condition
- Symlink Attack - Directory Escape
- Hard Link Attack
- Hard Link - File Overwrite

### File Permission Issues
- World-Readable Sensitive Files
- World-Writable Directories
- Predictable File Locations

### Temporary File Security
- Temporary File Enumeration
- Temporary File Race Condition
- Temp File Predictability

- Race Condition in File Operations

## Advanced Cryptographic Attacks
- Side-Channel Attacks
- Timing Attack (Crypto)
- Cache Timing Attack
- Power Analysis Attack
- Fault Injection Attack
- Meet-in-the-Middle Attack
- Collision Attack on Hash Functions
- Pre-image Attack on Hashes
- Padding Oracle

## Advanced XSS Variants
- Mutated XSS (mXSS)
- DOM Clobbering + XSS
- MathML-based XSS
- PDF XSS
- Flash-based XSS (if Flash exists)
- Encoding Confusion XSS
- Content Security Policy (CSP) Bypass via XSS

## Browser Security Bypasses

### SOP & CORS Bypasses
- Same-Origin Policy Bypass
- SOP - Postman Trick
- SOP - CORS Misconfiguration Exploitation

### Content Security Policy Bypasses
- Content Security Policy (CSP) Bypass
- CSP - Inline Script Execution
- CSP - Unsafe-eval Bypass
- CSP - nonce Bypass
- CSP - hash Bypass
- COOP/COEP/CORP Misconfiguration (cross-origin isolation issues)
- Permissions-Policy Misconfiguration (overly permissive powerful features)

### Framing & Header Bypasses
- X-Frame-Options Bypass
- X-Frame-Options - Clickjacking via Frame
- X-Content-Type-Options Bypass
- Strict-Transport-Security (HSTS) Downgrade

### Cookie Security Bypasses
- HttpOnly Cookie Bypass
- Secure Flag Bypass (HTTP over HTTPS downgrade)
- SameSite Bypass

### Advanced Browser Bypasses
- Referrer-Policy Bypass
- Feature-Policy Bypass
- Document.domain Property Manipulation
- Service Worker Scope Abuse / Cache Poisoning (sw-controlled origin content)

## Logic & State Issues

### Memory & Reference Issues
- Use-After-Free in Application Logic
- Dangling Reference
- Circular Reference

### Concurrency & Timing Issues
- Time-of-Check-Time-of-Use (TOCTOU) in Authentication
- TOCTOU - State Verification
- Broken Reference Integrity

### State Machine Issues
- State Machine Bypass
- Invalid State Transition
- State Reversion

### Transaction Issues
- Transaction Atomicity Violation
- Partial Transaction Rollback
- Transaction Interleaving

### Synchronization Issues
- Insufficient Locking/Concurrency
- Missing Mutex
- Deadlock Vulnerability

## Code Extraction & Reverse Engineering

### Code Decompilation & Extraction
- Decompilation Attacks
- Java Decompilation (cfr, procyon, fernflower)
- Python Decompilation (uncompyle6, decompyle3)
- .NET Decompilation (dnSpy, ILSpy)

### Obfuscation & Protection Bypass
- Obfuscation Bypass
- JavaScript Deobfuscation
- String Deobfuscation
- Control Flow Deobfuscation

### Secret Extraction
- Hardcoded Secrets in Binary
- API Keys in Binary
- Encryption Keys in Code

### Debug Information Leakage
- Source Map Exposure
- Debug Symbol Leakage
- Debug Information in Release Build
- String Table Analysis

### Reverse Engineering Techniques
- Binary Instrumentation
- Dynamic Code Analysis
- Memory Forensics

## Insecure Deserialization - Language Specific

### Java Serialization
- Java Serialization (Gadget Chain RCE)
- Java - commons-collections Gadget Chain
- Java - Spring Framework Gadget Chain
- Java - JNDI Injection via Serialization

### Python Deserialization
- Python Pickle RCE
- Python Pickle - __reduce__ Exploitation
- Python YAML Deserialization

### Ruby Deserialization
- Ruby Marshal Deserialization
- Ruby Marshal - Gadget Chains

### Go & C# Deserialization
- Go Serialization Issues
- C# BinaryFormatter RCE
- C# XML Deserialization
- C# DataSet Deserialization

### PHP & Other Languages
- PHP Serialization Exploitation
- PHP Object Injection

## Server & Cloud Misconfiguration

### Administrative Access Issues
- Unprotected Admin Panels
- Admin Panel Path Enumeration
- Admin Interface Default Port

### Credential Management
- Default/Weak Credentials on Services
- Default Credentials - MySQL
- Default Credentials - PostgreSQL
- Default Credentials - Redis
- Default Credentials - Memcached
- Default Credentials - MongoDB
- Default Credentials - RabbitMQ

### Backup & Version Control Exposure
- Backup Files Exposed (.bak, .old, .tar.gz)
- Incremental Backup Exposure
- Source Code Exposed (.git, .svn, .hg)
- Git Repository Exposure

### Configuration File Exposure
- Configuration Files Readable (web.config, .env)
- Application Config Exposure
- Database Config Exposure
- API Config Exposure

### Cloud Storage Misconfiguration
- Moved to [Cloud.md](Cloud.md)

### Container & Orchestration Exposure
- Moved to [OS_specific.md](OS_specific.md)

## Advanced SSRF Attacks

### SSRF via File Processing
- SSRF via PDF Generation
- SSRF via PDF - HTML-to-PDF Engine Fetch (wkhtmltopdf, headless chrome)
- SSRF via PDF - Remote Asset Fetch (images/fonts/stylesheets)
- SSRF via Image Processing (ImageMagick)
- SSRF via ImageMagick - Remote URL Fetch (delegates/handlers)
- SSRF via ImageMagick - Ghostscript/Delegate Fetch
- SSRF via Video Processing
- SSRF via Video - ffmpeg Remote Fetch (subtitles, playlists, concat)
- SSRF via Document Conversion
- SSRF via Document - Remote Template/Asset Fetch

### SSRF via Service Integration
- SSRF via Webhook Systems
- SSRF via Webhook - URL Validation Bypass (redirects)
- SSRF via Notification Services
- SSRF via Notification - Template/Link Preview Fetch
- SSRF via Email Services (tracking pixels, link preview)
- SSRF via GraphQL
- SSRF via GraphQL - Resolver URL Fetchers

### Advanced SSRF Exploitation
- SSRF - Cloud Metadata Service (AWS/GCP/Azure)
- SSRF - Port Scanning Internal Network
- SSRF - Gopher Protocol Abuse
- SSRF - Dict Protocol Abuse
- SSRF - FastCGI Exploitation
- SSRF - URL Parser Confusion (userinfo, @, #, mixed schemes)

## Encoding & Normalization Bypasses
- Unicode Normalization Bypass
- Overlong UTF-8 Encoding
- Punycode/IDN Homograph Attack
- Case Mapping Bypass
- Byte Order Mark (BOM) Injection

## Insecure Randomness
- Weak RNG Seeds
- Predictable Nonce Generation
- Weak Token Generation
- Insufficient Entropy in Randomness
- PRNG State Prediction/Recovery

## Regex & Pattern Matching Issues
- ReDoS (Regular Expression Denial of Service)
- Regex Bypass - Wildcard Abuse
- Regex Bypass - Anchoring Issues
- Regex Bypass - Character Class Errors

## Advanced Authorization Attacks
- Attribute-Based Access Control (ABAC) Bypass
- Role-Based Access Control (RBAC) Bypass
- Capability-Based Access Control Bypass
- Delegation Abuse
- Impersonation Attack
- Permission Escalation via Role Confusion

## HTTP Desynchronization Attacks
- HTTP Request Desynchronization (HTTP/2 Smuggling)
- HTTP/2 Rapid Reset Attack
- Content-Length Desync
- Transfer-Encoding Desync

## Advanced CORS & CSRF
- CORS + CSRF Combination Attack
- Same-Origin Policy Bypass via CORS
- SOP Bypass via Flash/Silverlight (legacy)
- CSRF via DNS Rebinding
- CSRF Token Prediction

## Vulnerability Chains & Compositional Risks

### Browser, Routing & Cache
- Client-Side Path Traversal -> Client-Side Request Forgery
- Client-Side Path Traversal -> Open Redirect -> DOM XSS
- Client-Side Path Traversal -> Attacker-Controlled Response -> DOM XSS
- Client-Side Open Redirect -> DOM XSS
- Client-Side Open Redirect -> Client-Side CSRF
- Client-Side Open Redirect -> Sensitive Information Leakage
- DOM Clobbering -> DOM XSS
- Client-Side Prototype Pollution -> DOM XSS
- `postMessage` Origin/Source Validation Failure -> DOM XSS
- XSS -> Service Worker Registration -> Persistent Client-Side Interception
- Path Confusion -> Web Cache Deception -> Authenticated Data Exposure
- Cache-Key Confusion -> Cross-Tenant Data Exposure
- Stale Cache -> Revoked Authorization or Account-State Exposure
- Unkeyed Request Metadata -> Web Cache Poisoning -> Stored-Like XSS
- Unkeyed Request Metadata -> Web Cache Poisoning -> Phishing or Redirect Poisoning
- CRLF Injection -> HTTP Response Splitting -> Web Cache Poisoning
- HTTP/1.1 Request Smuggling -> Web Cache Poisoning
- HTTP/1.1 Request Smuggling -> Response-Queue Desynchronization -> Cross-User Response Manipulation
- HTTP/2, H2C, or H2-to-H1 Desynchronization -> Persistent Backend Connection Poisoning -> Credential Hijacking or Access-Control Bypass
- CDN/Reverse-Proxy Rewrite Differential -> Authentication or Authorization Bypass
- Subdomain Takeover -> Overly Broad CORS Trust -> Credentialed Cross-Origin Data Access
- Subdomain Takeover -> Parent-Domain Cookie Tossing -> Session Fixation or Cookie Shadowing
- CORS Origin Reflection -> Credentialed Cross-Origin Data Exposure
- Host / Forwarded Header Trust -> Password-Reset Link or Absolute Redirect Poisoning -> Account Takeover or Token Leakage

### OAuth, OIDC, SAML & Session Chains
- Open Redirect or Weak `redirect_uri` Validation -> Authorization Code or Access-Token Leakage -> Account Takeover
- OAuth Mix-Up or Issuer Confusion -> Authorization Code or Token Substitution -> Session Swap
- Missing PKCE -> Authorization-Code Interception -> Token Theft
- Missing `state` -> Login CSRF or Session Swap
- Missing OIDC `nonce` -> ID Token Replay -> Session Takeover
- Mobile Deep-Link or Universal-Link Collision -> Authorization-Code Interception -> Token Theft
- `postMessage` Origin/Source Validation Failure -> OAuth Callback or Token Exposure -> Cross-Origin Account Compromise
- OAuth Callback Fragment or Referer Leakage -> Authorization-Code or Token Theft
- OAuth Device Flow User-Code Reuse -> Session Swap or Account Takeover
- JWT Audience/Issuer/Tenant Confusion -> Cross-Application Privilege Escalation
- JWT Algorithm or Key Confusion -> Forged Token -> Account Takeover
- SAML Assertion Wrapping or Incomplete Assertion Binding -> Wrong Subject or Service Provider Acceptance -> Account Takeover
- SAML Audience/Recipient/ACS Validation Gap -> Assertion Replay at Another Service Provider -> Account Takeover
- Account Linking or Email-Claim Confusion -> Attacker Identity Linked to Victim Account -> Account Takeover
- Session Fixation -> Victim Authentication on Attacker-Chosen Session -> Account Takeover
- Password-Reset Token Leakage -> Password Reset -> Account Takeover

### Injection, Parsing & Server-Side Execution Chains
- SQL Injection -> Authentication Bypass
- SQL Injection -> Data Exfiltration -> Credential Reuse or Account Takeover
- NoSQL Injection -> Authentication or Authorization Bypass
- LDAP Injection -> Authentication or Authorization Bypass
- HTTP Parameter Pollution -> Frontend/Backend Parameter Mismatch -> Authorization Bypass
- HTTP Parameter Pollution -> WAF/Validator Bypass -> Injection
- CRLF Injection -> Set-Cookie Injection -> Session Fixation
- XXE -> Local File Read -> Secret or Credential Exposure
- XXE -> SSRF -> Internal Service or Cloud Metadata Access
- SSRF -> Internal Admin/API Access -> Privilege Escalation
- SSRF -> Cloud Metadata Credentials -> Cloud Privilege Escalation
- SSRF -> Redis, Queue, or Internal Service Access -> Remote Code Execution
- Webhook or URL Fetcher -> DNS Rebinding or Redirect Bypass -> Internal API Access
- LFI -> Log Poisoning -> Remote Code Execution
- File Upload -> Local File Inclusion -> Remote Code Execution
- File Upload or Content-Type Confusion -> Stored XSS -> Session or Token Theft
- File Upload -> Parser/Converter Exploitation -> Remote Code Execution
- Archive Traversal + Symlink/Hardlink Handling -> Arbitrary File Write -> Configuration Override or Code Execution
- SSTI -> Remote Code Execution -> Secret or Cloud-Credential Exposure
- Insecure Deserialization -> Gadget Chain -> Remote Code Execution
- Server-Side Prototype Pollution -> Code Execution or Authorization Bypass
- Command Injection -> Secret or Cloud-Credential Exposure -> Privilege Escalation

### API, Authorization & Business-Logic Chains
- BOLA/IDOR -> Cross-Tenant Data Exposure
- BOLA/IDOR + Bulk, Batch, or GraphQL Resolver Access -> Cross-Tenant Data Exposure or Privilege Escalation at Scale
- Mass Assignment or Client-Controlled Fields -> Role, Owner, Price, or Workflow-State Change -> Privilege Escalation or Fraud
- GraphQL Federation/Gateway Trust Gap -> Downstream Resolver Authorization Bypass -> Cross-Service Data Exposure
- GraphQL Introspection -> Sensitive Schema or Resolver Exposure -> Attack-Surface Expansion
- WebSocket Origin/Auth Gap -> Cross-Site WebSocket Hijacking -> Authenticated Message Access
- CORS Misconfiguration + CSRF -> Authenticated Cross-Origin State Change
- CSRF -> MFA Disable, Email Change, Password Change, or Payment Action
- Race Condition + Missing Idempotency -> Double Spend, Duplicate Action, or Workflow Bypass
- Price, Quantity, or Coupon Manipulation -> Payment or Inventory Fraud
- Password Reset or Account-Recovery Logic Flaw -> Account Takeover
- File/Resource IDOR -> Private File or Object Storage Exposure

### Build, Dependency & Release Chains
- Dependency Confusion or Typosquatting -> CI Dependency Installation -> Build-Secret or Cloud-Credential Exposure -> Release or Deployment Compromise
- Malicious Package Postinstall/Build Script -> CI Code Execution -> Secret Exfiltration
- Untrusted Pull-Request Code or Artifact -> Privileged CI Workflow Execution -> CI-Secret Exfiltration -> Repository, Package, or Cloud Takeover
- Compromised CI Action or Third-Party Build Step -> Artifact or Release-Signing Manipulation -> Downstream Supply-Chain Compromise
- Artifact Substitution -> Trusted Deployment Workflow -> Production Compromise
- Compromised Package Registry or Mirror -> Dependency Substitution -> Build or Runtime Compromise
- Source-Map or Build-Artifact Secret Exposure -> API/Cloud Credential Abuse
- Archive Traversal During Build/Deploy -> Configuration Override or Code Execution

### AI Agent, MCP & Tool-Using Application Chains
- Direct Prompt Injection -> Agent Goal Hijack -> Unauthorized Tool Call
- Indirect Prompt Injection -> Agent Goal Hijack -> Excessively Privileged Tool Call -> Data Exfiltration or Unauthorized Change
- Tool or MCP Description Poisoning -> Misleading Tool Selection -> Secret Exposure or Unauthorized Action
- Tool or MCP Output Poisoning -> Prompt Injection -> Unauthorized Tool Call or Code Execution
- Persisted Agent Memory/Context Poisoning -> Later Privileged Session -> Cross-User Data Exposure or Unauthorized Action
- Untrusted Agent Skill, Plugin, or Tool Supply Chain -> Privileged Agent Execution -> Workspace, Repository, or Connected-Service Compromise
- Agent Identity or Scope Creep -> Prompt Injection or Tool Misuse -> Privilege Escalation Across Connected Systems
- Cross-Agent Delegation -> Confused Deputy -> Unauthorized Action Under a More-Privileged Identity
- Untrusted Model Output -> Automated Code, Query, or Configuration Execution -> Injection or Deployment Compromise

## Out-of-Band Data Exfiltration
- DNS Exfiltration
- DNS Tunneling
- ICMP Exfiltration
- Out-of-Band Data Leakage
- Error-based Data Exfiltration (via error messages)

## Non-Web Checklists
- OS/container/host vulnerabilities: see [OS_specific.md](OS_specific.md)
- AD/Kerberos/protocol vulnerabilities: see [Network.md](Network.md)
- Cloud provider vulnerabilities: see [Cloud.md](Cloud.md)
