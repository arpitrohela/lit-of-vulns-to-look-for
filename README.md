# list-of-vulns-to-look-for
Vulnerability checklist to go through for each web application.

See also:<br>
- OS/container/host: [OS_specific.md](OS_specific.md)<br>
- AD/Kerberos/protocols: [Network.md](Network.md)<br>
- Cloud (AWS/Azure/GCP): [Cloud.md](Cloud.md)<br>

## CTF Playbook - Web Quick Checks
Enumeration & fast probes for common web surfaces:<br>
- Recon: ffuf/feroxbuster for paths; check `.git/`, backups, source maps<br>
- Auth: try default creds, login CSRF/forced login, weak JWT (alg:none, HS/RS confusion)<br>
- IDOR: increment IDs, try tenant headers, bulk endpoints with mixed IDs<br>
- SQLi: error/time/boolean; quick `sqlmap -u <url> --batch` on suspect params<br>
- Command/Code Injection: whitespace/IFS/encoding bypass; force outbound `curl`/DNS callbacks<br>
- XSS: DOM sinks (innerHTML/insertAdjacentHTML), CSP gaps, JSONP callbacks<br>
- Uploads: double extensions, SVG/HTML polyglots, content-sniffing mismatches<br>
- SSRF: metadata URLs, IP encodings (octal/hex), redirect chains to forbidden hosts<br>
- Smuggling/Desync: CL.TE/TE.CL probes; cache poisoning via unkeyed headers<br>

Useful one-liners:<br>
- Path brute: `ffuf -u https://host/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`<br>
- Params diff: `wfuzz -c -z file,/usr/share/wordlists/SecLists/Discovery/WEB-Content/burp-parameter-names.txt --hc 404 https://host/page?FUZZ=1`<br>
- Out-of-band test: embed attacker domain in payloads; monitor dnslog/collaborator<br>

## Injection Vulnerabilities

### Code Injection
Code Injection (CWE-94)<br>
Code Injection - PHP eval()<br>
Code Injection - Python exec/eval<br>
Code Injection - JavaScript eval<br>
Code Injection - Java Runtime.exec<br>
Code Injection - Ruby eval<br>
Code Injection - ASP.NET Eval<br>
Code Injection - Template Code Injection<br>
Code Injection - Dynamic Class Loading<br>
Code Injection - Reflection-based<br>
Code Injection - Expression Injection (OGNL/SpEL/MVEL/JEXL/EL)<br>
Code Injection - Expression Injection via Data Binding (framework binding language quirks)<br>
Code Injection - Deserialization-to-Exec Chain (type confusion to eval/exec)<br>
Code Injection - Encoding/Normalization Bypass (payload decoded after validation)<br>
Code Injection - Polyglot Payloads (works across multiple parsers/contexts)<br>
Code Injection - Sandbox Escape (template sandbox / restricted eval bypass)<br>

### Command Injection
Command Injection - Generic (CWE-77)<br>
Command Injection - Blind (Out-of-band)<br>
Multiple File Fields with Same Name (unexpected overwrite/merge)<br>
RFC 5987 `filename*=` Encoding Handling (parser support differences)<br>
Content-Transfer-Encoding Quirks (base64/quoted-printable acceptance differences)<br>
Trailing Whitespace in Boundary Lines (accept vs reject)<br>
Chunked + Multipart Combination Edge Cases (frontend/backend disagreement)<br>
CRLF Variants Inside Part Headers (\r\n vs \n parsing)
Command Injection - Space Bypass<br>
Command Injection - Quote Escape<br>
Command Injection - Backtick Execution<br>
Command Injection - Command Substitution $(cmd)<br>
Command Injection - Variable Expansion Abuse<br>
WebSocket Message Injection / Lack of server-side validation<br>
WebSocket `permessage-deflate` Resource Exhaustion (compression bombs / CPU spikes)<br>
WebSocket Binary/Text Type Confusion (validator assumes one type)
Command Injection - Encoding Bypass<br>
Command Injection - Pipe (|) Chaining<br>
Command Injection - Semicolon (;) Chaining<br>
Command Injection - AND (&&) Chaining<br>
Command Injection - OR (||) Chaining<br>
Command Injection - Wildcard Abuse<br>
Command Injection - Glob Pattern Abuse<br>
HTTP/3 / QUIC Misconfiguration (alt-svc upgrades, proxy translation gaps)<br>
HTTP/3 alt-svc Cache Poisoning (persisted upgrade hints across origins)<br>
HTTP/3 Pseudo-header Normalization Differences (authority/path handling)
TLS 1.3 0-RTT Replay Risk (state-changing requests accepted in early data)
Command Injection - CR Injection (\r / %0d) as Separator<br>
Command Injection - Tab/IFS Separator Bypass (\t / ${IFS})<br>
Command Injection - Brace Expansion Abuse (shell-specific)<br>
Command Injection - Command Concatenation without Spaces (shell parsing quirks)<br>
WebRTC Peer Connection Trust Issues (origin/permission flows)<br>
SSE Event ID Reuse / Stream Resumption Mix-up (delivers other users’ events)<br>
SSE `Cache-Control` / `Vary` Misuse (public caches serving private streams)<br>
TURN Credential Exposure / Reuse (static creds leaked in client code)
WebRTC Data Channel AuthZ Missing (unauthenticated peer message acceptance)
Command Injection - Windows CMD Metacharacters (&, |, ^, %VAR%)<br>
Command Injection - PowerShell Injection (subexpressions, encoded command, argument parsing)<br>
Command Injection - PowerShell EncodedCommand Confusion (UTF-16LE base64 / decoding layers)<br>
Command Injection - Argument Injection (inject flags/args into safe binary execution)<br>
Command Injection - URL/Double URL Encoding of Metacharacters<br>
Command Injection - Unicode Normalization Bypass (lookalike separators/quotes)<br>

OAuth Device Code Flow Misconfiguration (broad device auth, user code reuse, polling endpoint auth gaps)<br>
Device Flow `user_code` Reuse Across Accounts (phishing + session swap)<br>
`verification_uri_complete` Open Redirect/Link Spoofing (social engineering vectors)<br>
Device Flow Polling Endpoint Missing AuthZ (bind to client/user/session)<br>
Polling Interval Ignored (aggressive polling -> DoS or rate bypass)
CRLF Injection (CWE-93)<br>
CRLF Injection - HTTP Header<br>
CRLF Injection - Email Header<br>
CRLF Injection - Log Injection<br>
CRLF Injection - Request Smuggling<br>
CRLF Injection - Response Splitting (CWE-113 overlap)<br>
CRLF Injection - Set-Cookie Injection / Cookie Fixation via Header Injection<br>
CRLF Injection - Location/Header Redirect Manipulation<br>
CDN/Third-Party Widget Trust (script injection via provider compromise)<br>
SRI + `crossorigin` Nuance (anonymous vs use-credentials affects integrity checks)<br>
Registry Substitution/Mirror Attacks (alternate registry serving malicious packages)<br>
Lockfile Integrity & Pinning (package-lock/shrinkwrap not enforced or absent)<br>
Self-hosted Library Integrity (hash/pin for internal CDN artifacts)
CRLF Injection - Encoded Newlines (%0d%0a / %0a / %0d) Bypass<br>
CRLF Injection - Double-Encoded Newlines (%250d%250a) Bypass<br>
CRLF Injection - Unicode Newline Variants (U+000A/U+000D equivalents) Confusion<br>
CRLF Injection - Folding/Obs-Fold Parsing Differences (legacy header folding)<br>
iOS/Android Keychain/Keystore Misuse (unencrypted storage, broad ACLs)<br>
iOS Universal Links Misconfiguration (domain association not enforced)
Android `android:autoVerify` Mismatch (links not verified, attacker-controlled)
`intent:` Scheme Tricks (parameter injection to launch insecure flows)
Exported Components Chain (Activities/Services/Receivers reachable unauthenticated)
WebView SSL Error Handler Override (proceed on certificate errors)

### Injection - Special Elements
Failure to Sanitize Special Elements into a Different Plane (Special Element Injection) (CWE-75)<br>
Special Element Injection - HTML Context<br>
Content Script XSS (DOM injection on arbitrary sites)<br>
`chrome.storage.sync` Sensitive Data Exposure (synced across accounts/devices)
Remote Update/Sideload Supply Chain (auto-updates from untrusted sources)
Relaxed CSP in Extensions (allow-eval/inline enabling code injection)
Special Element Injection - CSS Context<br>
Special Element Injection - URL Context<br>
Special Element Injection - JSON Context (string breakouts / parser differences)<br>
Special Element Injection - XML Context (attribute/element/entity contexts)<br>
Special Element Injection - CSV/Spreadsheet Formula Context<br>
Special Element Injection - Template/Expression Context<br>
Special Element Injection - Encoding/Normalization Confusion (decode after validate)<br>
ESI Injection (Edge Side Includes) leading to cache poisoning / content splicing<br>
Client Hints Unkeyed (Sec-CH-UA, Sec-CH-UA-Platform, viewport) causing variant mix-ups<br>
Authorization Header Caching Misconfig (caches responses despite auth)
CDN Cache Key Misconfiguration (missing user/tenant/role dimensions)
### LDAP Injection
LDAP Injection (CWE-90)<br>
LDAP Injection - Query Manipulation<br>
LDAP Injection - Filter Bypass<br>
LDAP Injection - Wildcard Bypass<br>
LDAP Injection - Blind LDAP Injection<br>
LDAP Filter Injection<br>
LDAP Injection - Unescaped Special Chars (*, (, ), \\, \0) (RFC 4515/4514 issues)<br>
Content Sniffing at Edge/CDN vs Origin Mismatch (X-Content-Type-Options absent)<br>
Office Remote Template Injection (DOCX/RTF referencing remote resources)
Image ICC Profile Injection (metadata parsers code paths)
LDAP Injection - Attribute Injection (inject additional filter clauses)<br>
LDAP Injection - Null Byte Truncation (downstream bindings/parsers)<br>
LDAP Injection - Unicode Normalization / Case Folding Bypass (schema matching quirks)<br>
LDAP Injection - URL Encoding vs LDAP Escaping Mismatch (decode layer disagreement)<br>

### XPath / XQuery / XML Path Injection
XPath Injection<br>
XPath Injection - Predicate Manipulation<br>
XPath Injection - Encoding/Normalization Bypass (decode after validate)<br>
XQuery Injection<br>
XQuery Injection - Function/Module Abuse (where supported)<br>

### ORM / Query Language Injection
HQL/JPQL Injection (Hibernate/JPA)<br>
LINQ Injection (dynamic query composition)<br>
SQL/ORM - ORDER BY / LIMIT / Column Name Injection (string-built query fragments)<br>
 
Evidence to Capture (for quick reporting):<br>
- Screenshots of pivotal responses (admin views, other users’ data)<br>
- Raw request/response pairs showing exploit (headers, body, cookies)<br>
- Cache headers (`Cache-Control`, `Vary`, `Age`) demonstrating poisoning/mix-ups<br>
- Auth artifacts (JWTs, cookies) and validation gaps (missing `aud`/`iss`)<br>
- OOB callback logs (DNS/HTTP hits with correlation IDs)
Query Language Injection - Encoding/Normalization Confusion (app/ORM/driver mismatch)<br>

### OS Command Injection
OS Command Injection (CWE-78)<br>
OS Command Injection - Linux/Unix<br>
OS Command Injection - Windows<br>
OS Command Injection - macOS<br>
OS Command Injection - Shellshock-Style Environment Parsing (if applicable)<br>
OS Command Injection - Argument Injection into Interpreters (bash/python/perl flags)<br>
 
Evidence to Capture:<br>
- Cart/server totals mismatch screenshots (before/after tamper)<br>
- Parallel request logs showing double-spend/duplicate actions<br>
- Webhook replay traces (idempotency keys missing or ignored)<br>
- Audit logs/receipts proving action without proper authorization
OS Command Injection - Encoding/Decoding Layer Mismatch (proxy/framework/app)<br>

### Reflected File Download
Reflected File Download (RFD) {json endpoint or json api}<br>
RFD - CSV Injection<br>
RFD - JSON Breakout<br>
RFD - Content-Disposition Bypass<br>

### Remote & Local File Inclusion
Remote File Inclusion (CWE-98)<br>
Remote File Inclusion - PHP Wrappers (php://)<br>
Remote File Inclusion - Input Filters Bypass<br>
Remote File Inclusion - Null Byte Injection<br>
Remote File Inclusion - Log File Inclusion<br>
Remote File Inclusion - URL Scheme Abuse (gopher://, dict://, etc.)<br>
Local File Inclusion (LFI) via Path Traversal<br>
LFI - Filter Bypass<br>
LFI - Encoding Bypass<br>
LFI - Case Sensitivity Bypass<br>
LFI - Null Byte Truncation (legacy file APIs / extension checks)<br>
LFI - Double Decode / Mixed Encoding Traversal<br>
LFI - Windows/UNC/Device Path Inclusion (platform-specific)<br>
RFI - Redirect/SSRF-Assisted Inclusion (follow redirects into restricted targets)<br>
RFI - MIME/Content-Type Confusion in Include Handler (remote content treated as code)<br>

### Resource Injection
Resource Injection (CWE-99)<br>
Resource Injection - Credential Injection<br>
Resource Injection - Connection String Injection<br>

### SQL Injection (CWE-89)
SQL Injection (CWE-89)<br>
SQL Injection - Error-based<br>
SQL Injection - Union-based<br>
SQL Injection - Blind<br>
SQL Injection - Time-based Blind<br>
SQL Injection - Boolean-based Blind<br>
SQL Injection - Stacked Queries<br>
SQL Injection - Polyglot<br>
SQL Injection - Second-order<br>
SQL Injection - Blind with Out-of-Band<br>
SQL Injection - OOB via DNS<br>
SQL Injection - OOB via HTTP<br>
SQL Injection - OOB via SMB (UNC path injection on MSSQL)<br>
SQL Injection - Inference via Error Messages (verbose error exploitation)<br>
SQL Injection - Heavy Query DoS (expensive joins/cartesian products for timing)<br>
SQL Injection - Comment Bypass (-- / # / /* */)<br>
SQL Injection - Quote Escape Bypass<br>
SQL Injection - String Delimiter Bypass<br>
SQL Injection - Space Bypass (/**/, %09, %0a)<br>
SQL Injection - Keyword Case Variation<br>
SQL Injection - Function Alias Bypass<br>
SQL Injection - Encoding Bypass (Hex, URL, Double)<br>
SQL Injection - Normalization Bypass<br>
SQL Injection - UNION Bypass<br>
SQL Injection - WHERE Clause Abuse<br>
SQL Injection - ORDER BY Bypass<br>
SQL Injection - GROUP BY Bypass<br>
SQL Injection - HAVING Clause Injection<br>
SQL Injection - LIMIT Bypass<br>
SQL Injection - Parameter Type Confusion (numeric vs string parsing differences)<br>
SQL Injection - JSON/Array Parameter SQLi (ORM or query builder quirks)<br>
SQL Injection - LIKE/ILIKE Wildcard Abuse<br>
SQL Injection - Collation/Charset Confusion (unicode normalization impacts comparisons)<br>
SQL Injection - Truncation / Null Byte Effects in DB Driver Layers<br>
SQL Injection - WAF Bypass via Encoding/Obfuscation (double decode, comments, whitespace)<br>
SQL Injection - HTTP Parameter Pollution-Assisted SQLi (first/last wins differences)<br>
SQL Injection - Order By/Sort Parameter Injection (dynamic ORDER BY strings)<br>
SQL Injection - Identifier Injection (table/column name injection, quoting rules)<br>

### XML Injection & XXE
XML Entity Expansion (CWE-776)<br>
XML Entity Expansion - Billion Laughs<br>
XML Entity Expansion - Quadratic Blowup<br>
XML External Entities (XXE) (CWE-611)<br>
XML External Entities (XXE) - Classic<br>
XML External Entities (XXE) - Blind<br>
XML External Entities (XXE) - Out-of-band<br>
XXE - Parameter Entity<br>
XXE - External DTD<br>
XXE - File Disclosure via FTP<br>
XXE - Java XXE Gadgets<br>
XML Injection (CWE-91)<br>
XML Injection - Attribute Injection<br>
XML Injection - Element Injection<br>
XXE - Encoding/Normalization Bypass (different decoder before XML parser)<br>
XXE - Protocol Trickery (file://, http(s)://, ftp://, jar:, gopher: where supported)<br>
XXE - XInclude Injection (if XInclude processing enabled)<br>
XXE - SSRF via External Entity Resolution<br>

### Template Injection
Template Injection - Server-Side (SSTI)<br>
Template Injection - Client-Side (CSTI)<br>
Server-Side Template Injection (Jinja2, ERB, Twig, etc.)<br>
Expression Language Injection (EL Injection)<br>
EL Injection - Spring EL<br>
EL Injection - OGNL Injection<br>
EL Injection - MVEL Injection<br>



## Cross-Site Scripting (XSS) (CWE-79)

### XSS - Primary Variants
Cross-site Scripting (XSS) - DOM (CWE-79)<br>
Cross-site Scripting (XSS) - Reflected (CWE-79)<br>
Cross-site Scripting (XSS) - Stored (CWE-79)<br>
Cross-site Scripting (XSS) - Generic (CWE-79)<br>
Cross-site Scripting (XSS) - Mutation (mXSS)<br>
Cross-site Scripting (XSS) - Self XSS<br>
Cross-site Scripting (XSS) - Universal XSS (UXSS)<br>
Cross-site Scripting (XSS) - Blind XSS (out-of-band callback / victim is admin tooling)<br>
Cross-site Scripting (XSS) - Persistent DOM XSS (stored data later used by DOM sinks)<br>

### XSS - Context-Specific
Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) (CWE-80)<br>
XSS via HTML Context<br>
XSS via HTML Attribute Context (quoted/unquoted attributes)<br>
XSS via HTML URI Attribute Context (href/src/action/poster/srcdoc etc.)<br>
XSS via JavaScript Context<br>
XSS via JavaScript Template Literal Context (backticks, ${} interpolation)<br>
XSS via JSON-in-HTML Context (inline JSON then parsed, quote breaking)<br>
XSS via CSS Context<br>
XSS via URL Context<br>
XSS via Event Handlers<br>
XSS via HTML5 Events (onload, onerror, etc.)<br>
XSS via DOM Sink APIs (innerHTML/outerHTML/insertAdjacentHTML/document.write/srcdoc)<br>

### XSS - Vector-Specific
XSS via SVG<br>
XSS via HTML Injection (non-script tags that become script via parsing/mutation)<br>
XSS via Data URIs<br>
XSS via JavaScript Protocol (javascript:)<br>
XSS via VBScript Protocol (legacy IE contexts)<br>
XSS via Canvas<br>
XSS via Web Workers<br>
XSS via Service Workers<br>
XSS via Web Components<br>
XSS via Iframe<br>
XSS via Object Tag<br>
XSS via Embed Tag<br>
XSS via Markdown/BBCode Rendering<br>
XSS via JSONP / Script Include Reflection (callback parameter abuse)<br>
XSS via File Upload (HTML/SVG polyglot served with sniffable Content-Type)<br>
XSS via postMessage Handling (origin check bypass + DOM sink)<br>
XSS - Framework Gadgets (AngularJS sandbox escapes, React dangerouslySetInnerHTML, Vue moustache contexts)<br>

### XSS - Encoding Bypass
XSS via Double Encoding<br>
XSS via Multiple Decode Passes (double decode across proxy/framework/app)<br>
XSS via Unicode Encoding<br>
XSS via HTML Entity Encoding<br>
XSS via Character Reference<br>
XSS via Character Reference Edge Cases (no semicolon, mixed hex/dec, overlong sequences)<br>
XSS via Mixed Encoding<br>
XSS via UTF-7/UTF-8 Mismatch<br>
XSS via Legacy/Non-UTF8 Charset Confusion (Shift_JIS / ISO-2022-JP edge cases)<br>
XSS via JavaScript Escape Confusion (\\xNN, \\uNNNN, \\u{...} decoding differences)<br>
XSS via CSS Escape Confusion (CSS \HHHHH escapes)<br>

### XSS - Filter Bypass
XSS Using MIME Type Mismatch (CAPEC-209)<br>
XSS - Whitelist Bypass<br>
XSS - Regex Bypass<br>
XSS - Case Sensitivity Bypass<br>
XSS - Null Byte Injection<br>
XSS - Comment Injection<br>
XSS - Tag/Attribute Balancing (parser differential between filter and browser)<br>
XSS - Polyglot Payloads (works across multiple contexts)<br>
XSS - Sanitizer Differential (DOMPurify/bleach/etc. vs browser parsing)<br>

### XSS - Advanced Variants
Mutated XSS (mXSS)<br>
DOM Clobbering + XSS<br>
MathML-based XSS<br>
PDF XSS<br>
Flash-based XSS (if Flash exists)<br>
Encoding Confusion XSS<br>
Content Security Policy (CSP) Bypass via XSS<br>
XSS - CSP Gadget Abuse (nonce/hash reuse, JSONP endpoints, allowed script gadgets)<br>
XSS - Trusted Types Bypass / Missing Trusted Types (sink protections absent)<br>
XSS via Prototype Pollution -> DOM Sink (polluted config leads to dangerous rendering)<br>



## Authentication & Password Management

### Authentication Bypass
Authentication Bypass Using an Alternate Path or Channel (CWE-288)<br>
Authentication Bypass - Direct SQL Injection<br>
Authentication Bypass - Parameter Pollution<br>
Authentication Bypass - JWT Flaws<br>
Authentication Bypass - Cookie Manipulation<br>
Authentication Bypass - Default Credentials<br>
Authentication Bypass - Weak Verification<br>
Authentication Bypass - Logic Flaw<br>
Authentication Bypass - Client-Side Validation<br>
Authentication Bypass - Null/Empty Password<br>
Authentication Bypass - SSO/OIDC Misconfiguration (accept unsigned/none alg tokens, missing aud/iss checks)<br>
Authentication Bypass - OAuth Misconfiguration (implicit flow issues, code substitution, redirect URI tricks)<br>
Authentication Bypass - Account Linking Confusion (login with provider A links to victim account)<br>
Authentication Bypass - Email/Phone Verification Not Enforced (unverified accounts gain access)<br>
Authentication Bypass - “Remember Device” / Trusted Device Logic Flaw<br>
Authentication Bypass - Magic Link Reuse / Not Bound to Session/Device<br>

### Brute Force
Brute Force (CWE-307)<br>
Brute Force - Credential Stuffing<br>
Brute Force - Rate Limiting Bypass<br>
Brute Force - Distributed Attack<br>
Brute Force - Dictionary Attack<br>
Brute Force - Rainbow Table<br>
Brute Force - CAPTCHA Bypass<br>
Brute Force - CAPTCHA Assistance<br>
Brute Force - Account Lockout Bypass<br>
Brute Force - Timing Window Bypass<br>

### Core Authentication Issues
Improper Authentication - Generic (CWE-287)<br>
Missing Authentication for Critical Function (CWE-306)<br>
No Authentication on Admin Panels<br>
No Authentication on Sensitive APIs<br>
Auth - Weak Password Policy / No Password Complexity or Length Requirements<br>
Auth - Password Policy Bypass (Unicode, whitespace trimming, normalization differences)<br>
Auth - Username/Email Canonicalization Issues (case folding, dots/plus addressing confusion)<br>
Auth - Login CSRF / Forced Login (attacker logs victim into attacker account)<br>

### Password Reset Attacks
Password Reset Vulnerability<br>
Password Reset - Predictable Token<br>
Password Reset - Token Reuse<br>
Password Reset - Token Brute Force<br>
Password Reset - Token Expiration Bypass<br>
Password Reset - Email Enumeration<br>
Password Reset - Security Question Bypass<br>
Password Reset - Account Recovery Abuse<br>
Password Reset - Link Interception<br>
Password Reset - Token Not Bound to User/Session (swap token across accounts)<br>
Password Reset - Host Header Poisoning (reset link generated with attacker-controlled host)<br>

### Account Lockout & Security
Account Lockout Bypass<br>
Account Lockout - Timing Window Exploitation<br>
Account Lockout - Progressive Bypass<br>
Account Enumeration via Lockout<br>

### Credential Change Issues
Unverified Password Change (CWE-620)<br>
Password Change - No Old Password Verification<br>
Password Change - Session Fixation<br>
Password Change - CSRF<br>
Password Change - Does Not Invalidate Other Sessions/Tokens<br>
Password Change - Old Password Still Valid (race / eventual consistency)<br>

### Password Recovery
Weak Password Recovery Mechanism for Forgotten Password (CWE-640)<br>
Password Recovery - Weak Secret Questions<br>
Password Recovery - Recovery Code Reuse<br>
Password Recovery - Recovery Token Prediction<br>

### Multi-Factor Authentication
Two-Factor Authentication Bypass<br>
2FA - SMS Interception<br>
2FA - TOTP Predictability<br>
2FA - Backup Code Reuse<br>
2FA - Backup Code Prediction<br>
2FA - QR Code Bypass<br>
2FA - Push Notification Fatigue<br>
2FA - Biometric Bypass<br>
2FA - Hardware Token Spoofing<br>
2FA - Recovery Code Exposure<br>
2FA - Enrollment/Disable Not Re-Authenticated (change MFA settings without password)<br>
2FA - Step-Up Auth Missing (sensitive action requires only 1st factor)<br>
2FA - Rate Limit Missing on OTP Entry (online brute force)<br>

### WebAuthn / FIDO2 Issues
WebAuthn - rpId Misconfiguration (origin/domain mismatch bypass)<br>
WebAuthn - Challenge Reuse / Not Bound to Session/User<br>
WebAuthn - User Verification vs Presence Confusion (UV required but not enforced)<br>
WebAuthn - Attestation Trust Misconfigured / Unnecessarily Trusted<br>
WebAuthn - Duplicate Credential IDs / Account Linking Confusion<br>
WebAuthn - Resident Keys Handling Bugs (credential discovery and misuse)<br>
WebAuthn - allowCredentials Manipulation (empty list allows unexpected authenticators)<br>
WebAuthn - U2F `appid` Extension Confusion (legacy origin scope bypass)<br>
WebAuthn - `enterpriseAttestation` Misuse (over-trusting enterprise attestations)<br>
WebAuthn - `credProtect` Level Misconfiguration (credentials readable without UV)<br>
WebAuthn - CTAP1 vs CTAP2 Fallback Confusion (policy gaps across transports)<br>
WebAuthn - Passkey Sync Surfaces (cross-device synced credentials trust issues)<br>

### CAPTCHA Issues
Guessable Captcha (CWE-804)<br>
CAPTCHA - Image Recognition Bypass<br>
CAPTCHA - Weak Algorithm<br>
CAPTCHA - Reuse<br>
CAPTCHA - Time Window Bypass<br>
CAPTCHA - Audio CAPTCHA Bypass<br>
CAPTCHA - Accessibility Bypass<br>

### Other Authentication Issues
Phishing (CAPEC-98)<br>
Insecure Password Storage (in session/memory)<br>
Credential Logging<br>
Login Timing Attack<br>
Username Enumeration<br>
Account Enumeration<br>
Email Enumeration via Reset Function<br>
Auth - Session Created Before Full Auth (partial auth state abuse)<br>
Auth - Multi-tenant Login Confusion (tenant switch via header/param)<br>



## Authorization & Access Control

### Core Authorization Issues
Improper Access Control - Generic (CWE-284)<br>
Improper Authorization (CWE-285)<br>
Incorrect Authorization (CWE-863)<br>
Missing Authorization (CWE-862)<br>
Authorization Check Bypass<br>
Authorization Logic Flaw<br>
Authorization - Multi-Tenant Isolation Failure (org_id/tenant_id not enforced server-side)<br>
Authorization - Cache-Based Authorization Bypass (shared cache key missing user/role/tenant)<br>

### Insecure Direct Object Reference (IDOR)
Insecure Direct Object Reference (IDOR) (CWE-639)<br>
IDOR - Horizontal Privilege Escalation<br>
IDOR - Vertical Privilege Escalation<br>
IDOR - Parameter Pollution<br>
IDOR - Numeric ID Enumeration<br>
IDOR - UUID Prediction<br>
IDOR - Hash Collision<br>
IDOR - Encoding Bypass<br>
IDOR - Missing Authorization Check<br>
IDOR - Indirect Reference Bypass (predictable mapping tables / short links)<br>
IDOR - Batch/Bulk Endpoints (modify list of IDs to include unauthorized objects)<br>
IDOR - GraphQL BOLA/BFLA (field-level auth missing)<br>

### Access Control Enforcement
Client-Side Enforcement of Server-Side Security (CWE-602)<br>
Access Control - Client-Side Validation Only<br>
Access Control - Hidden Field Manipulation<br>
Access Control - Parameter Tampering<br>

### Privilege-Related Issues
Execution with Unnecessary Privileges (CWE-250)<br>
Improper Privilege Management (CWE-269)<br>
Privilege Escalation (CAPEC-233)<br>
Privilege Escalation - Vertical<br>
Privilege Escalation - Horizontal<br>
Privilege Escalation - Sudo/Root<br>
Privilege Escalation - Kernel Exploit<br>
Privilege Escalation - SUID Binary Abuse<br>
Privilege Escalation - Insecure sudo Configuration<br>
Privilege Escalation - LD_PRELOAD Injection<br>
Privilege Escalation - DLL Hijacking<br>
Privilege Escalation - SetUID Bypass<br>

### Permission-Related Issues
Incorrect Permission Assignment for Critical Resource (CWE-732)<br>
Improper Handling of Insufficient Permissions or Privileges (CWE-280)<br>
Overly Permissive File Permissions<br>
Overly Permissive Directory Permissions<br>

### Function & Object Level Access Control
Function-Level Access Control Bypass<br>
Function-Level Authorization (FLAC) Bypass<br>
Function-Level Access - HTTP Method Bypass<br>
Function-Level Access - Method Override Header Abuse (X-HTTP-Method-Override)<br>
Object-Level Access Control Bypass<br>
Object-Level Authorization (OLAC) Bypass<br>
Object-Level Access - Parameter Manipulation<br>
Object-Level Access - Nested Object Injection (child object auth not enforced)<br>
Object-Level Access - Alternate Identifier Abuse (slug vs id vs uuid uses different checks)<br>

### Role-Based Access Control (RBAC)
RBAC Misconfiguration<br>
RBAC - Role Confusion<br>
RBAC - Role Inheritance Bypass<br>
RBAC - Default Role Abuse<br>

### Attribute-Based Access Control (ABAC)
ABAC Bypass<br>
ABAC - Attribute Injection<br>
ABAC - Policy Bypass<br>

### Capability-Based Access Control
Capability-Based Access Control Bypass<br>
Capability Token Theft<br>
Capability Token Prediction<br>

### Advanced Authorization Attacks
Delegation Abuse<br>
Impersonation Attack<br>
Permission Escalation via Role Confusion<br>



## Cryptography & Encryption

### Cipher/Algorithm Issues
Cryptographic Issues - Generic (CWE-310)<br>
Inadequate Encryption Strength (CWE-326)<br>
Use of a Broken or Risky Cryptographic Algorithm (CWE-327)<br>
Use of DES/3DES<br>
Use of MD5/SHA1<br>
Use of MD4<br>
Use of RC4<br>
Use of RC2<br>
Use of Insecure Stream Cipher<br>
Use of Insecure Block Cipher Mode (ECB)<br>

### Hash-Related Issues
Reversible One-Way Hash (CWE-328)<br>
Weak Hash Function<br>
Hash Collision Vulnerability<br>
Hash Rainbow Table Attack<br>
Hash - No Salt Used<br>
Hash - Weak Salt Generation<br>
Password Hashing - Weak Parameters (low cost factor / iterations / memory)<br>
Password Hashing - Fast Hash Used for Passwords (SHA* without KDF)<br>

### Key Management Issues
Key Exchange without Entity Authentication (CWE-322)<br>
Reusing a Nonce, Key Pair in Encryption (CWE-323)<br>
Use of a Key Past its Expiration Date (CWE-324)<br>
Missing Required Cryptographic Step (CWE-325)<br>
Key Storage in Plaintext<br>
Key Derivation - Weak Function<br>
Key Derivation - Insufficient Iterations<br>
Key Rotation - Missing<br>
Key Rotation - Improper Implementation<br>
Key Management - Weak KDF Choice (PBKDF2 params too low / scrypt/Argon2 misconfig)<br>
Key Management - Predictable/Static IV/Nonce Generation<br>
Key Management - Key ID / Version Confusion (selecting wrong key for verify/decrypt)<br>

### RNG/Randomness Issues
Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) (CWE-338)<br>
Use of Insufficiently Random Values (CWE-330)<br>
PRNG - Predictable Seed<br>
PRNG - State Prediction<br>
PRNG - Insufficient Entropy<br>
PRNG - Java Random (not SecureRandom)<br>
PRNG - PHP mt_rand<br>
PRNG - Weak Random Library<br>
PRNG - JavaScript Math.random() Used for Tokens/Secrets<br>

### Encryption Mode Issues
ECB Mode Usage<br>
ECB Mode - Pattern Leakage<br>
IV Reuse in Encryption<br>
CBC Mode - IV Predictability<br>
CBC Mode - Padding Oracle<br>
Counter Mode - Nonce Reuse<br>
GCM Mode - IV Reuse<br>
GCM Mode - Missing AAD Binding (context not authenticated)<br>

### Password Encryption
Weak Cryptography for Passwords (CWE-261)<br>
Password Hashing - No Salt<br>
Password Hashing - Weak Algorithm (MD5, SHA1)<br>
Password Hashing - Single Hash Iteration<br>
Password Hashing - Crackable Function<br>

### Hard-coded Cryptography
Use of Hard-coded Cryptographic Key (CWE-321)<br>
Hard-coded Key in Source Code<br>
Hard-coded Key in Binary<br>
Hard-coded Key in Configuration<br>

### Advanced Cryptographic Attacks
Padding Oracle Attack<br>
Side-Channel Attacks<br>
Timing Attack (Crypto)<br>
Cache Timing Attack<br>
Power Analysis Attack<br>
Fault Injection Attack<br>
Meet-in-the-Middle Attack<br>
Collision Attack on Hash Functions<br>
Pre-image Attack on Hashes<br>



## Credential Storage & Transmission

### Insecure Storage
Cleartext Storage of Sensitive Information (CWE-312)<br>
Password Stored in Plaintext<br>
API Key Stored in Plaintext<br>
Database Password in Plaintext<br>
Private Key Stored in Plaintext<br>
Secrets in Crash Dumps / Core Dumps<br>
Secrets in APM/Monitoring Tools (Sentry/NewRelic payload capture)<br>

Plaintext Storage of a Password (CWE-256)<br>
Storing Passwords in a Recoverable Format (CWE-257)<br>
Reversible Password Hashing<br>
Password Encryption with Weak Cipher<br>

Insecure Storage of Sensitive Information (CWE-922)<br>
Sensitive Data in Browser Cache<br>
Sensitive Data in Application Cache<br>
Sensitive Data in Backup<br>

Missing Encryption of Sensitive Data (CWE-311)<br>

### Credential in Files & Configuration
Password in Configuration File (CWE-260)<br>
Password in web.config<br>
Password in .env file<br>
Password in application.properties<br>
Password in application.yml<br>
Password in settings.py (Django)<br>
Password in config.php<br>
Secrets in CI/CD Config (GitHub Actions, GitLab CI, Jenkins)<br>
Secrets in Kubernetes Manifests/Helm Values<br>

Password in Codebase<br>
Password Hardcoded in Source Code<br>

Password in Comments<br>
Credentials in Code Comments<br>
Temporary Password in Comments<br>

Password in Version Control<br>
Password Committed to Git<br>
Password in Git History<br>
Password in .git/config<br>

### Credential in Environment & Memory
Password in Environment Variables (Unprotected)<br>
Password Visible in /proc/<pid>/environ<br>
Password Visible in Process List<br>
Password in Memory Dump<br>
Secrets in Command-Line Arguments (ps output)<br>

Insecure Password Storage (in session/memory)<br>
Password in Session Variables<br>
Password in Memory (Plain)<br>

### Hard-coded Credentials
Use of Hard-coded Credentials (CWE-798)<br>
Hard-coded Admin Password<br>
Hard-coded API Key<br>
Hard-coded Database Password<br>
Hard-coded Service Account<br>
Hard-coded Token<br>

Use of Hard-coded Password (CWE-259)<br>
Default Hard-coded Password<br>

### Connection Strings & Tokens
Database Credentials in Connection Strings<br>
Connection String in Log Files<br>
Connection String in Error Messages<br>
Connection String in Source Code<br>

### Client-Side Credentials
API Keys in Client-Side Code<br>
API Key Visible in JavaScript<br>
API Key in HTML Source<br>
Secret Token in Frontend<br>
Secrets in Source Maps (exposed .map files)<br>
Secrets in Mobile/Desktop Client Apps (hardcoded in binaries)<br>

Tokens in Browser Local Storage<br>
JWT in localStorage<br>
Session Token in localStorage<br>
Refresh Token in localStorage<br>
Password in localStorage<br>

### Transport Security
Cleartext Transmission of Sensitive Information (CWE-319)<br>
HTTP (not HTTPS) for Sensitive Data<br>
Unencrypted API Communication<br>
Unencrypted Database Connection<br>

Insufficiently Protected Credentials (CWE-522)<br>
Unprotected Transport of Credentials (CWE-523)<br>
Credentials Over HTTP<br>
Credentials Over Unencrypted Channel<br>

### Sensitive Data Exposure
Sensitive Data in Logs<br>
Password in Application Logs<br>
Password in Access Logs<br>
API Key in Logs<br>
Token in Logs<br>
PII in Logs<br>
Secrets in Analytics/Telemetry Events (client->vendor leakage)<br>

Metadata Leakage<br>
Excessive Data Exposure<br>



## Session Management

### Session Lifetime Issues
Insufficient Session Expiration (CWE-613)<br>
No Session Timeout<br>
Excessive Session Timeout<br>
Session Never Expires<br>
Idle Timeout Not Enforced (activity not tracked server-side)<br>
Absolute Timeout Missing (only sliding/idle expiration)<br>
Sliding Expiration Abuse (keepalive endpoint extends session indefinitely)<br>
Remember-Me / Persistent Session Token Never Expires<br>
Refresh Token Acts as Long-Lived Session (no rotation / no revocation)<br>
Logout Does Not Invalidate Server-Side Session<br>

### Session Fixation
Session Fixation (CWE-384)<br>
Session Fixation - Cookie Reuse<br>
Session Fixation - Pre-login Session<br>
Session Fixation - URL Parameter<br>
Session Fixation - No Session Regeneration<br>
Session Fixation - Session ID Accepted from Multiple Locations (Cookie + Header + Param)<br>
Session Fixation - Login CSRF / Forced Login (attacker forces victim into attacker-controlled session)<br>
Session Fixation - Cookie Tossing (subdomain sets parent-domain session cookie)<br>
Session Fixation - Path Confusion Cookie Shadowing (attacker sets more specific Path cookie)<br>
Session Fixation - Hostname Confusion / Alternate Host Sets Cookie<br>
Session Fixation - Session Adoption (server accepts attacker-chosen session ID)<br>

### Session Hijacking
Session Hijacking<br>
Session Token Theft via XSS<br>
Session Token Interception<br>
Session Cookie Theft<br>
Session Hijacking - Token in URL (Referer leakage, browser history, logs)<br>
Session Hijacking - Token in Redirect Location Header<br>
Session Hijacking - Token Leaked via Third-Party Requests (analytics/pixels)<br>
Session Hijacking - Token Captured via MITM / TLS Downgrade / Bad HTTPS Config<br>
Session Hijacking - Session Token Reuse After Password Change<br>
Session Hijacking - Session Token Reuse After Logout<br>

### Session Prediction & Weakness
Session Prediction<br>
Predictable Session ID<br>
Weak Session Token Generation<br>
Weak Session ID Algorithm<br>
Weak Session ID Length<br>
Session ID - Timestamp/Counter-Based Tokens<br>
Session ID - Low Entropy PRNG / Guessable RNG Seed<br>
Session ID - Sequential / Incremental IDs<br>
Session ID - Deterministic Encoding (base64/hex of user id + time)<br>
Session ID - UUID Misuse (non-random UUID versions / predictable UUIDs)<br>
Session Token Brute Force (short tokens / weak rate limiting)<br>

### Session Token Encoding / Normalization Confusion
Session Token - URL Encoding / Double URL Encoding Confusion<br>
Session Token - Base64 vs Base64URL Confusion (+/ vs -_ and padding)<br>
Session Token - Mixed Hex/Base64 Parsing Confusion<br>
Session Token - Unicode Normalization Confusion (NFC/NFD) in token handling<br>
Session Token - Whitespace/Control Character Truncation (leading/trailing spaces, \t, \r\n)<br>
Session Token - Null Byte Truncation (%00) in downstream components<br>
Session Token - Compression/Decompression Confusion (e.g., JWT "zip" handling)<br>

### Cookie-Related Issues
Reliance on Cookies without Validation and Integrity Checking in a Security Decision (CWE-784)<br>
Cookie Tampering<br>
Cookie Forgery<br>
Cookie Validation Bypass<br>
Cookie Integrity Check Missing<br>

Cookie Theft via XSS<br>
Cookie Exposure in Error Messages<br>
Cookie in Logs<br>

Cookie-Based Session Fixation<br>
Cookie Domain Scope Bypass<br>
Cookie Path Scope Bypass<br>
Cookie Scope - Domain Attribute Misuse (overbroad domain, leading dot quirks)<br>
Cookie Scope - Public Suffix / eTLD+1 Confusion<br>
Cookie - Secure Flag Missing<br>
Cookie - HttpOnly Missing<br>
Cookie - SameSite Missing / Misconfigured (Lax/Strict/None)<br>
Cookie - SameSite=None Without Secure (dropped by modern browsers)<br>
Cookie - Max-Age/Expires Confusion (persistence bugs)<br>
Cookie Prefix Bypass - __Host- Misuse (should be Secure, no Domain, Path=/)<br>
Cookie Prefix Bypass - __Secure- Misuse (should be Secure)<br>

Cookie Parsing/Handling Quirks<br>
Cookie - Duplicate Cookie Names (shadowing / last-wins vs first-wins differences)<br>
Cookie - Multiple Cookie Headers (proxy/app disagreement)<br>
Cookie - Case Sensitivity Differences in Cookie Names<br>
Cookie - Quoted Values / Special Characters Parsing Differences<br>
Cookie - Semicolon/Comma Delimiter Confusion<br>
Cookie - Whitespace Normalization Differences around '=' and ';'<br>

### Session Timeout Issues
Session Timeout Bypass<br>
Session Timeout - Timing Window<br>
Session Timeout - Concurrent Request<br>
Session Timeout - Keepalive/Background Requests Prevent Expiry<br>
Session Timeout - Timeout Enforced Only Client-Side (UI timer only)<br>
Session Timeout - Refresh Token Extends Session Beyond Intended Window<br>

### Concurrent Session Issues
Concurrent Session Usage<br>
Multiple Active Sessions<br>
Session Multiplexing<br>
Concurrent Session Limit Bypass (multiple devices/tokens allowed)<br>
Logout/Invalidate Race (one session invalidates another incorrectly)<br>

### Session State Issues
Session State Corruption<br>
Session State Manipulation<br>
Session State in URL<br>
Session State Exposure<br>
Session State - Cross-App Session Confusion (shared cookie across apps/paths)<br>
Session State - Environment Confusion (staging/prod share cookie domain)<br>
Session State - CSRF Token Not Bound to Session (token reuse across sessions)<br>
Session State - Privilege Change Not Reflected in Session (stale roles)<br>



## Path Traversal & File Access

### Path Traversal - Core
Path Traversal (CWE-22)<br>
Path Traversal - Directory Traversal<br>
Path Traversal - Navigate to Parent Directory<br>
Path Traversal - Read Arbitrary File<br>
Path Traversal - Write Arbitrary File<br>
Path Traversal - Delete/Overwrite File<br>
Path Traversal - Bypass “Safe Directory” Root (broken chroot/jail logic)<br>

### Path Traversal - Bypass Techniques
Path Traversal - Null Byte Injection (%00)<br>
Path Traversal - Encoding Bypass (URL Encoding)<br>
Path Traversal - Double Encoding (%252e)<br>
Path Traversal - Unicode Encoding (%u002e)<br>
Path Traversal - Backslash Bypass (\\)<br>
Path Traversal - Trailing Slash/Dot (./, ../, ...)<br>
Path Traversal - Mixed Slash (/ and \\)<br>
Path Traversal - Case Sensitivity Bypass<br>
Path Traversal - Extension Bypass<br>
Path Traversal - Dot-Segment Confusion (./, ../, ././/, ..//)<br>
Path Traversal - “..” Obfuscation (.%2e, %2e., %2e%2e)<br>
Path Traversal - Encoded Separator Bypass (%2f, %5c)<br>
Path Traversal - Double-Encoded Separators (%252f, %255c)<br>
Path Traversal - Mixed Encodings (URL + Unicode + Double-URL)<br>
Path Traversal - Overlong UTF-8 / Legacy UTF-8 Decoding Bypass<br>
Path Traversal - Unicode Slash Variants (normalization of “/” lookalikes)<br>
Path Traversal - Unicode Dot Variants (normalization of “.” lookalikes)<br>
Path Traversal - Unicode Normalization (NFC/NFD/NFKC/NFKD) Confusion<br>
Path Traversal - Path Separator Normalization Differences (app vs framework vs proxy)<br>
Path Traversal - Path Collapse/Canonicalization Differences (realpath/resolve mismatch)<br>
Path Traversal - Filter-on-Input / Use-after-Decode (validate before decode, use after decode)<br>
Path Traversal - Validate-on-Decode / Use-before-Decode (validate after decode, use raw)<br>
Path Traversal - Multiple Decoding Passes (decode twice in different layers)<br>
Path Traversal - Partial Decoding (some layers decode %2f, others do not)<br>
Path Traversal - URL Path vs Query Parameter Differences (path segment traversal vs param traversal)<br>
Path Traversal - Semicolon/Matrix Param Confusion (`;` in paths)<br>
Path Traversal - Fragment/Anchor Confusion (`#` stripped/kept inconsistently)<br>
Path Traversal - Whitespace/Control Character Confusion (\t, \r\n) in path parsing<br>
Path Traversal - Trailing Space/Dot Handling Differences (Windows-specific trimming)<br>
Path Traversal - Alternative Data Streams / Suffix Confusion (platform-specific)<br>

### Path Traversal Variants
Path Traversal: '.../...//' (CWE-35)<br>
Path Traversal - Absolute Path<br>
Path Traversal - Relative Path<br>
Path Traversal - Mixed Absolute/Relative (e.g., `C:..\..` semantics on Windows)<br>
Path Traversal - Path Prefix Confusion (leading `//` or `\\` treated specially)<br>
Path Traversal - UNC Path Access (\\\\server\\share\\path)<br>
Path Traversal - Windows Drive Letter Paths (C:\\Windows\\..., C:/Windows/...)<br>
Path Traversal - Windows Device Paths (\\\\?\\, \\\\.\\)<br>
Path Traversal - Windows Short Names (8.3) / Alternate Representation<br>
Path Traversal - Tilde/Environment Expansion Confusion (server-side expansion bugs)<br>

Relative Path Traversal (CWE-23)<br>
Relative Path - Directory Escape<br>
Relative Path - Prefix Stripping Bypass (remove `../` once, leave rest)<br>
Relative Path - Allowlist Prefix Bypass (prefix allowed but later segments escape)<br>

### File Inclusion Attacks
File Inclusion - Local File Inclusion (LFI)<br>
LFI - /etc/passwd<br>
LFI - /etc/shadow<br>
LFI - /etc/hosts<br>
LFI - /proc/self/environ<br>
LFI - /proc/self/cmdline<br>
LFI - /proc/self/fd (file descriptor tricks)<br>
LFI - Application Secrets (env/config/keys)<br>
LFI - Config Files<br>
LFI - Source Code<br>
LFI - Log Files<br>
LFI - Session Files<br>
LFI - Encoding Bypass<br>
LFI - Path Normalization Bypass (realpath mismatch)<br>
LFI - Windows Files (win.ini, hosts, IIS/web.config, etc.)<br>

File Inclusion - Remote File Inclusion (RFI)<br>
RFI - Remote Code Execution<br>
RFI - Log Poisoning<br>
RFI - Protocol Abuse (php://, data://)<br>
RFI - Redirect-Based Fetch (follow redirects to restricted schemes/hosts)<br>
RFI - DNS Rebinding-Assisted File Fetch (if hostname allowlist exists)<br>

File Inclusion - Log Poisoning<br>
Log Poisoning - Access Log<br>
Log Poisoning - Error Log<br>
Log Poisoning - Application Log<br>
Log Poisoning - User-Agent/Header Injection then Include<br>
Log Poisoning - Newline/CRLF Injection into Logs then Include<br>

File Inclusion - Wrapper Abuse<br>
Wrapper Abuse - php:// Protocol<br>
Wrapper Abuse - php://filter (transform-based file read)<br>
Wrapper Abuse - data:// Protocol<br>
Wrapper Abuse - file:// Protocol (if supported by target language/runtime)<br>
Wrapper Abuse - glob:// Protocol<br>
Wrapper Abuse - phar:// Protocol<br>
Wrapper Abuse - zip:// / jar:file: / archive wrappers (runtime-specific)<br>
Wrapper Abuse - expect:// / ssh2:// / ftp:// wrappers (runtime-specific)<br>
Wrapper Abuse - rar:// Protocol<br>
Wrapper Abuse - ogg:// Protocol<br>

### Path Traversal via Data Conversion / Extraction
Archive Extraction Traversal (Zip Slip / Tar Slip / 7z Traversal)<br>
Path Traversal - Filename Normalization Bugs during Unzip/Untar<br>
Path Traversal - Symlink-in-Archive then Write Outside Root<br>
Path Traversal - Hardlink-in-Archive then Overwrite Target File<br>
Path Traversal - Windows Path in Archive (drive letter / UNC) Confusion<br>
Path Traversal - Mixed Separator Paths in Archives (\\ vs /)<br>
Path Traversal - Unicode Normalization in Archive Entry Names<br>
Path Traversal - Double-Decode in Archive Entry Names (%252e%252e etc.)<br>

### Directory & Browsing Issues
Forced Browsing (CWE-425)<br>
Directory Traversal via Parameter<br>
Directory Listing Enabled<br>
Hidden Directory Discovery<br>
Admin Directory Exposure<br>
Backup Directory Exposure<br>
Forced Browsing - Backup/Temp Extensions (.bak, .old, .swp, .tmp)<br>
Forced Browsing - Source/VC Paths (.git/, .svn/, .hg/)<br>

### Temporary File Issues
Insecure Temporary File (CWE-377)<br>
Temporary File Enumeration<br>
Temporary File - Predictable Name<br>
Temporary File - World Readable<br>
Temporary File - World Writable<br>
Temporary File - Symlink Swap / TOCTOU (tmp file race)<br>

### Search Path Issues
Untrusted Search Path (CWE-426)<br>
Current Directory in PATH<br>
Executable in Writable Directory<br>
DLL Hijacking via PATH<br>
Search Path - Relative Include/Require Path Hijack (runtime-specific)<br>
Search Path - Library Load Path Hijack (runtime-specific)<br>

### Symlink & Hard Link Issues
Symbolic Link Following (Symlink Attack)<br>
Symlink - Race Condition<br>
Symlink - Directory Escape<br>
Hard Link Attack<br>
Hard Link - File Overwrite<br>
Symlink - Upload then Link to Sensitive Target (file read/write via symlink)<br>



## Request/Response Manipulation

### CSRF Attacks
Cross-Site Request Forgery (CSRF) (CWE-352)<br>
CSRF - Token Bypass<br>
CSRF - Token Reuse<br>
CSRF - Token Prediction<br>
CSRF - Double Submit Cookies<br>
CSRF - SameSite Bypass<br>
CSRF - SameSite=Lax Bypass via Top-Level Navigation / GET-to-POST Patterns<br>
CSRF - SameSite=None Cookie Misconfiguration (missing Secure)<br>
CSRF - GET-based<br>
CSRF - POST-based<br>
CSRF - Multipart Form<br>
CSRF - JSON POST<br>
CSRF - Content-Type Confusion (form vs json endpoints)<br>
CSRF - CORS + CSRF Chaining (misconfigured CORS enables credentialed cross-origin writes)<br>
CSRF - No Token Validation<br>
CSRF - Weak Token Validation<br>
CSRF - Token in Body Bypass (via URL)<br>
CSRF - Token Not Bound to Session/User (swap token across accounts)<br>
CSRF - Token in Cookie Only (readable by attacker-controlled subdomain)<br>

### HTTP Request Smuggling
HTTP Request Smuggling (CWE-444)<br>
HTTP Request Smuggling - CL.TE (Content-Length/Transfer-Encoding)<br>
HTTP Request Smuggling - TE.CL<br>
HTTP Request Smuggling - TE.TE<br>
HTTP Request Smuggling - CL.CL<br>
HTTP Request Smuggling - Frontend/Backend Mismatch<br>
HTTP/2 Rapid Reset Attack<br>
HTTP/2 to HTTP/1.1 Downgrade Smuggling (H2->H1 translation differences)<br>
Request Smuggling - Header Normalization Differences (duplicate headers, whitespace, obs-fold)<br>
Request Smuggling - Chunked Parsing Edge Cases (invalid chunk sizes, extensions)<br>

### HTTP Response Manipulation
HTTP Response Splitting (CWE-113)<br>
HTTP Response Splitting - Header Injection<br>
HTTP Response Splitting - Cookie Injection<br>
HTTP Response Splitting - Cache Poisoning<br>

### Header Injection
Improper Neutralization of HTTP Headers for Scripting Syntax (CWE-644)<br>
HTTP Response Header Injection<br>
HTTP Header Injection<br>
Host Header Injection<br>
Host Header - Cache Poisoning<br>
Host Header - Password Reset Poisoning<br>
Host Header - Websocket/Absolute URL Generation Poisoning<br>
X-Forwarded-For Injection<br>
X-Original-URL Injection<br>
X-Rewrite-URL Injection<br>
X-Forwarded-Host / X-Forwarded-Proto Injection<br>
Forwarded Header Injection (RFC 7239)<br>

### URL & Encoding Issues
Improper Handling of URL Encoding (Hex Encoding) (CWE-177)<br>
URL Encoding Bypass<br>
Double URL Encoding<br>
Unicode URL Encoding<br>
URL Parsing Differential (WHATWG vs backend parser) / authority confusion<br>
Userinfo (@) Tricks / URL Credential Segment Confusion<br>

### HTTP Parameter Pollution
HTTP Parameter Pollution (HPP)<br>
HPP - Multiple Parameter Names<br>
HPP - Case Sensitivity Bypass<br>
HPP - Encoding Variation<br>
HPP - Parameter Duplication<br>
HPP - Array Parameter Confusion (?a=1&a=2 vs a[]=1&a[]=2)<br>
HPP - JSON vs Query Param Precedence Differences<br>



## Server-Side Request Forgery (SSRF)

### SSRF - Core Variants
Server-Side Request Forgery (SSRF) (CWE-918)<br>

### SSRF - Target Access
SSRF - Local File Access (file://)<br>
SSRF - Local File via /etc/passwd<br>
SSRF - Local File via /etc/hosts<br>

SSRF - Internal Service Access<br>
SSRF - Internal API Access<br>
SSRF - Internal Database Access<br>

SSRF - Port Scanning<br>
SSRF - Service Discovery<br>
SSRF - Link-local / Loopback Access (127.0.0.1, ::1, 169.254.169.254)<br>
SSRF - IPv6 Literal / IPv6 Zone ID Handling (parser quirks)<br>
SSRF - IP Encoding Tricks (decimal/octal/hex, mixed notation)<br>

### SSRF - Cloud/Metadata
SSRF - Cloud Metadata (AWS, GCP, Azure)<br>
SSRF - AWS EC2 Metadata<br>
SSRF - AWS IMDSv1<br>
SSRF - AWS IMDSv2<br>
SSRF - GCP Metadata Service<br>
SSRF - Azure Metadata<br>
SSRF - DigitalOcean Metadata<br>

### SSRF - Protocol Abuse
SSRF - Gopher Protocol<br>
SSRF - Dict Protocol<br>
SSRF - LDAP Protocol<br>
SSRF - FTP Protocol<br>
SSRF - SMTP Protocol<br>

### SSRF - Advanced
SSRF - DNS Rebinding<br>
SSRF - Bypass via URL Tricks<br>
SSRF - Encoding Bypass<br>
SSRF - Case Sensitivity Bypass<br>
SSRF - Whitelist Bypass<br>
SSRF - Redirect Chain Bypass (follow redirects to forbidden targets)<br>
SSRF - Hostname vs Resolved IP Allowlist Mismatch (DNS pinning issues)<br>
SSRF - URL Fragment/Query Confusion in Filters (validate one part, request another)<br>

### Advanced SSRF Vectors
SSRF via PDF Generation<br>
SSRF via Image Processing (ImageMagick)<br>
SSRF via Video Processing<br>
SSRF via Document Conversion<br>
SSRF via Webhook Systems<br>
SSRF via Notification Services<br>
SSRF via GraphQL<br>



## Redirect & Navigation

### Open Redirect
Unvalidated/Open Redirect (CWE-601)<br>
Open Redirect - Absolute URL<br>
Open Redirect - Relative URL<br>
Open Redirect - Protocol-based (javascript:, data:, vbscript:)<br>
Open Redirect - Double Encoding Bypass<br>
Open Redirect - Unicode Encoding Bypass<br>
Open Redirect - Case Sensitivity Bypass<br>
Open Redirect - Null Byte Injection<br>
Open Redirect - Parameter Pollution<br>
Open Redirect - URL Parser Differential (//evil.com, \\evil.com, mixed slashes)<br>
Open Redirect - Scheme Confusion (http:\\evil.com in lenient parsers)<br>

### Advanced Redirect Bypass
Open Redirect - JavaScript<br>
Open Redirect - Meta Refresh<br>
Open Redirect - Header Injection<br>
Open Redirect - Whitelist Bypass<br>
Open Redirect - Partial Match Bypass<br>
Open Redirect - Domain Confusion<br>
Open Redirect - Subdomain Bypass<br>

### CORS Misconfiguration
Overly Permissive Cross-domain Whitelist (CWE-942)<br>
CORS Misconfiguration<br>
CORS - Wildcard Allow<br>
CORS - Null Origin<br>
CORS - Credential Leak<br>
CORS - Dynamic Origin Based on Input<br>
CORS - Regex Bypass in Origin Check<br>
CORS - Subdomain Wildcard Bypass<br>
CORS - Reflect Origin with Credentials (Access-Control-Allow-Origin echoes attacker origin)<br>
CORS - Insecure Preflight Caching (Access-Control-Max-Age too long / varies missing)<br>
CORS - Missing Vary: Origin (cache serves permissive ACAO to other origins)<br>

### DOM-Based Navigation
DOM-Based Open Redirect (CWE-1024)<br>
window.location Manipulation<br>
window.open Manipulation<br>
iframe.src Manipulation<br>

## Deserialization & Code Execution

### Language-Specific Deserialization
Deserialization of Untrusted Data (CWE-502)<br>
Deserialization - TypeName/Polymorphic Type Handling Enabled (gadget instantiation)<br>
Deserialization - Signed/Encrypted Token Confusion (accepts unsigned serialized blobs)<br>

Java Deserialization (RCE)<br>
Java Serialization - Gadget Chain<br>
Java - commons-collections<br>
Java - Spring Framework Gadgets<br>
Java - JNDI Injection<br>

Python Pickle Deserialization<br>
Python Pickle - Arbitrary Code Execution<br>
Python - yaml.load(unsafe)<br>
Python - Unsafe JSON Deserialization to Objects (custom object_hook)<br>

PHP Unserialization<br>
PHP - __wakeup() Bypass<br>
PHP - __destruct() Exploitation<br>
PHP - POP Chain<br>

NodeJS Deserialization<br>
NodeJS - Function Constructor<br>
NodeJS - Unsafe Object Merge<br>

YAML Deserialization<br>
YAML - Arbitrary Code Execution<br>
YAML - Object Construction<br>

JSON Deserialization with Type Confusion<br>
JSON - Type Juggling<br>
JSON Schema/Validation Confusion<br>
JSON Schema - additionalProperties misuse (accepts attacker-supplied fields)<br>
JSON Merge-Patch Prototype Pollution ({"__proto__": {"polluted": true}})<br>
JSON Parser Differential (duplicate keys first/last wins impacting authz)

Ruby Marshal Deserialization<br>
Go Serialization Issues<br>
C# BinaryFormatter RCE<br>
C# / .NET - TypeNameHandling (Json.NET) / polymorphic deserialization gadgets<br>
Java - Jackson Default Typing / polymorphic deserialization gadgets<br>

### Code Execution Related
Remote Code Execution (RCE) - General<br>
Command Execution via Expression Language<br>

Download of Code Without Integrity Check (CWE-494)<br>
Code Integrity Verification Missing<br>

Embedded Malicious Code (CWE-506)<br>
Malicious Code in Dependencies<br>
Malicious Code in Library<br>

Replicating Malicious Code (Virus or Worm) (CWE-509)<br>

### Backdoors & Debug Code
Leftover Debug Code (Backdoor) (CWE-489)<br>
Debug Endpoints Exposed<br>
Test Code in Production<br>

Malware (CAPEC-549)<br>



## Input Validation

### Core Input Validation
Improper Input Validation (CWE-20)<br>
No Input Validation<br>
Whitelist Missing<br>
Blacklist Bypass<br>
Input Validation - Type Confusion (string vs number vs boolean vs null)<br>
Input Validation - JSON Parser Differential (duplicate keys, NaN/Infinity handling)<br>
Input Validation - Content-Type Confusion (treat JSON as form or vice versa)<br>
Input Validation - Unicode Normalization / Case Folding Confusion<br>

### Escape/Control Sequence Issues
Improper Neutralization of Escape, Meta, or Control Sequences (CWE-150)<br>
Escape Character Bypass<br>
Control Character Injection<br>

### Blacklist Issues
Incomplete Blacklist (CWE-184)<br>
Blacklist Bypass - Encoding<br>
Blacklist Bypass - Case Sensitivity<br>
Blacklist Bypass - Homograph<br>
Blacklist Bypass - Null Byte<br>
Blacklist Bypass - Unicode<br>

### Format String Attacks
Use of Externally-Controlled Format String (CWE-134)<br>
Format String Attack - %x (Read)<br>
Format String Attack - %n (Write)<br>
Format String Attack - Information Disclosure<br>
Format String Attack - Arbitrary Write<br>

### Error Handling
Improper Check or Handling of Exceptional Conditions (CWE-703)<br>
Unchecked Error Condition (CWE-391)<br>
Missing Error Handling<br>
Insufficient Error Handling<br>
Exception Handling - Fail-Open on Parser Errors (invalid input accepted on error path)<br>



## Memory Safety Issues

### Buffer Overflow
Buffer Overflow (CWE-120)<br>
Stack Buffer Overflow<br>
Stack Buffer Overflow - Return Address Overwrite<br>
Stack Buffer Overflow - ROP Chain<br>
Heap Buffer Overflow<br>
Heap Buffer Overflow - Heap Metadata Corruption<br>
Off-by-one Buffer Overflow<br>

### Buffer Over-read/Under-read
Buffer Over-read (CWE-126)<br>
Information Disclosure via Buffer Over-read<br>
Buffer Under-read (CWE-127)<br>

### Buffer Underflow
Buffer Underflow (CWE-124)<br>

### Double Free & Heap Issues
Double Free (CWE-415)<br>
Double Free - Heap Corruption<br>
Heap Overflow (CWE-122)<br>
Heap Overflow - Metadata Corruption<br>
Heap Overflow - Use After Free Chain<br>
Memory Corruption - Generic (CWE-119)<br>

### Null Pointer Issues
NULL Pointer Dereference (CWE-476)<br>
NULL Pointer Dereference - Crash (DoS)<br>
NULL Pointer Dereference - Code Execution<br>

### Stack Overflow
Stack Overflow (CWE-121)<br>
Stack Overflow - Recursion<br>
Stack Overflow - Deep Nesting<br>

### Use After Free
Use After Free (CWE-416)<br>
Use After Free - Information Disclosure<br>
Use After Free - Code Execution<br>
Use After Free - Double Free Chain<br>

### Array Index Issues
Array Index Underflow (CWE-129)<br>
Out-of-bounds Read (CWE-125)<br>
Out-of-bounds Write<br>

### Integer Issues
Integer Overflow (CWE-190)<br>
Integer Overflow - Arithmetic<br>
Integer Overflow - Allocation<br>
Integer Overflow - Buffer Size Calculation<br>

Integer Underflow (CWE-191)<br>
Integer Underflow - Negative Size<br>

Wrap-around Error (CWE-128)<br>
Integer Wrap-around<br>

### Off-by-one Errors
Off-by-one Error (CWE-193)<br>
Off-by-one - Array Access<br>
Off-by-one - Loop Condition<br>

### Buffer Size Issues
Incorrect Calculation of Buffer Size (CWE-131)<br>
Buffer Size Miscalculation<br>
Buffer Size Underestimation<br>

### String/Null Termination
Improper Null Termination (CWE-170)<br>
Missing Null Terminator<br>
Null Termination Bypass<br>

### Arbitrary Write Primitive
Write-what-where Condition (CWE-123)<br>
Arbitrary Memory Write<br>
Arbitrary Function Pointer Write<br>
Arbitrary VTable Write<br>



## Type Safety & Logic Issues

### Type Confusion
Type Confusion (CWE-843)<br>
Type Confusion - JavaScript<br>
Type Confusion - PHP<br>
Type Confusion - Python<br>
Type Confusion - Java Generics<br>
Type Confusion - Loose Typing<br>

### Type Coercion
Type Coercion Bypass<br>
String to Number Coercion<br>
String to Boolean Coercion<br>
NULL Type Confusion<br>
Numeric Truncation / Rounding Issues (float->int, locale decimals)<br>

### Comparison Issues
Incorrect Comparison (CWE-697)<br>
Loose Comparison (== vs ===)<br>
Weak Comparison in JavaScript<br>
String Number Comparison<br>
Boolean Comparison Bypass<br>

### Immutability Issues
Modification of Assumed-Immutable Data (MAID) (CWE-471)<br>
Constant Modification<br>
Final Field Modification<br>
Immutable Object Mutation<br>

Object Mutation<br>
Object Property Modification<br>
Object State Corruption<br>



## Information Disclosure

### Generic Information Disclosure
Information Disclosure (CWE-200)<br>

### Directory/File Exposure
File and Directory Information Exposure (CWE-538)<br>
Directory Listing Enabled<br>
Backup File Exposure<br>
Hidden File Disclosure (.git, .env, .swp, .bak)<br>
Source Code Disclosure<br>
Configuration File Disclosure<br>
Private Key Disclosure<br>

### Debug Information Exposure
Information Exposure Through Debug Information (CWE-215)<br>
Debug Mode Enabled<br>
Stack Traces Exposed<br>
Debug Variables Exposed<br>
Debug Endpoints Accessible<br>
Debug Console Enabled<br>
Source Maps Exposed<br>
Profiling Endpoints Accessible (`/prof`, `pprof`, `/flame`)<br>
Metrics Endpoints Leaking Internal State (`/metrics`, `/actuator`, `/health`)<br>
Coverage Reports Exposed (`/__coverage__`, `/coverage`)<br>
Test Endpoints in Production (`/__tests__`, `/test`, `/e2e`)<br>
Swagger UI / API Docs in Production (`/swagger`, `/api-docs`, `/redoc`)<br>

### Error Message Disclosure
Information Exposure Through an Error Message (CWE-209)<br>
Verbose Error Messages<br>
SQL Error Messages (Table/Column Names)<br>
Database Error Details<br>
Framework Error Messages<br>
File Path Disclosure in Errors<br>

### Directory Listing
Information Exposure Through Directory Listing (CWE-548)<br>
Apache Directory Listing<br>
Nginx Directory Listing<br>

### Timing-Based Leaks
Information Exposure Through Discrepancy (CWE-203)<br>
Timing Attack<br>
Response Time Discrepancy<br>
Processing Time Analysis<br>

Information Exposure Through Timing Discrepancy (CWE-208)<br>
Timing-based Information Leak<br>
Constant-Time Comparison Missing<br>

### Data in Transit/Storage
Information Exposure Through Sent Data (CWE-201)<br>
Data in Logs<br>
Data in Cookies<br>
Data in Response Headers<br>
Data in Error Messages<br>
Secrets in Client-Side Error Reports (stack traces/telemetry)<br>

### Privacy & Excessive Exposure
Privacy Violation (CWE-359)<br>
PII in Logs<br>
PII Exposure via API<br>
PII in Cookies<br>

Metadata Leakage<br>
File Metadata Exposure<br>
Image EXIF Data<br>
Document Metadata<br>

Excessive Data Exposure<br>
API Returning Unnecessary Data<br>
Bulk Data Extraction<br>



## Certificate & Transport Security

### Certificate Validation
Improper Certificate Validation (CWE-295)<br>
Certificate Validation - Missing<br>
Certificate Validation - Hostname Mismatch<br>
Certificate Validation - Wildcard Certificate Bypass<br>
Certificate Validation - Self-Signed Certificate<br>
Certificate Validation - Expired Certificate<br>

### Certificate Pinning
Certificate Pinning Bypass<br>
Certificate Pinning - Hardcoded Pin Extraction<br>
Certificate Pinning - Dynamic Pin Bypass<br>

### Certificate Chain
Improper Following of a Certificate's Chain of Trust (CWE-296)<br>
Certificate Chain - Intermediate Compromise<br>
Certificate Chain - Root CA Bypass<br>
Certificate Chain - Revocation Bypass<br>

### TLS/SSL Issues
Man-in-the-Middle (CWE-300)<br>
SSL/TLS Downgrade Attack<br>
SSL/TLS - Protocol Downgrade (to SSLv3, TLSv1.0)<br>
TLS - Weak Diffie-Hellman Parameters / Logjam-Style Issues<br>
TLS - Missing HSTS (Strict-Transport-Security) / HSTS Misconfiguration<br>
TLS - Mixed Content (HTTPS page loads HTTP subresources)<br>
TLS - Heartbleed<br>
TLS - CRIME Attack<br>
TLS - BEAST Attack<br>
TLS - POODLE Attack<br>

### MITM Attacks
MITM - Certificate Spoofing<br>
MITM - Proxy Attack<br>
MITM - ARP Spoofing<br>

### DNS Security
Reliance on Reverse DNS Resolution for a Security-Critical Action (CWE-350)<br>
DNS Spoofing<br>
DNS Cache Poisoning<br>
DNS Hijacking<br>
DNS Rebinding<br>
DNS Tunneling (exfiltration)<br>

### Encryption Channel Issues
Inadequate Encryption Strength<br>
Encryption - Weak Cipher Suite<br>
Encryption - RC4<br>
Encryption - DES/3DES<br>

## Business Logic & Configuration

### CTF Playbook - Business Logic Quick Checks
Focus on server-side validation vs client trust:<br>
- Tamper prices/quantities/discount fields in intercepted requests (Burp) and hidden inputs<br>
- Try out-of-range values (negative, fractional, huge) and boundary tests (0/1/max)<br>
- Concurrency: redeem same gift card/coupon in parallel tabs; double-submit checkout<br>
- Change currency/region/shipping params; observe tax/VAT/shipping threshold logic<br>
- Webhooks: replay payment/refund events; test idempotency keys presence/enforcement<br>
- State machine: call steps out of order (confirm before pay, ship before confirm)<br>
- Multi-tenant edges: apply actions across tenants/orgs; header/param-based tenant switching

### Price & Quantity Manipulation
Business Logic Errors (CWE-840)<br>
Price Manipulation - Direct Price Change<br>
Price Manipulation - Cart Manipulation<br>
Price Manipulation - Coupon Stacking<br>
Price Calculation Order-of-Operations Bugs (discount after tax vs before)<br>
Client-side Price Anchoring (computed only in browser; server trusts client total)<br>
Quantity Bypass - Negative Quantities<br>
Quantity Bypass - Fractional Quantities<br>
Quantity Bypass - Zero Quantity<br>
Quantity Bypass - Decimal Quantities<br>
Quantity Rounding / Floating-Point Errors (0.1+0.2 edge cases)

### Transaction & Payment Bypass
Workflow Bypass - Payment Step Skip<br>
Workflow Bypass - Order Confirmation Skip<br>
Transaction Replay<br>
Transaction Reversal<br>
Partial Payment Bypass<br>
Double Charging Prevention Bypass<br>
Payment Intent/Status Confusion (mark paid via client parameter)<br>
Refund Without Payment / Over-refund via multiple partial refunds<br>
Webhook Idempotency Missing (replay creates duplicate orders/credits)

### Coupon & Discount Abuse
Coupon Code Reuse<br>
Coupon Code Enumeration<br>
Coupon - Applied to Unauthorized Items<br>
Coupon - Stack Multiple Coupons<br>
Coupon - Expired Coupon Acceptance<br>
Coupon Scope Misconfiguration (applies across tenants or excluded categories)
Coupon Minimum Threshold Manipulation (decimal rounding to meet free shipping/discount)

### Reward & Currency Manipulation
Gift Card Exploitation<br>
Gift Card Balance Manipulation<br>
Gift Card Transfer Bypass<br>
Loyalty Points Manipulation<br>
In-Game Currency Manipulation<br>
Gift Card Double-Spend via Race Condition (redeem same code concurrently)<br>
Self-Referral / Referral Abuse (multi-account loops, cookie tampering)
Currency Conversion Manipulation (change currency param for lower price)

### Inventory & Availability
Inventory System Bypass<br>
Inventory Negative Balance<br>
Out-of-Stock Item Purchase<br>
Stock Reservation Bypass<br>
Flash Sale Exploitation<br>
Hold-to-Purchase Window Exploitation (reservation time extension loop)
Backorder Logic Abuse (force shipment despite no stock)

### Misconfiguration
Misconfiguration (CWE-16)<br>
Debug Mode Enabled<br>
Default Credentials<br>
Overly Permissive Permissions<br>
Admin Panel Exposed<br>
Test/Staging Exposed to Production<br>

### DNS Misconfiguration
DNS misconfiguration<br>
DNS Wildcard (*)<br>
Subdomain Takeover<br>
Subdomain Enumeration<br>
Zone Transfer (AXFR) Allowed<br>

### Security Through Obscurity
Security Through Obscurity (CWE-656)<br>
Relying on Hidden Files for Security<br>
Hidden Client Flags for Premium Features (enable via param)
Feature Flag Misconfiguration (beta features accessible without auth)
Obscured Admin Paths<br>
Hidden API Endpoints<br>

### Design Principles Violation
Violation of Secure Design Principles (CWE-657)<br>
Missing Authentication Check<br>
Missing Authorization Check<br>
Missing Input Validation<br>
Missing Error Handling<br>

## File Upload & Content Processing

### Upload Validation & Storage
Unrestricted File Upload (CWE-434)<br>
Content-Type Trust / MIME Sniffing Confusion<br>
File Extension Validation Bypass (double extensions, trailing dots/spaces, case folding)<br>
Unicode Normalization / Homoglyph Extension Bypass<br>
Null Byte Truncation in Filename/Path (legacy components)<br>
Path Traversal in Upload Filename / Storage Key ("../" in name or metadata)<br>
Overwrite Existing Files (same name/key) / Race Conditions in Upload Finalize<br>
Direct Object Reference to Uploaded Files (IDOR on download endpoints)<br>

### Parser Differentials & Polyglots
File Polyglots (valid in multiple formats; content-based detection bypass)<br>
Archive Smuggling (ZIP slip, TAR traversal, symlink/hardlink in archives)<br>
Decompression Bombs (ZIP/GZIP/7z) / Resource Exhaustion via Parsing<br>
Image Processing RCE Surface (ImageMagick/FFmpeg/libvips/ghostscript class issues)<br>
Office/PDF Processing Surface (macros/embedded objects, PDF actions, parser bugs)<br>
Metadata/EXIF Injection (downstream rendering/templating consumers)<br>
Polyglot Payload Details (SVG+HTML, PDF+JS, GIF with JavaScript) for stored XSS/RCE surfaces<br>
Content Sniffing at Edge/CDN vs Origin Mismatch (X-Content-Type-Options absent)<br>
Office Remote Template Injection (DOCX/RTF referencing remote resources)<br>
Image ICC Profile Injection (metadata parsers code paths)<br>

### Multipart Parser Differentials
Boundary Obfuscation / Malformed Boundary Handling (accepts invalid boundaries)<br>
Conflicting Filename/Content-Type Fields (last-wins vs first-wins)<br>
Mixed Case Header Names / Duplicate Headers in Parts<br>
Null Byte / Encoding Tricks Inside Part Headers<br>
Multiple File Fields with Same Name (unexpected overwrite/merge)<br>
RFC 5987 `filename*=` Encoding Handling (parser support differences)<br>
Content-Transfer-Encoding Quirks (base64/quoted-printable acceptance differences)<br>
Trailing Whitespace in Boundary Lines (accept vs reject)<br>
Chunked + Multipart Combination Edge Cases (frontend/backend disagreement)<br>
CRLF Variants Inside Part Headers (\r\n vs \n parsing)<br>

## SSO / Identity Provider Integrations (SAML / OIDC / OAuth)

### OIDC / OAuth Integration Issues
redirect_uri Parsing Differences (scheme/host/path normalization confusion)<br>
Missing/Weak state Validation (login CSRF / session swapping)<br>
PKCE Missing / PKCE Downgrade (public clients)<br>
Issuer Confusion / JWKS Confusion (accepting tokens from wrong issuer/JWKS)<br>
Nonce Missing / Weak Nonce Validation (replay)<br>
Over-broad Scopes / Consent Misuse (least privilege failure)<br>
OAuth Device Code Flow Misconfiguration (broad device auth, user code reuse, polling endpoint auth gaps)<br>
Device Flow `user_code` Reuse Across Accounts (phishing + session swap)<br>
`verification_uri_complete` Open Redirect/Link Spoofing (social engineering vectors)<br>
Device Flow Polling Endpoint Missing AuthZ (bind to client/user/session)<br>
Polling Interval Ignored (aggressive polling -> DoS or rate bypass)<br>

### SAML Integration Issues
SAML Signature Wrapping (XSW) / XML canonicalization quirks<br>
SAML Response/Assertion Signature Validation Gaps (partial validation)<br>
Insecure IdP-Initiated Flow Handling (unsolicited responses)<br>
Audience/Recipient/ACS URL Validation Gaps (accepting for wrong SP)<br>

## Caching / CDN / Edge

### Cache Key & Normalization Issues
Cache Key Normalization Bugs (path/query/header canonicalization differences)<br>
Vary Header Misuse / Missing Vary (user-specific content cached)<br>
Authenticated Responses Cached as Public (session leakage)<br>
Host Header / X-Forwarded-Host Cache Poisoning<br>
Stale-While-Revalidate / Race Conditions Returning Other Users' Data<br>
Unkeyed Header Gadgets (Accept-Language, Accept-Encoding, X-Forwarded-Proto) poisoning preconditions<br>
ESI Injection (Edge Side Includes) leading to cache poisoning / content splicing<br>
Client Hints Unkeyed (Sec-CH-UA, Sec-CH-UA-Platform, viewport) causing variant mix-ups<br>
Authorization Header Caching Misconfig (caches responses despite auth)<br>
CDN Cache Key Misconfiguration (missing user/tenant/role dimensions)<br>

### Edge Rewrites & Routing
CDN/Reverse Proxy Rewrite Differentials (proxy vs app routing disagreement)<br>
Private Origin Exposed Directly (bypass WAF/CDN/auth at edge)<br>

## Observability / Telemetry Leakage

### Logging, Tracing, Analytics
Secrets in Server Logs (Authorization headers, cookies, tokens)<br>
Secrets in Client-Side Error Reports (stack traces/telemetry)<br>
Secrets in Analytics/Telemetry Events (client->vendor leakage)<br>
Trace Header Abuse (traceparent/baggage) leading to log injection / data leakage<br>
Debug Endpoints in Production (metrics, profiling, health checks with sensitive info)<br>

## Denial of Service

### Rate Limiting & Throttling Bypass
Allocation of Resources Without Limits or Throttling (CWE-770)<br>
Rate Limiting Bypass - IP Spoofing<br>
Rate Limiting Bypass - X-Forwarded-For<br>
Rate Limiting Bypass - Client Rotation<br>
Rate Limiting Bypass - Thread Pool Exhaustion<br>
Rate Limiting Bypass - Endpoint/Route Variations (same action on multiple paths)<br>
Rate Limiting Bypass - Per-User vs Per-IP Mismatch (shared IP environments)<br>
Resource Exhaustion - Memory<br>
Resource Exhaustion - CPU<br>
Resource Exhaustion - Disk<br>
Resource Exhaustion - Bandwidth<br>
Resource Exhaustion - Connections<br>

### DDoS Attacks
Denial of Service (CWE-400)<br>
DDoS - Volumetric - UDP Flood<br>
DDoS - Volumetric - ICMP Flood<br>
DDoS - Volumetric - DNS Query Flood<br>
DDoS - Protocol-based - SYN Flood<br>
DDoS - Protocol-based - Fragmented IP<br>
DDoS - Protocol-based - Ping of Death<br>
DDoS - Application-layer - HTTP Flood<br>
DDoS - Application-layer - SlowLoris<br>

### Data Amplification Attacks
Improper Handling of Highly Compressed Data (Data Amplification) (CWE-409)<br>
Zip Bomb - Nested Compression<br>
Zip Bomb - Zero-byte Files<br>
XML Bomb - Billion Laughs Attack<br>
XML Bomb - Quadratic Blowup<br>
Gzip Bomb<br>
Brotli Bomb<br>

### Algorithmic Complexity
Uncontrolled Recursion (CWE-674)<br>
Algorithmic Complexity Attack - Regular Expression ReDoS<br>
Algorithmic Complexity Attack - Sorting Algorithm<br>
Algorithmic Complexity Attack - Hash Collision<br>
Algorithmic Complexity Attack - Database Query<br>
Algorithmic Complexity - GraphQL Depth/Complexity Abuse<br>

### Slowdown Attacks
Slowloris Attack<br>
Slow HTTP POST<br>
Slow Read Attack<br>
Slow Headers<br>
Slow Body<br>

### Resource Depletion
Connection Exhaustion<br>
Memory Allocation Loop<br>
CPU Utilization Attack<br>
Disk Space Exhaustion<br>

## UI & User Interaction

### Clickjacking & UI Redressing
UI Redressing (Clickjacking) (CAPEC-103)<br>
Clickjacking - Button Hijacking<br>
Clickjacking - Drag & Drop<br>
Clickjacking - with Transparency<br>
Clickjacking - Form Field Overlay<br>
Clickjacking - Frame Busting Bypass<br>
Clickjacking - X-Frame-Options Bypass<br>
Clickjacking - frame-ancestors CSP Misconfiguration / Missing<br>

### Visual Spoofing
User Interface (UI) Misrepresentation of Critical Information (CWE-451)<br>
Visual Spoofing - URL Bar<br>
Visual Spoofing - SSL Certificate<br>
Visual Spoofing - Domain Names<br>
Visual Spoofing - Favicon Manipulation<br>
Visual Spoofing - Look-alike Domains<br>

### HTML Injection & UI Manipulation
HTML Injection for UI Manipulation<br>
UI Injection - Popup/Alert Spoofing<br>
UI Injection - Content Insertion<br>
UI Injection - Form Hijacking<br>

### CSS-based Attacks
CSS Injection<br>
CSS - Input Validation Bypass<br>
CSS - Event Handler<br>

## Race Conditions & Synchronization

### TOCTOU Vulnerabilities
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') (CWE-362)<br>
Time-of-check Time-of-use (TOCTOU) Race Condition (CWE-367)<br>
TOCTOU - File Operations (symlink, stat/open)<br>
TOCTOU - File Permissions<br>
TOCTOU - Account Operations (check balance, withdraw)<br>
TOCTOU - Resource Allocation<br>
TOCTOU - Authentication State<br>

### Asynchronous Race Conditions
Async Race Condition<br>
Promise Race Condition<br>
Event Handler Race Condition<br>
Database Transaction Race Condition<br>
Cache Coherency Race Condition<br>

### Lock & Synchronization Issues
Double Lock<br>
Lock-Order Deadlock<br>
Missing Lock<br>
Stale Lock<br>

### State Management Races
State Machine Race Condition<br>
Initialization Race Condition<br>
Finalization Race Condition<br>
Webhook/Callback Replay (idempotency missing)<br>
Payment/Order Race (double-spend via concurrent checkout)<br>
Coupon/Gift Card Redemption Race (redeem same code in parallel)<br>
Inventory Reservation Race (overselling limited stock)<br>

## Data Control & State Management

### State Data Manipulation
External Control of Critical State Data (CWE-642)<br>
State Variable Tampering<br>
Session State Manipulation<br>
Application State Manipulation<br>
Workflow State Bypass<br>

### Resource Reference Control
Externally Controlled Reference to a Resource in Another Sphere (CWE-610)<br>
Insecure Direct Object Reference (IDOR) - Reference Manipulation<br>
Path Traversal via Resource Reference<br>
Cross-context Reference<br>

### Exposed Functionality
Exposed Dangerous Method or Function (CWE-749)<br>
Exposed Admin Methods<br>
Exposed Debug Methods<br>
Exposed Internal APIs<br>

### Component & Module Security
Improper Export of Android Application Components (CWE-926)<br>
Exposed Broadcast Receiver<br>
Exposed Content Provider<br>
Exposed Service<br>
Exported Activity<br>

### Supply Chain & Dependencies
Inclusion of Functionality from Untrusted Control Sphere (CWE-829)<br>
Supply Chain Attack<br>
Dependency Confusion - NPM<br>
Dependency Confusion - PyPI<br>
Typosquatting Attack<br>
Dependency Hijacking<br>
Subresource Integrity (SRI) Missing / Bypass (third-party scripts tamper risk)<br>
CDN/Third-Party Widget Trust (script injection via provider compromise)<br>
SRI + `crossorigin` Nuance (anonymous vs use-credentials affects integrity checks)<br>
Registry Substitution/Mirror Attacks (alternate registry serving malicious packages)<br>
Lockfile Integrity & Pinning (package-lock/shrinkwrap not enforced or absent)<br>
Self-hosted Library Integrity (hash/pin for internal CDN artifacts)<br>

### Untrusted Input Reliance
Trust of System Event Data (CWE-360)<br>
Reliance on Untrusted Inputs in a Security Decision (CWE-807)<br>
Use of Inherently Dangerous Function (CWE-242)<br>

### File Upload Vulnerabilities
Unrestricted Upload of File with Dangerous Type (CWE-434)<br>
File Upload - Extension Bypass (.php.jpg)<br>
File Upload - MIME Type Bypass<br>
File Upload - Double Extension (.php.png)<br>
File Upload - Null Byte Injection (.php%00.jpg)<br>
File Upload - Polyglot Files (PDF + PHP)<br>
File Upload - Content Validation Bypass<br>
File Upload - SVG Injection<br>
File Upload - GIF with JavaScript<br>
File Upload - Filename Path Traversal (../ in upload name)<br>
File Upload - Stored XSS via Uploaded HTML/SVG Served Inline<br>
File Upload - Archive Bomb / Decompression Bomb<br>
File Upload - Zip Slip (Path Traversal)<br>
File Upload - Archive Bomb<br>

## API & Web Service Vulnerabilities

### API Authentication & Authorization
API Key Exposure<br>
API Key Hardcoded<br>
API Key in URL<br>
API - Broken User Authentication<br>
API - Broken Function Level Authorization<br>
API - Broken Object Level Authorization (BOLA)<br>
API - BOLA - ID Enumeration<br>
API - BOLA - Sequential ID Prediction<br>
API - BOLA - UUID Bypass<br>
API - AuthZ via Header Trust (X-User/X-Role headers accepted from client)<br>
API - Tenant Header Confusion (X-Tenant/Org header not validated)<br>

### API Rate Limiting & DoS
API - Missing Rate Limiting<br>
API - Rate Limiting Bypass<br>
API - Lack of Resources & Rate Limiting<br>
API - Slow Rate Limit<br>
API - DoS - Bulk Operations<br>

### API Data Exposure
API - Excessive Data Exposure<br>
API - Unintended Data Exposure<br>
API - Debug Data Exposure<br>
API - GraphQL Introspection Leaking Schema (even when disabled via workarounds)<br>
API - WADL/WSDL Exposure (SOAP service definitions)<br>
API - OPTIONS Method Disclosure (reveals allowed methods/headers)<br>
API - Trace/Track Method Enabled (HTTP TRACE reflects request incl headers)<br>

### API Input Validation
API - Mass Assignment<br>
API - Parameter Pollution<br>
API - Content-Type Confusion<br>
API - Improper JSON Parsing<br>
API - Duplicate JSON Keys (last-wins vs first-wins authz/input differences)<br>
API - Unknown Field Handling (silently accepted dangerous fields)<br>

### GraphQL Attacks
GraphQL - Introspection Enabled<br>
GraphQL - Query Depth Abuse<br>
GraphQL - Fragment Abuse<br>
GraphQL - Alias Abuse<br>
GraphQL - DoS via Complexity<br>
GraphQL - Circular Reference<br>
GraphQL - Field Duplication<br>
GraphQL - Batching/Multipart Requests Abuse<br>
GraphQL - Authorization Missing on Resolvers (BOLA/BFLA)<br>
GraphQL - Persisted Query Bypass (tamper hash/id to run arbitrary query)<br>
GraphQL - Federation Edge Cases (entity resolution auth gaps across services)<br>
GraphQL - File Upload Spec Abuse (multipart handling quirks, auth bypass via uploads)<br>
GraphQL - Router/Proxy Rate Limit & Cache Key Bugs (per-user keys missing)<br>

### WebSockets
WebSocket Auth Confusion (missing auth on upgrade, cookie-only trust)<br>
WebSocket Origin Check Missing / Weak<br>
WebSocket CSRF via auto-connect in victim browser<br>
WebSocket Header Injection / Protocol Mismatch (Sec-WebSocket-Protocol abuse)<br>
WebSocket Message Injection / Lack of server-side validation<br>
WebSocket `permessage-deflate` Resource Exhaustion (compression bombs / CPU spikes)<br>
WebSocket Binary/Text Type Confusion (validator assumes one type)<br>
WebSocket CORS/CSP Misconfig at handshake (edge proxies trusting Origin)<br>

### HTTP/2 & gRPC
HTTP/2 to HTTP/1 Desync (proxy/backend parsing differences)<br>
H2C (cleartext upgrade) Exposure / Misconfig<br>
gRPC Reflection Abuse (enumerate services/methods)<br>
gRPC Message Fuzzing / Type Confusion (weak validation on protobuf fields)<br>
HTTP/2 Trailer/Header Quirks (cache/keying and auth filters bypass)<br>
Reverse proxy h2/h1 translation smuggling vectors (CL/TE mismatches across layers)
HTTP/3 / QUIC Misconfiguration (alt-svc upgrades, proxy translation gaps)

### Real-time Channels
Server-Sent Events (SSE) Exposure (auth/caching issues on event streams)<br>
SSE - Cache Poisoning / Unkeyed Stream Responses (mix user streams)<br>
SSE Event ID Reuse / Stream Resumption Mix-up (delivers other users' events)<br>
SSE `Cache-Control` / `Vary` Misuse (public caches serving private streams)<br>
WebRTC STUN/TURN Misconfiguration (leak internal IPs / relay exfil paths)<br>
TURN Credential Exposure / Reuse (static creds leaked in client code)<br>
WebRTC Peer Connection Trust Issues (origin/permission flows)<br>
WebRTC Data Channel AuthZ Missing (unauthenticated peer message acceptance)<br>

### REST API Issues
REST API - HTTP Method Bypass (PUT, DELETE, PATCH)<br>
REST API - Inconsistent HTTP Method Handling<br>
REST API - Header-based Authentication Bypass<br>
REST API - Content Negotiation<br>
REST API - Version Bypass (v1/v2 endpoint authorization differences)<br>
REST API - Pagination Limit Bypass (negative/huge offset or limit values)<br>
REST API - Pagination Cursor Manipulation (base64/JWT cursor tampering)<br>
REST API - Filter Injection (ORM/query builder injection via filter params)<br>
REST API - Sorting Column Injection (ORDER BY injection via sort parameter)<br>
REST API - Field Selection Bypass (requesting restricted fields via include/fields param)<br>
REST API - Bulk Operations Authorization Gaps (batch endpoints skip per-item checks)<br>
REST API - Swagger/OpenAPI Spec Exposure (reveals internal endpoints/schemas)<br>
REST API - Debug/Profiling Endpoints (`/debug`, `/metrics`, `/__coverage__`)<br>
REST API - Health Check Information Leakage (version/dependency info in responses)<br>

## Encoding & Escaping Issues

### Double/Triple Encoding Bypasses
Double Encoding Attack<br>
Double Encoding - %.252e (..)<br>
Double Encoding - %252f (/) Bypass<br>
Double Encoding - %252e%252e Path Traversal<br>
Triple Encoding<br>
Mixed Encoding (URL + HTML + Unicode)<br>

### Character Encoding Confusion
Charset Confusion (CWE-176)<br>
UTF-8/UTF-16 Mismatch<br>
UTF-7 Encoding Bypass<br>
UTF-32 Bypass<br>
Shift_JIS Encoding Bypass<br>
Unicode Normalization (NFC vs NFD)<br>
Overlong UTF-8 / Legacy UTF-8 Decoding Bypass<br>

### Escape Sequence Bypasses
HTML Entity Encoding Bypass<br>
JavaScript String Escaping Bypass<br>
URL Encoding Bypass<br>
Base64 Encoding Bypass<br>
Hex Encoding Bypass<br>

### Context-Specific Encoding Issues
Encoding Confusion - JavaScript Context<br>
Encoding Confusion - URL Context<br>
Encoding Confusion - SQL Context<br>
Encoding Confusion - XML Context<br>
Encoding Confusion - CSS Context (CSS escapes vs HTML escapes)<br>
Encoding Confusion - LDAP Context (RFC 4515/4514 escape mismatches)<br>
Encoding Confusion - JSON Context (unicode escapes, control char handling)<br>
Encoding Confusion - CSV Context (formula injection via =, +, -, @)<br>
Encoding Layer Mismatch (decode at proxy, use raw at app or vice versa)<br>
Partial Encoding (encode dangerous chars but miss edge cases / normalization)<br>
Nested Encoding Contexts (JSON in HTML in URL; innermost wins)<br>

## NoSQL Injection

### MongoDB Attacks
NoSQL Injection (CWE-943)<br>
MongoDB Injection<br>
MongoDB - Operator Injection ($ne, $gt, $regex)<br>
MongoDB - $ne Bypass ({"password": {"$ne": null}})<br>
MongoDB - $regex Bypass<br>
MongoDB - $where JavaScript Injection<br>
MongoDB - JavaScript Map-Reduce Injection<br>

### CouchDB Attacks
CouchDB Injection<br>
CouchDB - Selector Injection<br>
CouchDB - View Query Injection<br>

### ElasticSearch Attacks
ElasticSearch Injection<br>
ElasticSearch - Query Injection<br>
ElasticSearch - Query DSL Injection<br>

### Firebase & Realtime Database
Firebase - Insecure Rules<br>
Firebase - Wildcard Rules<br>

### Cassandra & Other NoSQL
Cassandra Injection<br>
Redis Injection<br>
Redis - Blind Injection<br>
Redis - Command Injection via EVAL/EVALSHA (Lua scripting abuse)<br>

### Generic NoSQL Attacks
NoSQL - Error-based Detection<br>
NoSQL - Time-based Blind Injection<br>
NoSQL - Boolean-based Blind<br>
NoSQL - Out-of-Band Exfiltration<br>
NoSQL - Aggregation Pipeline Injection (MongoDB $lookup/$merge/$graphLookup abuse)<br>
NoSQL - Type Confusion in Queries (string vs number vs object comparison bugs)<br>
NoSQL - Index Hinting Abuse (force inefficient queries via hint parameter)<br>

## JWT & Token Issues

### JWT Vulnerabilities
JWT - Algorithm Confusion<br>
JWT - No Signature Verification<br>
JWT - Weak Secret<br>
JWT - Key Confusion (RS256 to HS256 downgrade)<br>
JWT - Algorithm Downgrade (RS256 to none)<br>
JWT - Token Prediction<br>
JWT - Expired Token Acceptance<br>
JWT - Claims Manipulation (payload editing)<br>
JWT - Kid Injection (key ID)<br>
JWT - Jti Replay (no claim validation)<br>
JWT - JWKS Injection / JWK Header Abuse (jku/jwk/x5u where supported)<br>
JWT - Missing aud/iss/nbf Validation (accept tokens for other apps)<br>
JWT - Base64 vs Base64URL Confusion / Padding Handling Differences<br>

### Token Management Issues
OAuth 2.0 - Authorization Code Disclosure<br>
OAuth 2.0 - Token Theft<br>
OAuth 2.0 - Code Substitution<br>
OAuth 2.0 - State Parameter Bypass<br>
OAuth 2.0 - Redirect URI Bypass<br>

### Refresh Token Issues
Refresh Token - Prediction<br>
Refresh Token - No Rotation<br>
Refresh Token - No Expiration<br>

## Web Cache Poisoning

### Cache Poisoning Attacks
Web Cache Poisoning<br>
Cache Poisoning - Host Header Injection<br>
Cache Poisoning - X-Forwarded-Host Injection<br>
Cache Poisoning - X-Original-URL Injection<br>
Cache Poisoning - Query String Injection<br>
Cache Poisoning - Missing Vary Headers (cache key missing Origin/Host/Accept-Encoding)<br>
Cache Poisoning - Unkeyed Headers (X-Forwarded-Host, X-Original-URL, X-Host)<br>

### Cache Deception
Cache Deception Attack<br>
Cache Deception - Static Resource Confusion<br>
Cache Deception - Path Normalization<br>
Cache Deception - File Extension Confusion<br>

### Cache Splitting
HTTP Cache Splitting<br>
Cache Splitting - CRLF Injection<br>
Cache Splitting - Request Smuggling via Cache<br>

## XXE Advanced

### XXE Exploitation Techniques
XXE - Parameter Entity<br>
XXE - External DTD (SYSTEM/PUBLIC)<br>
XXE - Billion Laughs Attack (XML Bomb)<br>
XXE - Exfiltration via OOB (DNS/HTTP)<br>
XXE - Blind XXE with Out-of-Band Data<br>
XXE - Error-based Exfiltration<br>
XXE - File Wrapper Abuse<br>
XXE - Expect Module Exploitation<br>

## Subdomain & DNS
Moved to [Network.md](Network.md)<br>

## Server-Side Template Injection (SSTI) - Language Specific

### Python Template Engines
Jinja2 Template Injection<br>
Jinja2 - Payload: {{7*7}}<br>
Jinja2 - Filter Bypass<br>
Jinja2 - Attribute Access Bypass<br>

### JavaScript/Node.js Template Engines
Pug/Jade Template Injection<br>
Pug - Code Execution<br>
EJS Template Injection<br>
Handlebars Template Injection<br>

### Java Template Engines
Freemarker Template Injection<br>
Freemarker - API Bypass<br>
Velocity Template Injection<br>
Velocity - Directive Abuse<br>

### PHP/Ruby Template Engines
Twig Template Injection<br>
Twig - Payload Bypass<br>
ERB Template Injection<br>
Thymeleaf Template Injection (Spring)<br>

### Generic SSTI
SSTI - Expression Language Injection<br>
SSTI - SpEL (Spring Expression Language)<br>
SSTI - OGNL (Object-Graph Navigation Language)<br>
SSTI - MVEL (MVFLEX Expression Language)<br>
SSTI - Sandbox Escape (template engine sandbox bypass)<br>
SSTI - Server-Side Template Injection via Email/PDF Rendering Pipelines<br>
SSTI - Nunjucks Template Injection (Node.js)<br>
SSTI - Liquid Template Injection (Ruby/Jekyll)<br>
SSTI - Smarty Template Injection (PHP)<br>
SSTI - Go Template Injection (text/template, html/template)<br>
SSTI - Python f-string Injection (runtime format string evaluation)<br>

## Prototype Pollution & Object Manipulation

### Prototype Pollution Techniques
Prototype Pollution (JavaScript)<br>
Prototype Pollution - __proto__ Injection<br>
Prototype Pollution - Constructor.prototype Injection<br>
Prototype Pollution - Bypass via Encoding<br>
Prototype Pollution - Bypass via Case Variation<br>
Prototype Pollution - Bypass via Null Character<br>
Prototype Pollution - JSON Parse + Merge (pollution from request bodies)<br>
Prototype Pollution - Querystring Parser Pollution (a[__proto__][x]=1)<br>

### Object Injection
Object Property Injection<br>
Property Descriptor Pollution<br>
Accessor Property Injection<br>

### Merge/Extend Function Vulnerabilities
Merge/Extend Function Abuse<br>
Deep Merge Vulnerability<br>
Recursive Merge Bypass<br>

### Advanced Prototype Pollution
Prototype Pollution - Constructor Confusion<br>
Prototype Pollution - Function Property Pollution<br>
Prototype Pollution - Array Pollution<br>

## HTTP Parameter Pollution & Request Issues

### HTTP Parameter Pollution
HTTP Parameter Pollution (HPP)<br>
HPP - Case Sensitivity Variation<br>
HPP - Encoding Variation<br>
HPP - Multiple Parameters with Same Name<br>
HPP - Null Byte Injection<br>
HPP - Duplicate Parameter Handling<br>

### Host Header & Forwarding Headers
Host Header Attack<br>
Host Header - Password Reset Poisoning<br>
Host Header - Cache Poisoning<br>
Host Header - Redirect Poisoning<br>

### Forwarding Header Abuse
X-Forwarded-For Spoofing<br>
X-Forwarded-Host Injection<br>
X-Forwarded-Proto Abuse<br>
X-Original-URL/X-Rewrite-URL Bypass<br>
X-HTTP-Method-Override<br>

## Advanced Business Logic Attacks

### Pricing & Transaction Manipulation
Integer Overflow in Price Calculation<br>
Negative Price Processing<br>
Price Calculation Race Condition<br>

### Discount & Coupon Abuse
Discount Stacking<br>
Discount Percentage Manipulation<br>
Stacking Multiple Coupon Types<br>

### Refund & Payment Manipulation
Refund/Chargeback Abuse<br>
Partial Refund Bypass<br>
Refund Without Purchase<br>
Double Refund<br>

### Order Processing Bypass
Incomplete Transaction Processing<br>
Order State Manipulation<br>
Order Duplication<br>
Duplicate Order Processing<br>

### Shipping & Tax Bypass
Tax/Shipping Bypass<br>
Free Shipping Manipulation<br>
Zone/Region Manipulation<br>

### Account & Membership Exploitation
Loyalty Points Abuse<br>
Membership Downgrade Bypass<br>
Account Upgrade Manipulation<br>

## Advanced Authentication Attacks

### Enumeration Attacks
Login Timing Attack<br>
Timing-based Enumeration<br>
Username Enumeration<br>
Account Enumeration<br>
Email Enumeration via Reset Function<br>
Phone Number Enumeration<br>

### Session & Token Attacks
Weak Session Tokens<br>
Predictable Session IDs<br>
Session Token Entropy Analysis<br>
Session Token Collision<br>

### Concurrent Access & Abuse
Concurrent Login Abuse<br>
Simultaneous Session Abuse<br>
Device Fingerprinting Bypass<br>
Geo-location Check Bypass<br>
GPS Spoofing Bypass<br>

### Advanced Brute Force
Credential Stuffing - Account Takeover<br>
Distributed Brute Force<br>
Slow Brute Force (Rate Limit Bypass)<br>

## Client-Side Security Issues

### Browser Storage Issues
Local Storage/SessionStorage Injection<br>
LocalStorage - Sensitive Data Storage<br>
SessionStorage - Session Data Exposure<br>
Web Storage - XSS Exploitation<br>

### IndexedDB & Advanced Storage
IndexedDB Abuse<br>
IndexedDB - Unencrypted Sensitive Data<br>
IndexedDB - Cross-Tab Data Leakage (same origin different contexts)<br>
IndexedDB - Quota Exhaustion DoS (fill storage to block legitimate app)<br>
Web Storage Exploitation<br>
LocalForage Vulnerability<br>
Cache Storage API Poisoning (service worker caches attacker content)<br>
Persistent Storage Misconfiguration (sensitive data in persistent vs temporary)<br>
Storage Access API Bypass (partitioned storage access without user consent)<br>

### DOM Manipulation Issues
Insecure DOM Methods (eval, innerHTML, dangerouslySetInnerHTML)<br>
DOM Clobbering<br>
DOM Pollution via Prototype Pollution<br>
Dynamic Code Execution in DOM<br>

### JavaScript Execution Risks
eval() Code Execution<br>
Function() Constructor Abuse<br>
setTimeout/setInterval Code Injection<br>
JSON.parse() with User Input<br>

### Mobile & WebView Surfaces
Android Deep Link Intent Injection / URI Handler Abuse<br>
WebView JavaScript Bridge Injection / Insecure addJavascriptInterface<br>
SSL Pinning Bypass Surfaces (weak/no pinning in apps)<br>
iOS/Android Keychain/Keystore Misuse (unencrypted storage, broad ACLs)<br>
iOS Universal Links Misconfiguration (domain association not enforced)<br>
Android `android:autoVerify` Mismatch (links not verified, attacker-controlled)<br>
`intent:` Scheme Tricks (parameter injection to launch insecure flows)<br>
Exported Components Chain (Activities/Services/Receivers reachable unauthenticated)<br>
WebView SSL Error Handler Override (proceed on certificate errors)<br>

### Browser Extensions
Extension Messaging Injection / Origin Trust Gaps<br>
Insecure Extension Storage (tokens/secrets in local storage)<br>
Over-broad Permissions (file://, history, tabs) leading to data exfiltration<br>
Content Script XSS (DOM injection on arbitrary sites)<br>
`chrome.storage.sync` Sensitive Data Exposure (synced across accounts/devices)<br>
Remote Update/Sideload Supply Chain (auto-updates from untrusted sources)<br>
Relaxed CSP in Extensions (allow-eval/inline enabling code injection)<br>

### Modern Web Platform Surfaces
Progressive Web App (PWA) Manifest Injection (scope/start_url manipulation)<br>
Service Worker Scope Hijacking (register broader scope, intercept all traffic)<br>
Service Worker Cache Poisoning (attacker-controlled cache serving malicious responses)<br>
Service Worker Update Bypass (stale worker persists despite code changes)<br>
WebAssembly Module Injection / Untrusted WASM (side-channel/spectre risks)<br>
SharedArrayBuffer + Timing Attacks (high-resolution timer for side-channels)<br>
COOP/COEP Misconfiguration (cross-origin isolation bypass/downgrade)<br>
COOP `same-origin-allow-popups` Downgrade (popup reference leakage)<br>
COEP `credentialless` Misuse (resource loading without proper checks)<br>
PWA Installation Prompt Spoofing (beforeinstallprompt event abuse)<br>
Web Manifest `protocol_handlers` Abuse (register custom schemes for phishing)<br>

## Advanced File Operations

### Archive Traversal & Extraction
Zip Slip (Archive Traversal)<br>
Zip Slip - Path Traversal in Zip Extraction<br>
Tar Slip<br>
RAR Archive Slip<br>
7z Archive Slip<br>

### Symbolic & Hard Link Attacks
Symbolic Link Following (Symlink Attack)<br>
Symlink Attack - Race Condition<br>
Symlink Attack - Directory Escape<br>
Hard Link Attack<br>
Hard Link - File Overwrite<br>

### File Permission Issues
World-Readable Sensitive Files<br>
World-Writable Directories<br>
Predictable File Locations<br>

### Temporary File Security
Temporary File Enumeration<br>
Temporary File Race Condition<br>
Temp File Predictability<br>

Race Condition in File Operations<br>

## Advanced Cryptographic Attacks
Side-Channel Attacks<br>
Timing Attack (Crypto)<br>
Cache Timing Attack<br>
Power Analysis Attack<br>
Fault Injection Attack<br>
Meet-in-the-Middle Attack<br>
Collision Attack on Hash Functions<br>
Pre-image Attack on Hashes<br>
Padding Oracle<br>

## Advanced XSS Variants
Mutated XSS (mXSS)<br>
DOM Clobbering + XSS<br>
MathML-based XSS<br>
PDF XSS<br>
Flash-based XSS (if Flash exists)<br>
Encoding Confusion XSS<br>
Content Security Policy (CSP) Bypass via XSS<br>

## Browser Security Bypasses

### SOP & CORS Bypasses
Same-Origin Policy Bypass<br>
SOP - Postman Trick<br>
SOP - CORS Misconfiguration Exploitation<br>

### Content Security Policy Bypasses
Content Security Policy (CSP) Bypass<br>
CSP - Inline Script Execution<br>
CSP - Unsafe-eval Bypass<br>
CSP - nonce Bypass<br>
CSP - hash Bypass<br>
COOP/COEP/CORP Misconfiguration (cross-origin isolation issues)<br>
Permissions-Policy Misconfiguration (overly permissive powerful features)<br>

### Framing & Header Bypasses
X-Frame-Options Bypass<br>
X-Frame-Options - Clickjacking via Frame<br>
X-Content-Type-Options Bypass<br>
Strict-Transport-Security (HSTS) Downgrade<br>

### Cookie Security Bypasses
HttpOnly Cookie Bypass<br>
Secure Flag Bypass (HTTP over HTTPS downgrade)<br>
SameSite Bypass<br>

### Advanced Browser Bypasses
Referrer-Policy Bypass<br>
Feature-Policy Bypass<br>
Document.domain Property Manipulation<br>
Service Worker Scope Abuse / Cache Poisoning (sw-controlled origin content)<br>

## Logic & State Issues

### Memory & Reference Issues
Use-After-Free in Application Logic<br>
Dangling Reference<br>
Circular Reference<br>

### Concurrency & Timing Issues
Time-of-Check-Time-of-Use (TOCTOU) in Authentication<br>
TOCTOU - State Verification<br>
Broken Reference Integrity<br>

### State Machine Issues
State Machine Bypass<br>
Invalid State Transition<br>
State Reversion<br>

### Transaction Issues
Transaction Atomicity Violation<br>
Partial Transaction Rollback<br>
Transaction Interleaving<br>

### Synchronization Issues
Insufficient Locking/Concurrency<br>
Missing Mutex<br>
Deadlock Vulnerability<br>

## Code Extraction & Reverse Engineering

### Code Decompilation & Extraction
Decompilation Attacks<br>
Java Decompilation (cfr, procyon, fernflower)<br>
Python Decompilation (uncompyle6, decompyle3)<br>
.NET Decompilation (dnSpy, ILSpy)<br>

### Obfuscation & Protection Bypass
Obfuscation Bypass<br>
JavaScript Deobfuscation<br>
String Deobfuscation<br>
Control Flow Deobfuscation<br>

### Secret Extraction
Hardcoded Secrets in Binary<br>
API Keys in Binary<br>
Encryption Keys in Code<br>

### Debug Information Leakage
Source Map Exposure<br>
Debug Symbol Leakage<br>
Debug Information in Release Build<br>
String Table Analysis<br>

### Reverse Engineering Techniques
Binary Instrumentation<br>
Dynamic Code Analysis<br>
Memory Forensics<br>

## Insecure Deserialization - Language Specific

### Java Serialization
Java Serialization (Gadget Chain RCE)<br>
Java - commons-collections Gadget Chain<br>
Java - Spring Framework Gadget Chain<br>
Java - JNDI Injection via Serialization<br>

### Python Deserialization
Python Pickle RCE<br>
Python Pickle - __reduce__ Exploitation<br>
Python YAML Deserialization<br>

### Ruby Deserialization
Ruby Marshal Deserialization<br>
Ruby Marshal - Gadget Chains<br>

### Go & C# Deserialization
Go Serialization Issues<br>
C# BinaryFormatter RCE<br>
C# XML Deserialization<br>
C# DataSet Deserialization<br>

### PHP & Other Languages
PHP Serialization Exploitation<br>
PHP Object Injection<br>

## Server & Cloud Misconfiguration

### Administrative Access Issues
Unprotected Admin Panels<br>
Admin Panel Path Enumeration<br>
Admin Interface Default Port<br>

### Credential Management
Default/Weak Credentials on Services<br>
Default Credentials - MySQL<br>
Default Credentials - PostgreSQL<br>
Default Credentials - Redis<br>
Default Credentials - Memcached<br>
Default Credentials - MongoDB<br>
Default Credentials - RabbitMQ<br>

### Backup & Version Control Exposure
Backup Files Exposed (.bak, .old, .tar.gz)<br>
Incremental Backup Exposure<br>
Source Code Exposed (.git, .svn, .hg)<br>
Git Repository Exposure<br>

### Configuration File Exposure
Configuration Files Readable (web.config, .env)<br>
Application Config Exposure<br>
Database Config Exposure<br>
API Config Exposure<br>

### Cloud Storage Misconfiguration
Moved to [Cloud.md](Cloud.md)<br>

### Container & Orchestration Exposure
Moved to [OS_specific.md](OS_specific.md)<br>

## Advanced SSRF Attacks

### SSRF via File Processing
SSRF via PDF Generation<br>
SSRF via PDF - HTML-to-PDF Engine Fetch (wkhtmltopdf, headless chrome)<br>
SSRF via PDF - Remote Asset Fetch (images/fonts/stylesheets)<br>
SSRF via Image Processing (ImageMagick)<br>
SSRF via ImageMagick - Remote URL Fetch (delegates/handlers)<br>
SSRF via ImageMagick - Ghostscript/Delegate Fetch<br>
SSRF via Video Processing<br>
SSRF via Video - ffmpeg Remote Fetch (subtitles, playlists, concat)<br>
SSRF via Document Conversion<br>
SSRF via Document - Remote Template/Asset Fetch<br>

### SSRF via Service Integration
SSRF via Webhook Systems<br>
SSRF via Webhook - URL Validation Bypass (redirects)<br>
SSRF via Notification Services<br>
SSRF via Notification - Template/Link Preview Fetch<br>
SSRF via Email Services (tracking pixels, link preview)<br>
SSRF via GraphQL<br>
SSRF via GraphQL - Resolver URL Fetchers<br>

### Advanced SSRF Exploitation
SSRF - Cloud Metadata Service (AWS/GCP/Azure)<br>
SSRF - Port Scanning Internal Network<br>
SSRF - Gopher Protocol Abuse<br>
SSRF - Dict Protocol Abuse<br>
SSRF - FastCGI Exploitation<br>
SSRF - URL Parser Confusion (userinfo, @, #, mixed schemes)<br>

## Encoding & Normalization Bypasses
Unicode Normalization Bypass<br>
Overlong UTF-8 Encoding<br>
Punycode/IDN Homograph Attack<br>
Case Mapping Bypass<br>
Byte Order Mark (BOM) Injection<br>

## Insecure Randomness
Weak RNG Seeds<br>
Predictable Nonce Generation<br>
Weak Token Generation<br>
Insufficient Entropy in Randomness<br>
PRNG State Prediction/Recovery<br>

## Regex & Pattern Matching Issues
ReDoS (Regular Expression Denial of Service)<br>
Regex Bypass - Wildcard Abuse<br>
Regex Bypass - Anchoring Issues<br>
Regex Bypass - Character Class Errors<br>

## Advanced Authorization Attacks
Attribute-Based Access Control (ABAC) Bypass<br>
Role-Based Access Control (RBAC) Bypass<br>
Capability-Based Access Control Bypass<br>
Delegation Abuse<br>
Impersonation Attack<br>
Permission Escalation via Role Confusion<br>

## HTTP Desynchronization Attacks
HTTP Request Desynchronization (HTTP/2 Smuggling)<br>
HTTP/2 Rapid Reset Attack<br>
Content-Length Desync<br>
Transfer-Encoding Desync<br>

## Advanced CORS & CSRF
CORS + CSRF Combination Attack<br>
Same-Origin Policy Bypass via CORS<br>
SOP Bypass via Flash/Silverlight (legacy)<br>
CSRF via DNS Rebinding<br>
CSRF Token Prediction<br>

## Out-of-Band Data Exfiltration
DNS Exfiltration<br>
DNS Tunneling<br>
ICMP Exfiltration<br>
Out-of-Band Data Leakage<br>
Error-based Data Exfiltration (via error messages)<br>

## Non-Web Checklists
OS/container/host vulnerabilities: see [OS_specific.md](OS_specific.md)<br>
AD/Kerberos/protocol vulnerabilities: see [Network.md](Network.md)<br>
Cloud provider vulnerabilities: see [Cloud.md](Cloud.md)<br>



