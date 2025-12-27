# OS-specific Vulnerabilities (Linux / Windows / Containers)

This file contains OS, container, and host-level vulnerability variants.

- Web + API vulnerabilities (including GraphQL) live in [README.md](README.md).
- Network/Directory Services (AD/Kerberos/protocols) live in [Network.md](Network.md).
- Cloud provider-specific issues (AWS/Azure/GCP) live in [Cloud.md](Cloud.md).

## Windows

### CTF Playbook - Windows Quick Checks
- Enum: `whoami /all`, `systeminfo`, `wmic qfe list`, `net localgroup administrators`<br>
- Privs: `whoami /priv` (look for SeImpersonate/SeAssignPrimaryToken/SeDebug)<br>
- Services: `sc query`, `sc qc <service>`; check writable paths/dirs via `icacls`<br>
- Autoruns: registry run keys/startup folders writable?<br>
- Credentials: LSASS dump feasibility, saved creds (`cmdkey /list`), RDP files<br>
- UAC: test bypass preconditions; AlwaysInstallElevated registry keys<br>
- Lateral: WinRM/WMI enabled, firewall rules; scheduled task creation rights

### Windows Credential & Secret Exposure
Credentials in Windows Registry (SAM/SYSTEM hives)<br>
LSA Secrets Exposure<br>
DPAPI Secret Exposure<br>
Credential Manager Dump<br>
Unattend.xml / Sysprep Secrets<br>
Web.config / appsettings.json Secrets on Windows Hosts<br>
Hard-coded Credentials in Windows Services<br>
LSASS Memory Dump / Credential Theft (incl. WDigest or plaintext where enabled)<br>
NTDS.dit / ntdsutil / VSS Snapshot Exposure (domain creds at rest)<br>
Saved RDP Credentials / RDCMan / .rdp Files Credential Exposure<br>
PowerShell History/Transcripts (PSReadLine / transcription) Sensitive Data Exposure<br>
Windows Error Reporting (WER) / Crash Dump Sensitive Data Exposure<br>

### Windows Privilege Escalation (Local)
Unquoted Service Path<br>
Weak Service Permissions (service binary writable)<br>
Weak Service Configuration Permissions<br>
AlwaysInstallElevated Misconfiguration<br>
UAC Bypass Variants<br>
Token Impersonation / Token Kidnapping<br>
SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege Abuse<br>
DLL Search Order Hijacking<br>
PATH/DLL Planting in Writable Directories<br>
COM Hijacking<br>
LSASS Memory Dump / Credential Theft (incl. WDigest or plaintext where enabled)<br>
NTDS.dit / ntdsutil / VSS Snapshot Exposure (domain creds at rest)<br>
Saved RDP Credentials / RDCMan / .rdp Files Credential Exposure<br>
PowerShell History/Transcripts (PSReadLine / transcription) Sensitive Data Exposure<br>
Windows Error Reporting (WER) / Crash Dump Sensitive Data Exposure<br>
Scheduled Task Misconfiguration (writable action/trigger)<br>
Startup Folder / Run Keys Persistence (misuse for escalation)<br>
Insecure ACLs on System Binaries/Directories<br>
Driver/Kernel Attack Surface (outdated drivers)<br>
SeDebugPrivilege Abuse<br>
Credential Guard / LSA Protection Misconfiguration<br>
SeBackupPrivilege / SeRestorePrivilege Abuse (read/write protected files)<br>
SeTakeOwnershipPrivilege Abuse (take ownership + ACL rewrite)<br>
SeLoadDriverPrivilege Abuse (load vulnerable/signed drivers where possible)<br>
Writable Registry Autoruns / Service Parameters (ImagePath/ServiceDll/Parameters) Misconfiguration<br>

### Windows Lateral Execution Primitives (Host-side)
WMI Remote Execution Misconfiguration<br>
WinRM Misconfiguration<br>
Remote Service Creation Misconfiguration<br>
RDP Misconfiguration / Weak NLA Settings<br>
DCOM Remote Activation Misconfiguration<br>
Scheduled Tasks Remote Creation Misconfiguration (schtasks abuse surface)<br>

### Windows LOLBAS & Living-off-the-Land
certutil (download/decode)<br>
mshta (remote HTA execute)<br>
regsvr32 / scrobj (COM scriptlet execute)<br>
rundll32 (DLL exports execute)<br>
InstallUtil / msbuild (scripted install/build abuse)<br>
PowerShell download cradle (with AMSI evasion preconditions)<br>
bitsadmin / BITS jobs for stealthy transfer/exec<br>

### Windows Persistence & Defense Evasion
WMI Event Subscription Persistence<br>
Services / Scheduled Tasks Persistence (common autorun primitives)<br>
Registry Run Keys / Startup Folder Persistence<br>
Log Tampering / Event Log Clearing (detection evasion)<br>
AV/EDR Misconfiguration / Tamper Protection Disabled<br>

## Linux

### CTF Playbook - Linux Quick Checks
Enum & privesc probes:<br>
- Basics: `id`, `uname -a`, `env`, `sudo -l`<br>
- SUID scan: `find / -perm -4000 -type f 2>/dev/null`<br>
- Capabilities: `getcap -r / 2>/dev/null`<br>
- Cron/systemd: `ls -la /etc/cron*`, `systemctl list-timers --all`, `systemctl list-units --type=service`<br>
- PATH hijack candidates: `echo $PATH`, check writable dirs<br>
- NFS: check `/etc/exports` for `no_root_squash` and writable mounts<br>
- Docker: `id` shows `docker` group; try `docker run --privileged -v /:/host -it alpine sh`<br>
- Kernel: record version for known exploits; check loaded modules<br>

### Linux Privilege Escalation (Misconfiguration / Local)
SUID/SGID Binary Abuse<br>
Misconfigured sudoers (NOPASSWD / wildcards)<br>
Linux Capabilities Misconfiguration (cap_setuid, cap_dac_read_search)<br>
Writable /etc/passwd / /etc/shadow / /etc/sudoers<br>
Cron Job Misconfiguration (writable scripts)<br>
Systemd Service Unit Misconfiguration (writable ExecStart)<br>
Systemd Timer Misconfiguration (writable timer/service pairs)<br>
PATH Hijacking<br>
LD_PRELOAD / LD_LIBRARY_PATH Injection<br>
World-writable Directories in Execution Path<br>
NFS no_root_squash Misconfiguration<br>
Kernel Exploit Surface (outdated kernel)<br>
Container Runtime Group Membership (e.g., docker group)<br>
Sudo - Environment Variable Abuse (env_keep/env_reset misconfig)<br>
SUID Misconfiguration on Interpreters (python/perl/ruby) where applicable<br>

### Linux Privilege Escalation (Kernel / Drivers)
eBPF Attack Surface (unsafe sysctls / unprivileged bpf enabled where applicable)<br>
Vulnerable Kernel Modules / DKMS Artifacts<br>

### Linux Persistence & Defense Evasion
systemd Persistence (user/system units)<br>
Cron Persistence<br>
SSH Authorized Keys Persistence<br>
Log Tampering / Auditd Disabled / Journald Forwarding Disabled<br>

### Linux Data Exposure
Systemd Timer Misconfiguration (writable timer/service pairs)<br>
Secrets in `/proc/<pid>/environ`<br>
Secrets in Shell History (.bash_history, .zsh_history)<br>
Writable /etc/ld.so.preload Abuse<br>
Insecure File Permissions on Configs/Keys<br>
Core Dump Sensitive Data Exposure<br>
World-Readable Service Configs (systemd unit env files, app configs)<br>
Secrets in Journald/System Logs (journalctl, /var/log) and Debug Dumps<br>
Developer Credentials on Hosts (~/.aws, gcloud ADC, kubeconfig, Docker config.json)<br>

### Linux Credential Access & Artifacts
SSH Agent / SSH Keys Exposure (agent forwarding, key perms)<br>
Browser Credential Stores / Password Managers on Jump Hosts<br>
Kubernetes Credentials on Hosts (kubeconfig, client certs, tokens)<br>

## macOS

### CTF Playbook - macOS Quick Checks
- Enum: `id`, `sw_vers`, `system_profiler SPSoftwareDataType`, SIP status<br>
- Persistence: check `~/Library/LaunchAgents` and `/Library/LaunchAgents`/`LaunchDaemons` for writable plists<br>
- TCC DB: inspect `~/Library/Application Support/com.apple.TCC/TCC.db` for app permissions<br>
- DYLD/library injection surfaces if applicable; environment variables<br>
- Keychain: access controls; potential secrets via `security find-generic-password` (with permissions)

### CTF Playbook - macOS Quick Checks
Enum & privesc probes:<br>
- Basics: `id`, `uname -a`, `env`, `sudo -l`<br>
- Launchd: check writable `~/Library/LaunchAgents` and `/Library/LaunchDaemons` plists<br>
- TCC DB: inspect `~/Library/Application Support/com.apple.TCC/TCC.db` for app permissions<br>
- DYLD/library injection surfaces where applicable<br>
- SIP constraints noted (limits on system paths and kexts)<br>

### macOS Credential & Secret Exposure
Keychain Access Control Misconfiguration / Over-broad ACLs<br>
TCC (Transparency, Consent, and Control) Database Abuse / Permission Prompts Bypass Surface<br>
Secrets in plist Files / LaunchAgents Configs<br>

### macOS Privilege Escalation (Local)
Sudoers Misconfiguration / PATH Hijacking<br>
LaunchDaemons/LaunchAgents Misconfiguration (writable plists / scripts)<br>
Unsafe DYLD_* / Library Injection Surfaces (where applicable)<br>

### macOS Persistence & Defense Evasion
LaunchAgents / LaunchDaemons Persistence<br>
Login Items Persistence<br>
Log/Telemetry Tampering (detection gaps)<br>

## Container & Infrastructure Vulns

Sudoedit / Editor Escape Abuse (sudoedit + EDITOR/VISUAL quirks)<br>
### CTF Playbook - Containers/K8s Quick Checks
- Docker escape probes: privileged/run with host mount `-v /:/host`, socket mount `/var/run/docker.sock`<br>
- Inspect container capabilities/seccomp/AppArmor on compromised pods/containers<br>
- Kube tokens: `/var/run/secrets/kubernetes.io/serviceaccount`; RBAC: `kubectl auth can-i --list`<br>
- Kubelet unauth endpoints (legacy): `http://<kubelet>:10255/pods`<br>
- Ingress/Service exposures: NodePort/LoadBalancer reachability from attacker vantage<br>
### Docker Container Escape
Docker Container Escape - Privileged Mode<br>
Docker Container Escape - Unrestricted Capabilities<br>
Docker Container Escape - CAP_SYS_ADMIN<br>
Docker Container Escape - CAP_SYS_PTRACE<br>
Docker Container Escape - CAP_NET_ADMIN<br>
Docker Container Escape - Volume Mount Escape<br>
Secrets in Journald/System Logs (journalctl, /var/log) and Debug Dumps<br>
Developer Credentials on Hosts (~/.aws, gcloud ADC, kubeconfig, Docker config.json)<br>
Docker Container Escape - Host Volume Access<br>
Docker Container Escape - Socket Mount Escape (/var/run/docker.sock)<br>
Docker Container Escape - Cgroup Escape<br>
Docker Container Escape - Namespace Escape<br>
Docker Container Escape - Runc Vulnerability (CVE-2019-5736)<br>
Docker Container Escape - Shiftfs Vulnerability<br>
Docker Container Escape - Overlay2 Exploitation<br>
Docker Container Escape - Device File Abuse<br>
Docker Container Escape - /proc Filesystem Abuse<br>
Docker Container Escape - Seccomp Bypass<br>
Docker Container Escape - AppArmor/SELinux Bypass<br>
Docker Container Escape - Shared PID Namespace<br>
Docker Container Escape - Shared Network Namespace<br>
Docker Container Escape - Shared IPC Namespace<br>
Docker Container Escape - Kernel Module Loading<br>
Docker Container Escape - FUSE (Filesystem in Userspace) Abuse<br>
Docker Container Escape - Cgroup v1 release_agent / notify_on_release Abuse<br>

### Kubernetes API Abuse/Misconfiguration
Kubernetes - Default Service Account Token Exposure<br>
Kubernetes - RBAC Misconfiguration<br>
Kubernetes - ClusterRole Binding Abuse<br>
Kubernetes - RoleBinding Privilege Escalation<br>
Kubernetes - Service Account Token Theft<br>
Kubernetes - automountServiceAccountToken Misconfiguration (unneeded token exposure)<br>
Kubernetes - BoundServiceAccountTokenVolume Disabled / Long-lived Tokens<br>
Kubernetes - Insecure API Server Exposure<br>
Kubernetes - Anonymous Access Enabled<br>
Kubernetes - Metrics Server Exposure<br>
Kubernetes - Dashboard Exposure<br>
Kubernetes - Kubelet API Abuse<br>
Kubernetes - Kubelet Anonymous Access<br>
Kubernetes - Kubelet Insecure Port<br>
Kubernetes - Etcd Direct Access<br>
Kubernetes - Etcd Backup Exposure<br>
Kubernetes - API Server Audit Log Exposure<br>
Kubernetes - Secret Exposure in Logs<br>
Kubernetes - Secret in Environment Variables<br>
Kubernetes - ConfigMap Secret Confusion<br>
Kubernetes - Pod Privilege Escalation<br>
Kubernetes - Secret Encryption at Rest Disabled / Misconfigured KMS Provider<br>
Kubernetes - Pod Security Policy Bypass<br>
Kubernetes - Network Policy Misconfiguration<br>
Kubernetes - Ingress Controller Abuse<br>
Kubernetes - Service Type LoadBalancer Exposure<br>
Kubernetes - NodePort Service Abuse<br>
Kubernetes - ClusterIP Service Exposure (Internal)<br>
Kubernetes - CORS Misconfiguration in Services<br>
Kubernetes - Webhook Authentication Bypass<br>
Kubernetes - Admission Controller Bypass<br>
Kubernetes - RBAC Verb Abuse (*)<br>
Kubernetes - Namespace Escape<br>
Kubernetes - Container Runtime Socket Abuse<br>
Kubernetes - DaemonSet Privilege Escalation<br>
Kubernetes - StatefulSet Abuse<br>
Kubernetes - CronJob Command Injection<br>
Kubernetes - Init Container Abuse<br>
Kubernetes - Sidecar Container Exploitation<br>
Kubernetes - Volume Mount Escape<br>
Kubernetes - PersistentVolume Access<br>
Kubernetes - PVC Cross-Namespace Access<br>
Kubernetes - Storage Class Abuse<br>

### Container Image Registry Bypass
Container Registry - Unauthenticated Image Pull<br>
Container Registry - Weak Authentication<br>
Container Registry - Default Credentials<br>
Container Registry - Anonymous Push Enabled<br>
Container Registry - Image Deletion Allowed<br>
Container Registry - Image Tag Overwrite<br>
Container Registry - Manifest Manipulation<br>
Container Registry - Blob Manipulation<br>
Container Registry - CORS Misconfiguration<br>
Container Registry - API Key Exposure<br>
Container Registry - OAuth Token Leakage<br>
Container Registry - Bearer Token Exposure<br>
Container Registry - Docker Hub Token Reuse<br>
Container Registry - Private Image Public Access<br>
Container Registry - Image Layer Access Control Bypass<br>
Container Registry - Cross-Tenant Access<br>
Container Registry - Registry Credential in Image<br>
Container Registry - Secrets in Image Layers<br>
Container Registry - Vulnerable Image Detection Bypass<br>
Container Registry - Image Signing Bypass<br>
Container Registry - Docker Content Trust Bypass<br>
Container Registry - Registry Webhook Abuse<br>
Container Registry - Push Event Manipulation<br>
Container Registry - API Rate Limiting Bypass<br>
Docker Hub - Free Tier Account Takeover<br>
Docker Hub - Organization Access Abuse<br>

### Supply Chain via Malicious Dependencies
Dependency Confusion Attack<br>
Dependency Confusion - Private Package Registry<br>
Dependency Confusion - PyPI Attack<br>
Dependency Confusion - NPM Attack<br>
Dependency Confusion - RubyGems Attack<br>
Dependency Confusion - Maven Central Attack<br>
Dependency Confusion - NuGet Attack<br>
Package Hijacking<br>
Package Typosquatting<br>
Package Name Squatting<br>
Malicious Package in Public Registry<br>
Compromised Package Account<br>
Package Maintainer Account Takeover<br>
Build Script Injection (setup.py, package.json)<br>
Build Script Execution During Install<br>
Post-Install Script Execution<br>
Pre-build Hook Injection<br>
Malicious Transitive Dependency<br>
Dependency Downgrade Attack<br>
Version Pinning Bypass<br>
Lock File Tampering<br>
Semantic Versioning Abuse (^, ~)<br>
Package Repository Man-in-the-Middle<br>
Insecure Package Download (HTTP)<br>
Package Checksum Bypass<br>
GPG Signature Verification Bypass<br>
Package Signing Key Compromise<br>
Mirror/Proxy Poisoning<br>
CDN Cache Poisoning (Package)<br>

### Environment Variable Exposure
Secrets in Environment Variables<br>
Environment Variable Exposure in Logs<br>
Environment Variable Exposure in Error Messages<br>
Environment Variable Exposure in Process List (ps aux)<br>
Environment Variable Exposure in /proc/<pid>/environ<br>
Environment Variable Exposure in Container Image<br>
Environment Variable Exposure in Dockerfile<br>
Environment Variable Exposure in Docker Compose<br>
Environment Variable Exposure in Kubernetes YAML<br>
Environment Variable Exposure in Helm Charts<br>
Environment Variable Exposure in CI/CD Logs<br>
Environment Variable Exposure in Build Artifacts<br>
Environment Variable Exposure in Debug Endpoints<br>
Environment Variable Exposure in Spring Boot Actuator<br>
Environment Variable Exposure in Flask Debug Mode<br>
Environment Variable Exposure in Django Debug Mode<br>
Environment Variable Exposure in Application Configuration<br>
Environment Variable Exposure in Docker Inspect<br>
Environment Variable Exposure in Kubernetes Describe<br>
Environment Variable Exposure in Process Environment Tools<br>
Hard-coded Environment Variable Values<br>
Unencrypted Secrets in Environment<br>
Long-lived Secrets in Environment<br>

### Container Networking Issues
Container DNS Poisoning<br>
Container Network Policy Bypass<br>
Container Bridge Network Sniffing<br>
Container Host Network Escape<br>
Container Overlay Network Encryption Bypass<br>
Container Network Interface (CNI) Abuse<br>
Container Service Mesh Misconfiguration (Istio, Linkerd)<br>
Container Traffic Interception<br>
Container Network Namespace Sharing<br>
Host Network Namespace Access<br>
Container iptables Manipulation<br>
Container Network MTU Abuse<br>

### Container Runtime Issues
Containerd Security Issues<br>
CRI-O Runtime Abuse<br>
Podman Container Escape<br>
runC Vulnerability Exploitation<br>
Container Runtime Privilege Escalation<br>
Runtime Socket Access (containerd.sock)<br>
Runtime Process Injection<br>

### Container Image Security
Vulnerable Base Image<br>
Outdated Dependency in Image<br>
Malware in Image<br>
Backdoor in Image<br>
Image Layer Analysis<br>
Image Metadata Exposure (Labels)<br>
Image Build Context Leak<br>
Multistage Build Secrets Leak<br>
Image Cache Poisoning<br>

### Kubernetes Secrets Management
Kubernetes Secret Base64 Encoding (not encryption)<br>
Kubernetes Secret in etcd Unencrypted<br>
Kubernetes Secret Backup Exposure<br>
Kubernetes Secret Backup Not Encrypted<br>
Kubernetes Secret RBAC Misconfiguration<br>
Kubernetes Secret Namespace Escape<br>
Kubernetes Secret in Application Logs<br>
Kubernetes Secret Exposure via API<br>
Kubernetes Secret Exposure via kubectl<br>
Kubernetes External Secrets Misconfiguration<br>

### Container Resource Limits Abuse
Container Memory Limit Bypass<br>
Container CPU Limit Bypass<br>
Container Disk Quota Bypass<br>
Container Network Bandwidth Bypass<br>
Container PID Limit Bypass<br>
Resource Limit Exhaustion Attack<br>

### Container Logging Issues
Container Logs Exposure<br>
Container Logs Not Encrypted<br>
Container Logs Retention Issues<br>
Sensitive Data in Container Logs<br>
Log Aggregation Service Misconfiguration<br>
Splunk/ELK Stack Credential Exposure<br>

### Orchestration Platform Issues
Docker Swarm Security Issues<br>
Docker Swarm Token Exposure<br>
Swarm Manager Node Compromise<br>
Swarm Service Credential Exposure<br>
OpenShift Misconfiguration<br>
OpenShift SCC (Security Context Constraint) Bypass<br>
CloudNative Platform Misconfiguration<br>

### Container Host Security
Host Kernel Vulnerability (affecting containers)<br>
Host System Call Filtering Bypass<br>
Host Filesystem Access from Container<br>
Host Device Access from Container<br>
Host PCI Device Access<br>
Host USB Device Access<br>
Host GPU Access Misconfiguration<br>
Host Module Loading from Container<br>
