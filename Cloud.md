# Cloud Vulnerabilities (AWS / Azure / GCP)

This file contains cloud provider-specific misconfigurations and vulnerability variants.

- Web + API vulnerabilities (including GraphQL) live in [README.md](README.md).
- OS/container/host vulnerabilities live in [OS_specific.md](OS_specific.md).
- Network/Directory Services (AD/Kerberos/protocols) live in [Network.md](Network.md).

## Cross-Cloud / General
### CTF Playbook - Cloud Quick Checks
Identity & metadata fast probes:<br>
- AWS identity: `aws sts get-caller-identity`<br>
- AWS metadata: `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/`<br>
- Azure metadata: `curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"`<br>
- GCP metadata: `curl -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/?recursive=true&alt=json"`<br>
- Public storage: list S3/GCS/Blob containers; check public ACL/policies and signed URL TTLs<br>
- KMS/Secrets: review resource policies for cross-account principals; test decrypt/access paths<br>
- Serverless: enumerate triggers and HTTP endpoints; test unauth invocations<br>
Cloud IAM Misconfiguration (over-privileged roles)<br>
Long-lived Access Keys<br>
Public Object Storage Buckets<br>
Secret Leakage in User-Data / Instance Metadata<br>
SSRF to Cloud Metadata<br>
Misconfigured CI/CD Cloud Credentials<br>
Overly Permissive Default Network Rules / Security Groups<br>
Key Management Misconfiguration (KMS/Key Vault/Cloud KMS overly permissive)<br>
Cloud Audit Logging Disabled (CloudTrail/Activity Log/Audit Logs)<br>
Weak Resource Policies (cross-account/project subscription access)<br>
Org/Account-Level Guardrails Disabled (AWS SCP / Azure Policy / GCP Org Policy gaps)<br>
Federated Identity / OIDC Trust Too Permissive (CI/CD workload identity confusion)<br>
Terraform State / IaC Artifact Exposure (remote backend buckets, plan logs, outputs)<br>

### Identity & Federation (Cross-Cloud)
Federation Token Audience/Issuer Confusion (accepting tokens for wrong audience/issuer)<br>
Overly Broad Workload Identity Federation (repo/branch/env not pinned)<br>
Missing Session Constraints (no max session, no device/location conditions)<br>
Over-permissive AssumeRole/Impersonation Paths (chained trust abuse)<br>

### Guardrails / Org Controls (Cross-Cloud)
Delegated Admin / Break-Glass Accounts Not Monitored<br>
Policy Inheritance Confusion (org -> account/subscription/project overrides)<br>
Resource Policy Wildcards (* principals / broad conditions) in Multi-Account Setups<br>

### Logging / Monitoring / Detection Gaps (Cross-Cloud)
Short Log Retention / No Central Export (hard to investigate)<br>
Alerting Not Wired (no detections for IAM changes / key creation / policy edits)<br>
Sensitive Data in Logs (tokens/headers in function logs, app logs, audit logs)<br>

### CI/CD + Supply Chain in Cloud (Cross-Cloud)
Build Identity Confusion (PR builds or forks can reach privileged cloud identities)<br>
Secrets Injection via CI Variables / OIDC Token Requests from Untrusted Jobs<br>
Artifact/Package Registry Trust Issues (publishing to prod feed from untrusted pipeline)<br>

### Data Plane Exposure (Cross-Cloud)
Public Network Access Enabled on Managed Services (should be private endpoints)<br>
Missing Egress Controls (data exfil to attacker-controlled endpoints)<br>

### Network / Private Connectivity (Cross-Cloud)
Private Endpoint / Private Link Misconfiguration (unexpected exposure or bypass)<br>
DNS for Private Endpoints Misconfigured (split-horizon failures / name leaks)<br>
Overly Broad Egress (0.0.0.0/0) from Private Networks / NAT Gateways<br>
Misconfigured Peering / Transit (VPC/VNet peering routes too broad)<br>

### Secrets Management (Cross-Cloud)
Secrets Stored in Plaintext (env vars, config, object storage, repos)<br>
Secret Rotation Disabled / Long-Lived Credentials Used for Automation<br>
Cross-Environment Secrets Reuse (dev -> prod pivot)<br>

### Serverless / Eventing (Cross-Cloud)
Event Trigger Overreach (function triggers on attacker-controlled events)<br>
Public Webhook / Function Endpoint Exposure (auth missing at edge)<br>
Queue/Topic Policy Too Permissive (publish/subscribe from anywhere)<br>

### Containers / Managed Kubernetes (Cross-Cloud)
Managed K8s Cluster Public API / Weak Auth (EKS/AKS/GKE)<br>
Node Pool Credential / Metadata Access (cloud creds from node)<br>
Container Registry Pull Secrets / Build Service Accounts Over-privileged<br>

## AWS

### Organizations / Guardrails
AWS Organizations - SCP Not Enforced / Missing Guardrails<br>
AWS Organizations - Delegated Admin Abuse / Unreviewed Delegation<br>

### Logging / Monitoring
CloudTrail Disabled / Partial (not all regions, not all events)<br>
CloudTrail Log Bucket Misconfiguration (public, weak policy, no integrity controls)<br>
AWS Config Disabled / Not Recording Key Resource Types<br>
GuardDuty Disabled / Findings Ignored<br>
CloudTrail Log File Validation Disabled (integrity chain not enforced)<br>

### IAM
Overly Permissive IAM Policy (*:*)<br>
Privilege Escalation via IAM (PassRole, CreatePolicyVersion, AttachUserPolicy)<br>
AssumeRole Trust Policy Too Permissive<br>
AssumeRole ExternalId Missing / Confused Deputy Risk<br>
STS Token Abuse / Role Chaining<br>
IAM - Weak Condition Keys / Missing MFA Conditions for Privileged Actions<br>
IAM OIDC Provider Trust Too Broad (IRSA misuse; audience/repo not pinned)<br>

### STS / Temporary Credentials
AssumeRole with Wildcard Principal + No ExternalId Constraints<br>
Session Policy Confusion (caller can broaden effective permissions)<br>

### S3
S3 Bucket Public Read<br>
S3 Bucket Public Write<br>
S3 Bucket List Enabled<br>
Service Account Key Creation Allowed (org policy missing) / long-lived keys in CI/CD<br>
S3 Block Public Access Disabled / Not Enforced<br>
S3 ACL Misconfiguration (public ACLs)<br>
Metadata Recursive Fetch & Full Enumeration (?recursive=true&alt=json) exposing tokens/config<br>
S3 Bucket Policy Confusion (cross-account)<br>
S3 Static Website Misconfiguration<br>
S3 Pre-Signed URL Abuse (overlong TTL / over-permissioned)<br>
Federation Audience/Issuer Confusion (accept tokens from unintended identity providers)<br>
S3 - Server-Side Encryption Disabled / Weak KMS Policy<br>

### KMS / Secrets Manager / SSM
KMS Key Policy Too Permissive (cross-account decrypt/encrypt)<br>
KMS Grants Abuse (unexpected decrypt path)<br>
Secrets Manager - Resource Policy Too Permissive<br>
SSM Parameter Store - SecureString Not Used / KMS Misconfig<br>

### CloudFront / API Gateway / Edge
CloudFront Origin Exposed Directly (bypass WAF/auth at edge)<br>
CloudFront Signed URL/Cookie Misconfiguration<br>
API Gateway - Missing Auth (no authorizer / IAM auth not enforced)<br>
API Gateway - CORS Misconfiguration<br>

### Route 53 / DNS
Route53 - Subdomain Takeover via Dangling Records<br>
Route53 - Overly Permissive ChangeResourceRecordSets Permissions<br>

### EC2 / Metadata
IMDSv1 Enabled<br>
IMDSv2 Not Required (tokenless metadata access possible via SSRF chains)<br>
IMDS Hop Limit Misconfig<br>
Metadata Credential Theft (via SSRF)<br>
User Data Exposure<br>

### VPC / Network
Security Groups Overly Broad (0.0.0.0/0 to admin ports)<br>
Public S3/RDS via Missing VPC Endpoints / PrivateLink Controls<br>
VPC Endpoint Policy Too Permissive (data exfil via endpoints)<br>

### Lambda
Lambda Environment Variable Secrets<br>
Lambda Permission Overreach<br>
Lambda Function URL Public Exposure (if used)<br>
Lambda Layer Supply Chain Risk<br>

### Eventing (SQS/SNS/EventBridge)
SQS Queue Policy Too Permissive (send/receive from any principal)<br>
SNS Topic Policy Too Permissive (publish from any principal)<br>
EventBridge Rule Target Abuse (trigger privileged targets)<br>

### ECR
ECR Repository Public Access<br>
ECR Image Tag Overwrite<br>
ECR Credential Leakage<br>
ECR Image Scanning Disabled / Findings Ignored<br>

### ECS / EKS
ECS Task Role Over-privileged<br>
ECS Task Metadata Endpoint Exposure<br>
EKS Public API Endpoint Enabled / Missing CIDR Restrictions<br>
EKS aws-auth ConfigMap Misconfiguration (RBAC mapping abuse)<br>
EKS IRSA Misconfiguration (service accounts can assume privileged roles via broad trust)<br>
EKS Node IAM Role Misuse (pods access node role via metadata / credential exposure)

### RDS
RDS Publicly Accessible<br>
Weak Security Group Rules (0.0.0.0/0)<br>
RDS Snapshot Exposure<br>
RDS Encryption at Rest Disabled / Weak KMS Policy<br>

## Azure

### Subscription / Management Plane
Azure Policy Not Assigned / Not Enforced at Management Group<br>
Resource Locks Missing on Critical Resources<br>
Azure RBAC Role Assignments Too Broad (Owner/Contributor sprawl)<br>
Privileged Identity Management (PIM) Not Used / No Approval/Justification<br>

### Azure AD / Entra ID
Overly Permissive App Registration<br>
Consent Phishing / Overbroad OAuth Scopes<br>
Privileged Role Assignment Misconfiguration<br>
Legacy Auth Enabled / Conditional Access Gaps<br>
Entra ID - Guest User Oversharing / External Collaboration Misconfiguration<br>
App Registration - Implicit Flow Enabled (oauth2AllowImplicitFlow) / token leakage surfaces<br>
OIDC App - Weak Redirect URI Controls / Multi-tenant confusion (common endpoints)<br>
Graph API Pivot (Directory.Read.All -> privilege discovery/escalation paths)

### Conditional Access / Auth Controls
MFA Not Required for Privileged Roles<br>
Device/Location Conditions Missing (token replay and ATO easier)<br>
Token Lifetime / Continuous Access Evaluation Gaps<br>

### Storage Accounts / Blob
Blob Container Public Access<br>
SAS Token Over-permissioned / Long-lived<br>
Storage Account Firewall Misconfig<br>
Public Access Not Blocked at Account Level<br>

### App Service / Functions
App Service Publishing Credentials Exposure (deployment user/SCM)<br>
Kudu/SCM Endpoint Exposed<br>
Function App Public Exposure / Weak Auth on HTTP triggers<br>
Function Keys Leaked (in repos/logs)<br>

### Managed Identities / Metadata
Managed Identity Token Theft (via SSRF)<br>
Instance Metadata Service Exposure<br>
Managed Identity Audience Confusion (accepts tokens for unintended resource APIs)

### Networking
NSGs Overly Permissive (0.0.0.0/0 to admin ports)<br>
Private Endpoints Not Used / Public Network Access Enabled<br>
DNS Private Zones Misconfigured<br>

### Key Vault
Key Vault Access Policy Too Permissive<br>
Key Vault Secret Enumeration<br>
Key Vault Soft-Delete / Purge Protection Disabled<br>
Key Vault - RBAC vs Access Policy Confusion (unexpected access path)<br>

### Monitoring / Logs
Activity Logs Not Exported to Central Workspace<br>
Log Analytics Workspace Exposes Sensitive Data / Over-broad Reader Access<br>

### AKS
AKS Public API Enabled / Weak Authorized IP Ranges<br>
AKS Local Admin Accounts Enabled (cluster-admin bypass)<br>

## GCP

### Org / Guardrails
Org Policy Not Set (allows risky defaults like external IPs, SA key creation)<br>
VPC Service Controls Not Used for Sensitive Services<br>
Audit Logs Not Enabled for Admin/Data Access<br>

### IAM
Overly Permissive IAM Bindings<br>
Service Account Key Leakage<br>
Privilege Escalation via Service Account Impersonation<br>

### Workload Identity / Federation
Workload Identity Federation Misconfigured (accepts tokens from broad identities)<br>
Service Account Token Creator / Impersonation Too Broad<br>

### Cloud Storage
GCS Bucket Public Read<br>
GCS Bucket Public Write<br>
Signed URL Abuse / Overlong TTL<br>
Uniform Bucket-Level Access Disabled / ACL Confusion<br>

### Secret Manager / KMS
Secret Manager IAM Too Broad (viewer on secrets)<br>
Cloud KMS IAM Too Broad (encrypt/decrypt usable cross-project)<br>

### Metadata
GCP Metadata Token Theft (via SSRF)<br>

### Cloud Run / Functions
Cloud Run Service Public Invoker Enabled<br>
Cloud Functions HTTP Trigger Public Exposure<br>
Unauthenticated Invocations with Privileged Service Account<br>

### Artifact Registry
Artifact Registry Public Repository<br>
Image/Artifact Tag Overwrite<br>

### Pub/Sub
Pub/Sub Topic/Subscription IAM Too Permissive (publish/subscribe from anywhere)<br>
