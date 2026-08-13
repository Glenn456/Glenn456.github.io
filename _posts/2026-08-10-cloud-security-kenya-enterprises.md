---
title: "Kenyan Enterprises Moved to the Cloud. Their Security Model Did Not."
date: 2026-08-10 09:00:00 +0300
categories: [Cybersecurity, Kenya]
tags: [cloud security, kenya, aws, azure, misconfiguration, iam, data residency, detection, soc]
description: Cloud service providers are among the primary targets identified by Kenyan regulators. The dominant cause of cloud breaches is not provider vulnerability. It is customer misconfiguration, and the shared responsibility model is widely misunderstood.
image:
  path: https://images.unsplash.com/photo-1591696205602-2f950c417cb9?w=1200&h=500&fit=crop&q=80
  alt: Cloud infrastructure monitoring interface
---

## The Shared Responsibility Gap

The Communications Authority identified financial institutions, government bodies, and **cloud service providers** as the main targets of detected cyber threats, due to the sensitive data and live transactions they handle.

But the failure mode in cloud environments is usually not the provider. AWS, Azure, and Google Cloud have security programmes that most organisations cannot match. The failure is on the customer side of the shared responsibility line, and the most common reason is that organisations do not know where that line sits.

The provider secures the cloud. You secure what you put in it. Identity, configuration, data, network rules, and application security are yours.

---

## The Misconfigurations That Cause Breaches

### Publicly Accessible Storage

The most common and most damaging. An S3 bucket or Azure Blob container set to public because it was quicker during development, then never changed.

```bash
# Audit all S3 buckets for public access
aws s3api list-buckets --query 'Buckets[].Name' --output text | tr '\t' '\n' | while read b; do
  echo "=== $b ==="
  aws s3api get-public-access-block --bucket "$b" 2>/dev/null || echo "NO PUBLIC ACCESS BLOCK"
done
```

Enable account-level public access block. It overrides individual bucket settings and prevents the mistake from being possible.

### Over-Permissioned IAM

Roles and users granted broad permissions because scoping them correctly took time. `AdministratorAccess` attached to an application service account. Wildcard resource permissions in inline policies.

The blast radius of a compromised credential is defined entirely by what that credential can do.

Review with AWS IAM Access Analyzer or Azure Entra ID access reviews. Look specifically for:
- Policies with `"Action": "*"` or `"Resource": "*"`
- Service accounts with console access enabled
- Long-lived access keys, particularly any older than 90 days
- Users with permissions they have never actually used

### Exposed Management Interfaces

Security groups or network security groups allowing `0.0.0.0/0` on SSH, RDP, or database ports. Automated scanners find these within hours of exposure.

```bash
# Find security groups open to the world on sensitive ports
aws ec2 describe-security-groups --query \
  'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]' \
  --output table
```

### Absent or Ignored Logging

CloudTrail, Azure Activity Log, and GCP Audit Logs are the primary evidence source for any cloud incident. Common failures: logging not enabled in all regions, logs not centralised, logs not retained long enough, or logs enabled but never reviewed.

If an incident occurred three months ago and your retention is 90 days, you cannot investigate it.

### Unmanaged Secrets

API keys, database credentials, and tokens in environment variables, configuration files, container images, and source repositories. Use a secrets manager. Rotate on a schedule. Scan repositories for committed secrets.

---

## The Data Residency Question

This is a specifically Kenyan consideration that many organisations have not addressed.

The Data Protection Act restricts transfer of personal data outside Kenya without adequate safeguards, data subject consent, or another lawful basis.

Most major cloud providers do not have a region physically located in Kenya. If your workload runs in AWS `eu-west-1` or Azure `South Africa North`, personal data of Kenyan data subjects is being processed outside Kenya.

That is not automatically unlawful, but it does require a documented lawful basis and appropriate safeguards. Organisations should:

- Map which cloud regions process personal data
- Document the lawful basis for each cross-border transfer
- Review the provider's data processing terms and ensure they meet Kenyan requirements
- Consider whether sensitive categories should be processed in-country

Local data centre capacity in Kenya has grown, and for certain high-sensitivity workloads, in-country hosting is now a viable option that removes the question entirely.

---

## Detection in Cloud Environments

Cloud attacks have different signatures from on-premise attacks. These are the signals worth alerting on.

**Identity and access:**
- Root or global administrator account usage, which should be near-zero
- IAM policy modifications, particularly permission grants
- New access key creation
- Console login from an unusual geography or ASN
- MFA device changes
- Failed authentication followed by success from the same source

**Configuration:**
- Security group or NSG modification opening a port to `0.0.0.0/0`
- Storage bucket ACL or policy changes making data public
- Disabling of logging services, which is an immediate incident
- Modification of key management service key policies

**Data:**
- Unusual volume of storage read operations
- Data transfer to external accounts or unfamiliar regions
- Snapshot creation followed by sharing to an external account, a common exfiltration technique
- Database export operations

**Compute:**
- Instance launches in unused regions, frequently cryptomining
- Instances launched with unusually large instance types
- Changes to instance IAM role attachments

---

## A Practical Baseline

For a Kenyan enterprise starting from a low cloud security baseline, in priority order:

1. **Enable MFA on all human accounts.** Hardware keys for administrators.
2. **Enable and centralise logging** across all regions with retention of at least one year.
3. **Enable account-level public access block** on all object storage.
4. **Deploy a cloud security posture management tool.** Native options exist: AWS Security Hub, Azure Defender for Cloud, GCP Security Command Center. They will find your misconfigurations faster than manual review.
5. **Eliminate long-lived access keys** in favour of role assumption and workload identity federation.
6. **Implement infrastructure as code** with security review in the pipeline. Manual console changes are where misconfigurations originate.
7. **Map data residency** and document the lawful basis for cross-border processing.

---

## Key Takeaways

- Cloud breaches in the Kenyan context are overwhelmingly caused by customer-side misconfiguration, not provider vulnerability.
- The four highest-frequency misconfigurations are public storage, over-permissioned IAM, exposed management interfaces, and absent logging.
- Data residency is a live compliance question for Kenyan organisations, as most major providers lack an in-country region.
- Cloud attack detection requires different signals from on-premise: identity operations, configuration changes, and data transfer patterns.
- Native cloud security posture management tools will identify more issues in an afternoon than a manual review will in a month.

*Written by Glenn Ongalo | Nairobi, Kenya*
