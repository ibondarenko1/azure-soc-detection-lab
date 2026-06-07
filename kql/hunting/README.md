# Hunting queries

Curated KQL from this environment's Advanced-hunting history (the SC-200 "Drill" series), kept as a reusable hunting library and used for investigation pivots. Export each as its own `.kql` file here.

Planned set (paste from query history):

| File | What it hunts | Source |
|------|---------------|--------|
| `email-phishing-keywords.kql` | Inbound subjects with classic phishing lures | EmailEvents |
| `email-display-name-spoofing.kql` | Brand display-name from non-matching sender domain | EmailEvents |
| `email-auth-fail-spf-dkim-dmarc.kql` | Inbound mail failing SPF/DKIM/DMARC | EmailEvents |
| `url-ip-literal-domain.kql` | URLs whose domain is a raw IP (phishing indicator) | EmailUrlInfo |
| `url-tld-distribution.kql` | Suspicious TLD distribution across URLs | EmailUrlInfo |
| `join-email-urlinfo.kql` | EmailEvents ⨝ EmailUrlInfo on NetworkMessageId | multi-table |
| `join-alertinfo-evidence.kql` | AlertInfo ⨝ AlertEvidence on AlertId | multi-table |
| `exposuregraph-census.kql` | Asset/config census from the exposure graph | ExposureGraphNodes |

These back the **v2 email/phishing detection family** (see repo backlog).
