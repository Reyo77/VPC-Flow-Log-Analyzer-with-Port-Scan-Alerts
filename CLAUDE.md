# Project 3: VPC Flow Log Analyzer with Port-Scan Alerts (Python + Lambda)

## What we're building

A security tool that reads the VPC Flow Logs that Projects 1 and 2 saved in S3 and answers:
- **Who talks the most?** (top talkers by bytes and packets)
- **Which ports get blocked the most?**
- **When did rejected connections spike?** (rejects over time)
- **Is anyone scanning us?** (port-scan and sweep detection)

Two parts:
1. **Local analyzer (Mac):** Python CLI that downloads logs, analyzes with pandas, builds a single-file **HTML dashboard** with Plotly.
2. **Cloud alerting (AWS Lambda):** the detection logic as a Lambda, run **daily** by EventBridge, sending an **email via SNS** when it finds a scan.

Then prove it: bring Project 1's network up, run my own port scanner against my own instance, check the tool detects exactly what I did.

## My setup

- OS: macOS. Python 3.11+ in a virtual environment (system python3 is 3.15.0; check wheels in Phase 1).
- AWS region: **ap-southeast-2** (same as the Project 1 logging bucket, found in Phase 0). Use only this region.
- Log source: bucket `p1-flowlogs-228998979209` (read-only). 33 objects at Phase 0 (2026-10-20 .. 2026-10-21), expire after 30 days (earliest ~2026-11-19). Flow logs from Project 1's and Project 2's VPCs.
- Flow log format: AWS default (version 2), 14 fields:
  `version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status`
- Project 1 repo (traffic generation): `~/projects/aws-multi-vpc-terraform`
- SSH key: `~/.ssh/project1`
- Alert email: set in `infra/terraform.tfvars` (gitignored). User gives it in Phase 8.
- Name prefix `p3`. Tag everything `Project = "project3"`.
- GitHub repo: https://github.com/Reyo77/VPC-Flow-Log-Analyzer-with-Port-Scan-Alerts

## Rules for Claude

1. Explain in simple words what code does and why. User knows basic Python/FastAPI, is new to pandas, boto3, Lambda. Use real-world comparisons.
2. Never run `terraform apply` or `terraform destroy` (this repo or Project 1) without approval. Show the plan summary first and wait for "yes".
3. Never read, print or copy `~/.ssh/project1` or `~/.aws/credentials`.
4. The S3 bucket is READ-ONLY for this project. Never write/delete objects or change the bucket policy. The Lambda role must not have write access to it.
5. Never commit real log data. `data/`, `*.gz`, reports from real logs stay out of git. Tests use small synthetic fixtures written by hand.
6. Every phase must pass `pytest -q` plus its checks. After a phase passes: `ruff check .`, `pytest -q` (and `terraform fmt`/`validate` for infra), update `NOTES.md`, commit (e.g. `phase 5: port scan detection`).
7. Scanning: the scanner may only target private IPs (10.0.0.0/8) of my own instances. It must refuse public IPs. Slow and small (ports 1-1024, one target).
8. Cost: only Lambda, SNS, EventBridge, CloudWatch Logs and S3 reads. No Athena, Glue, OpenSearch, NAT Gateway. When Project 1's network is up for traffic generation, destroy it in the same session.

## Folder layout

```
flowlog_analyzer/
  __main__.py          CLI: fetch, summary, detect, dashboard
  core/                PURE Python, no pandas (shared with Lambda)
    parser.py  s3_source.py  detect.py
  analysis.py          pandas: top talkers, ports, rejects over time
  dashboard.py         Plotly -> single HTML file
lambda_fn/handler.py   daily detection -> SNS email
tools/portscan.py      TCP connect scanner (private IPs only)
tools/validate.py      compare detections with scanner ground truth
tests/ (fixtures/, test_parser, test_s3_source, test_analysis, test_detect, test_handler)
infra/                 Terraform: Lambda, IAM, SNS, EventBridge
data/ reports/         gitignored
docs/                  screenshots + sanitized sample output
```
`core/` has no pandas so the Lambda zip stays tiny and CLI + Lambda share the same detection code.

## Phases

0. Preflight (done): caller, bucket region, objects, one file downloaded, default format confirmed, lifecycle 30 days, Python version, no instances.
1. Repo + venv + requirements (boto3, pandas, plotly, pytest, ruff, moto) + skeleton + NOTES.md.
2. Parser: `FlowRecord`, `parse_line`, `parse_file` (.log and .log.gz), protocol names (6 TCP, 17 UDP, 1 ICMP, 50 ESP), `is_private`. Handle header, `-`, NODATA/SKIPDATA, malformed lines. Hand-written fixtures `sample.log` / `sample.log.gz`.
3. S3 loader: list by `AWSLogs/<account>/vpcflowlogs/<region>/YYYY/MM/DD/`, cache in `data/cache/`, stream-parse. CLI `fetch --days N`. Tests with moto.
4. Analysis (pandas): top 10 talkers by bytes, top ports, top rejected ports, rejects per 5-minute bucket, accept vs reject per interface, internal vs external sources. CLI `summary --days N`.
5. Detection (`core/detect.py`, thresholds as parameters): vertical scan (>=15 distinct dst ports on one dst within 5 min, mostly REJECT); horizontal sweep (same port on >=5 distinct hosts within 5 min); SSH brute-force (external source, >=20 connections to port 22 within 10 min). Findings: type, source, targets, ports summary, first/last seen, count, accept/reject split, severity. CLI `detect --days N` writes `reports/findings.json`. Positive, negative and boundary tests.
6. HTML dashboard (`reports/dashboard.html`): KPI cards, rejects over time, top talkers, top rejected ports, internal vs external table, findings table with severity colours. CLI `dashboard --days N`.
7. Real traffic + validation: `tools/portscan.py` (stdlib TCP connect, refuses non-10/8, writes ground-truth JSON), `tools/validate.py` (PASS/FAIL). Steps need approval: apply Project 1 network, scp scanner to bastion, scan dev-app private IP, wait ~10 min, fetch/detect/dashboard/validate, destroy Project 1 network.
8. Lambda + SNS + EventBridge (Terraform, own state): arm64, 256 MB, 120 s, zip of `core/` + handler only; least-privilege IAM (ListBucket on `AWSLogs/` prefix, GetObject `AWSLogs/*`, sns:Publish on the topic, own log group); SNS email subscription; daily schedule 03:30 UTC. Handler sends ONE email if findings, nothing otherwise; event can override the window. Tests with moto. Prove with `iam simulate-principal-policy` (deny PutObject/DeleteObject/ec2:*, allow GetObject/Publish).
9. End-to-end: new scan, invoke Lambda for the last hour, email arrives, validate passes, destroy Project 1 network.
10. README (Mermaid architecture, fields, rules + false positives, how to run/deploy, results, IAM explanation, cost, limits, mapping to GuardDuty/Athena/SIEM), screenshot checklist, 3 interview questions, fresh-clone check (no real logs, account IDs or emails in git), decide with user whether to keep the Lambda deployed.
