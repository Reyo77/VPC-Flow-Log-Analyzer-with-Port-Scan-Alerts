# NOTES

## Phase 0: Preflight (passed)
- Caller is IAM user `admin`. Bucket `p1-flowlogs-<account-id>` is in `ap-southeast-2`. 33 keys (32 log files + the empty `AWSLogs/<account>/` folder marker), 2026-10-20 to 2026-10-21, about 33 KB. Lifecycle: expire after 30 days, so the oldest logs go around 2026-11-19.
- Default 14-field format confirmed. System Python is 3.15.0; pandas/plotly/moto install fine on Python 3.14.5 (used for `.venv`).

## Phases 1-3: Setup, parser, S3 loader (passed)
- Parser: 9 tests. Real file: 34 records, equal to a manual `awk` count (34). Across all 32 cached files: 2367 real records, equal to the manual count of `log-status=OK` lines (2367); 35 NODATA lines (idle interfaces) are dropped by default.
- Loader: moto tests (list by day and region, cache, window filter). `fetch --days 30`: 32 files, 2367 records, 7 interfaces.

## Phase 4: Analysis (passed)
- 26 tests total. Live data: 2367 flows, 710 rejects (30%), 450 unique sources (443 external).
- Findings in the real data: 31 MB flows from AWS/Canonical addresses are package downloads (apt) to the firewalls; UDP 123 is the most rejected port (apps trying public NTP); TCP 23 and 3389 rejects come from many different internet scanners; the long idle gap overnight shows as zero buckets.
- Lessons for detection: (1) return traffic of accepted downloads looks like "many ports" from one source, so the scan rule must require mostly-REJECT; (2) my own Mac's IP is an "external" source on port 22, so the SSH rule needs an allowlist.

## Phase 5: Detection (passed)
- `core/detect.py`: vertical scan, horizontal sweep, SSH brute force; sliding time window; reject-ratio filter; `--allow` list. 51 tests (positive, negative, boundaries, two attackers, two bursts, allowlist, unsorted input).
- Bug found by a test: two bursts hours apart were merged into one finding because neighbouring flagged records were joined without checking the gap. Fixed.
- Live run on real data (no allowlist): 2 "SSH brute force" findings that are my own Mac (<my-mac-ip-1> on 20 Oct, <my-mac-ip-2> on 21 Oct) connecting to my own firewalls during tests, and 2 "sweeps" from 10.0.0.83 (Project 1's bastion) whose outbound HTTPS/NTP was blocked by its own security group. With my IPs allowlisted: only the 2 low-severity egress findings remain. Sweeps from an internal host to internet-only targets are now `low`.
- Known false positives: my own IPs (use `--allow`), internal hosts with blocked egress, vulnerability scanners we run ourselves.

## Phase 6: Dashboard (passed)
- `dashboard.py`: one HTML file (4.7 MB, plotly.js embedded): KPI cards, findings table (severity coloured, HTML-escaped), rejects over time, top talkers, top rejected ports, internal vs external tables. 4 tests (sections present, escaping, empty data). Built from real data and opened with `open reports/dashboard.html`.

## Phase 7 tools (built; real-traffic run pending approval)
- `tools/portscan.py`: stdlib TCP connect scanner, refuses anything outside 10.0.0.0/8, max 1024 ports, writes a ground-truth JSON. `tools/validate.py`: PASS/FAIL against `findings.json` (source, target, time window, port count, open ports). 7 tests.

## Wrap-up (session end)
- README and `documentation/PROJECT_DOCUMENTATION.md` written. Both state plainly what is finished and what is not.
- NOT done: Phase 7 live scan + validation (needs Project 1 network up, plan was 75 to add, never applied), Phase 8 Lambda/SNS/EventBridge, Phase 9 end-to-end. Nothing in AWS was created by this project.
- AWS check at session end (ap-southeast-2): no instances, VPCs, volumes, Elastic IPs, NAT gateways, flow logs, RDS, SNS topics, log groups or dashboards. Unrelated Lambda `hello-web` exists (not created by these projects, left alone).
- Account ID and my home IPs were removed from tracked files (git history of earlier commits still contains the bucket name with the account ID).
