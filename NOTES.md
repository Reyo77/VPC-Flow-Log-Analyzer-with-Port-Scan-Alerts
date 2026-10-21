# NOTES

## Phase 0: Preflight (passed)
- Caller is IAM user `admin`. Bucket `p1-flowlogs-228998979209` is in `ap-southeast-2`. 33 keys (32 log files + the empty `AWSLogs/<account>/` folder marker), 2026-10-20 to 2026-10-21, about 33 KB. Lifecycle: expire after 30 days, so the oldest logs go around 2026-11-19.
- Default 14-field format confirmed. System Python is 3.15.0; pandas/plotly/moto install fine on Python 3.14.5 (used for `.venv`).

## Phases 1-3: Setup, parser, S3 loader (passed)
- Parser: 9 tests. Real file: 34 records, equal to a manual `awk` count (34). Across all 32 cached files: 2367 real records, equal to the manual count of `log-status=OK` lines (2367); 35 NODATA lines (idle interfaces) are dropped by default.
- Loader: moto tests (list by day and region, cache, window filter). `fetch --days 30`: 32 files, 2367 records, 7 interfaces.

## Phase 4: Analysis (passed)
- 26 tests total. Live data: 2367 flows, 710 rejects (30%), 450 unique sources (443 external).
- Findings in the real data: 31 MB flows from AWS/Canonical addresses are package downloads (apt) to the firewalls; UDP 123 is the most rejected port (apps trying public NTP); TCP 23 and 3389 rejects come from many different internet scanners; the long idle gap overnight shows as zero buckets.
- Lessons for detection: (1) return traffic of accepted downloads looks like "many ports" from one source, so the scan rule must require mostly-REJECT; (2) my own Mac's IP is an "external" source on port 22, so the SSH rule needs an allowlist.
