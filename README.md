# Sigma Detection Rules

Twelve Sigma detection rules mapped to MITRE ATT&CK, a small Python evaluator that runs them without a SIEM, unit tests for every rule, and a replay of the rules against the logs from my [soc-incident-investigation](https://github.com/mmanzanares7/soc-incident-investigation) project.

## Project Description

Sigma is a vendor neutral rule format for describing what suspicious activity looks like in logs. A rule written once can be converted for Splunk, Elastic, Microsoft Sentinel and others. Writing good rules is a core SOC and detection engineering skill, and so is proving a rule works before it goes live and starts waking people up.

This repo covers the full loop on a small scale:

1. **Write** the rule (YAML in `rules/`) with a description, ATT&CK tags, log source, detection logic, known false positives and a severity level.
2. **Test** it. Every rule has events that must alert and benign look-alike events that must stay quiet (`tests/test_cases.json`).
3. **Tune** it. The encoded PowerShell rule shows how a filter removes a known false positive without losing the attack.
4. **Replay** the rules against a realistic multi source incident dataset and check what fires and what does not.

The evaluator (`scripts/sigma_engine.py`) is a deliberately small subset of the Sigma specification, so the logic is easy to read and audit. For production use, convert rules with pySigma instead.

## Rules and ATT&CK Mapping

| Rule | Tactic | Technique | Level |
|---|---|---|---|
| Office application spawns command shell or script host | Execution | T1204.002, T1059.003 | High |
| PowerShell started with an encoded command | Execution | T1059.001 | Medium |
| Scheduled task created to run a script interpreter | Persistence | T1053.005 | Medium |
| LSASS memory dump via comsvcs.dll | Credential Access | T1003.001 | High |
| Suspicious process access to LSASS | Credential Access | T1003.001 | High |
| Windows event log cleared with wevtutil | Defense Evasion | T1070.001 | High |
| Windows Security audit log cleared (event 1102) | Defense Evasion | T1070.001 | High |
| Volume shadow copies deleted | Impact | T1490 | High |
| File download with certutil | Command and Control | T1105 | Medium |
| Domain Admins group enumeration with net | Discovery | T1069.002 | Low |
| Remote Desktop logon by a service account | Lateral Movement | T1021.001, T1078 | Medium |
| Path traversal attempt in web request | Initial Access | T1190 | Medium |

## How It Works

- `rules/*.yml`: the rules. Each has a deterministic UUID, status `experimental`, and a `falsepositives` section.
- `scripts/sigma_engine.py`: loads a rule and tests an event (a dictionary of fields) against it. Supports `contains`, `startswith`, `endswith`, `all`, case insensitive matching, `and` / `or` / `not`, parentheses, and `1 of selection_*` / `all of` conditions. It does not support regex, CIDR, base64 modifiers or aggregations such as counts over a time window.
- `tests/test_cases.json`: 20 events that should alert and 30 benign events that should not, across the 12 rules.
- `scripts/run_tests.py`: runs the unit tests and the tuning example.
- `scripts/replay_investigation.py`: converts the endpoint and authentication logs into rule ready events and runs every rule.

Run it:

```
cd scripts
pip install pyyaml pandas
python3 run_tests.py
python3 replay_investigation.py
```

## Results

**Unit tests:** all 12 rules detect their positive cases and stay quiet on their benign cases (`results/rule_test_results.csv`). The benign cases are the near misses that matter, for example Word started normally by Explorer, `wevtutil` used to query rather than clear, `vssadmin list shadows`, and `certutil -hashfile`.

**Tuning example:** the encoded PowerShell rule alerts on a management agent (`CcmExec.exe` parent) when untuned. With the `filter_sccm` condition it stays quiet on the agent and still alerts on the attacker's `-enc` command.

**Replay against the incident logs** (2,278 process events and 597 authentication events, 8 days):

| Result | Count |
|---|---|
| Alerts raised | 10 |
| Alerts tied to the attack | 10 |
| Alerts on benign activity | 0 |

Alerts fired for the macro launched shell, the encoded PowerShell, the scheduled task persistence, Domain Admins enumeration, both LSASS rules, two interactive RDP logons by the service account `svc_backup`, `wevtutil cl Security` and event 1102. Benign look-alikes in the dataset did not fire: the `schtasks` jobs created by IT staff, the nightly backup logon, and the admin RDP sessions. Full output is in `results/replay_alerts.csv` and `results/replay_summary.csv`.

## Limitations

- **The replay is not an independent test.** I wrote the rules knowing what the attack contained, so catching it proves the rules and the data are consistent, not that the rules would find an unknown attacker. Real rule quality shows up against live traffic over weeks.
- **Gaps:** the investigation also found beaconing, a first seen exfiltration destination and a phishing email. These need aggregation over time or network and email data, which this simple evaluator and these rules do not cover. The investigation project detects them with statistics instead. Three rules (`certutil`, `vssadmin`, path traversal) had nothing to fire on in this dataset and are covered by unit tests only.
- The LSASS access rule excludes `MsMpEng.exe` by path, which an attacker could imitate. A production rule should also check the signer or the install directory.
- Rules are marked `experimental` and carry no organization specific tuning. Severity levels are my judgment.
- The dataset is synthetic. All domains use `.example` and all external IPs are from documentation ranges.

## Related Projects

- [soc-incident-investigation](https://github.com/mmanzanares7/soc-incident-investigation): the incident these rules are replayed against, and the statistical detections they do not cover.
- [phishing-email-analysis-toolkit](https://github.com/mmanzanares7/phishing-email-analysis-toolkit): the email side of the same attack chain.

## Summary

Twelve ATT&CK mapped Sigma rules with a readable evaluator, unit tests with benign look-alikes, a tuning example and a replay that caught every stage of the attack the rules were designed for with no false alerts. The point is the workflow: write, test, tune, replay, and be honest about what the rules cannot see.
