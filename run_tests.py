"""Unit-test every rule against hand-written events, then show a tuning example.
Usage: python3 run_tests.py   (from the scripts directory)"""
import copy, glob, json, os, csv
from sigma_engine import load_rule, matches

rules = {os.path.basename(p)[:-4]: load_rule(p) for p in sorted(glob.glob("../rules/*.yml"))}
cases = json.load(open("../tests/test_cases.json"))
rows, failures = [], []
for name, rule in rules.items():
    c = cases.get(name)
    if not c:
        failures.append(f"{name}: no test cases"); continue
    tp = sum(matches(rule, e) for e in c["should_alert"])
    tn = sum(not matches(rule, e) for e in c["should_not_alert"])
    for e in c["should_alert"]:
        if not matches(rule, e): failures.append(f"{name}: MISSED {e}")
    for e in c["should_not_alert"]:
        if matches(rule, e): failures.append(f"{name}: FALSE ALERT {e}")
    attack = [t for t in rule["tags"] if t.startswith("attack.t")]
    rows.append(dict(rule=name, level=rule["level"], technique=",".join(t[7:].upper() for t in attack),
                     positive_cases=len(c["should_alert"]), positives_detected=tp,
                     benign_cases=len(c["should_not_alert"]), benign_quiet=tn,
                     result="PASS" if tp == len(c["should_alert"]) and tn == len(c["should_not_alert"]) else "FAIL"))
with open("../results/rule_test_results.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
for r in rows:
    print(f"{r['result']}  {r['rule']:50s} {r['positives_detected']}/{r['positive_cases']} detected, {r['benign_quiet']}/{r['benign_cases']} benign quiet")
print(f"\n{sum(r['result']=='PASS' for r in rows)}/{len(rows)} rules pass")

# ---- Tuning example: encoded PowerShell with and without the SCCM filter ----
print("\nTuning example: encoded PowerShell rule")
rule = rules["proc_creation_win_powershell_encoded_command"]
untuned = copy.deepcopy(rule)
untuned["detection"]["condition"] = "selection_img and selection_flag"
sccm_event = {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "CommandLine": "powershell.exe -enc SQBFAFgA", "ParentImage": "C:\\Windows\\CCM\\CcmExec.exe"}
attack_event = {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA", "ParentImage": "C:\\Windows\\System32\\cmd.exe"}
for label, r in (("untuned", untuned), ("tuned (filter_sccm)", rule)):
    print(f"  {label:22s} management-agent event: {'ALERT' if matches(r, sccm_event) else 'quiet'}   attack event: {'ALERT' if matches(r, attack_event) else 'quiet'}")
if failures:
    print("\nFAILURES"); [print(" ", f) for f in failures]; raise SystemExit(1)
