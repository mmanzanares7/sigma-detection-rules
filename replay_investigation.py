"""Replay the rules against the synthetic logs from the soc-incident-investigation repo.
Reads ../replay/ (copied from that repo's data folder). Writes ../results/replay_alerts.csv
and ../results/replay_summary.csv. The attacker's host is known from the investigation, so
alerts outside that scope count as false positives for the purpose of this exercise."""
import glob, os
import pandas as pd
from sigma_engine import load_rule, matches, logsource_key

# Scope taken from the investigation report: patient zero plus the file server the attacker reached
ATTACK_HOSTS = {"WKS-FIN-014", "SRV-FILE-01"}
ATTACK_START = "2026-08-18 09:00:00"


def in_scope(raw):
    return raw["host"] in ATTACK_HOSTS and raw["timestamp"] >= ATTACK_START

rules = [load_rule(p) for p in sorted(glob.glob("../rules/*.yml"))]
ep = pd.read_csv("../replay/endpoint_events.csv").fillna("")
au = pd.read_csv("../replay/auth_events.csv").fillna("")

streams = {"process_creation": [], "process_access": [], "security": []}
for r in ep.to_dict("records"):
    if r["event_id"] == 1:
        streams["process_creation"].append((r, dict(Image=r["image"], CommandLine=r["command_line"], ParentImage=r["parent_image"])))
    elif r["event_id"] == 10:
        streams["process_access"].append((r, dict(SourceImage=r["image"], TargetImage=r["target_image"], GrantedAccess=r["granted_access"])))
    elif r["event_id"] == 1102:
        streams["security"].append((r, dict(EventID=1102)))
for r in au.to_dict("records"):
    streams["security"].append((r, dict(EventID=int(r["event_id"]), LogonType=int(r["logon_type"]), TargetUserName=r["user"])))

alerts, summary = [], []
for rule in rules:
    key = logsource_key(rule)
    tags = ",".join(t[7:].upper() for t in rule["tags"] if t.startswith("attack.t"))
    if key not in streams:
        summary.append(dict(rule=os.path.basename(rule["_path"])[:-4], technique=tags, level=rule["level"], events_checked=0,
                            alerts=0, related_to_attack=0, unrelated=0, note="No matching log source in the replay data"))
        continue
    hits = [(raw, ev) for raw, ev in streams[key] if matches(rule, ev)]
    for raw, ev in hits:
        alerts.append(dict(timestamp=raw["timestamp"], rule=rule["title"], level=rule["level"], technique=tags,
                           host=raw["host"], user=raw["user"], evidence=(ev.get("CommandLine") or ev.get("TargetImage") or f"EventID {ev.get('EventID')} LogonType {ev.get('LogonType', '')}")[:110]))
    on = sum(1 for raw, _ in hits if in_scope(raw))
    summary.append(dict(rule=os.path.basename(rule["_path"])[:-4], technique=tags, level=rule["level"], events_checked=len(streams[key]),
                        alerts=len(hits), related_to_attack=on, unrelated=len(hits) - on, note=""))
for a in alerts:
    a["related_to_attack"] = a["host"] in ATTACK_HOSTS and a["timestamp"] >= ATTACK_START
al = pd.DataFrame(alerts).sort_values("timestamp")
al.to_csv("../results/replay_alerts.csv", index=False)
sm = pd.DataFrame(summary)
sm.to_csv("../results/replay_summary.csv", index=False)
pd.set_option("display.width", 220); pd.set_option("display.max_colwidth", 70)
print(sm.drop(columns="note").to_string(index=False))
print("\nTotal alerts:", len(al), "| related to the attack:", int(al.related_to_attack.sum()), "| unrelated (false positives):", int((~al.related_to_attack).sum()))
print(al[["timestamp", "host", "user", "technique", "rule"]].to_string(index=False))
