import json
from pathlib import Path
from collections import Counter, defaultdict

# Load eve.json
eve_path = Path("eve.json")
events = []
with open(eve_path, "r", encoding="utf-8") as f:
    for line in f:
        try:
            events.append(json.loads(line.strip()))
        except json.JSONDecodeError:
            continue

# Initialize containers
event_counts = Counter()
timestamps = []

# Buckets for different event types
alerts = []
flows = []
http_logs = []
anomalies = []
dns_queries = []
dns_answers = defaultdict(list)
tls_sessions = []
file_transfers = []


for ev in events:
    if "timestamp" in ev:
        timestamps.append(ev["timestamp"])
    etype = ev.get("event_type")
    if etype:
        event_counts[etype] += 1

    if etype == "dns":
        q = ev.get("dns", {})
        rrname = q.get("rrname")
        if q.get("type") == "query":
            dns_queries.append(rrname)
        elif q.get("type") == "answer":
            for ans in q.get("answers", []):
                dns_answers[rrname].append(ans.get("rdata"))

    elif etype == "tls":
        tls_sessions.append({
            "src": ev.get("src_ip"),
            "dst": ev.get("dest_ip"),
            "sni": ev.get("tls", {}).get("sni"),
            "subject": ev.get("tls", {}).get("subject"),
            "issuer": ev.get("tls", {}).get("issuerdn"),
            "ja3": ev.get("tls", {}).get("ja3", {}).get("hash"),
        })

    elif etype == "fileinfo":
        fi = ev.get("fileinfo", {})
        http = ev.get("http", {})
        file_transfers.append({
            "src": ev.get("src_ip"),
            "dst": ev.get("dest_ip"),
            "filename": fi.get("filename"),
            "size": fi.get("size"),
            "type": http.get("http_content_type"),
            "url": http.get("url"),
            "hostname": http.get("hostname")
        })

    elif etype == "alert":
        a = ev.get("alert", {})
        alerts.append({
            "sig": a.get("signature"),
            "sev": a.get("severity"),
            "cat": a.get("category"),
            "src": ev.get("src_ip"),
            "dst": ev.get("dest_ip"),
            "time": ev.get("timestamp")
        })

    elif etype == "flow":
        flows.append({
            "src": ev.get("src_ip"),
            "dst": ev.get("dest_ip"),
            "sport": ev.get("src_port"),
            "dport": ev.get("dest_port"),
            "proto": ev.get("proto"),
            "bytes_toserver": ev.get("flow", {}).get("bytes_toserver"),
            "bytes_toclient": ev.get("flow", {}).get("bytes_toclient")
        })

    elif etype == "http":
        http_logs.append({
            "src": ev.get("src_ip"),
            "dst": ev.get("dest_ip"),
            "method": ev.get("http", {}).get("http_method"),
            "url": ev.get("http", {}).get("url"),
            "status": ev.get("http", {}).get("status"),
            "hostname": ev.get("http", {}).get("hostname")
        })

    elif etype == "anomaly":
        anomalies.append(ev)

# Time range
time_range = "N/A"
if timestamps:
    try:
        start = min(timestamps)
        end = max(timestamps)
        time_range = f"{start} → {end}"
    except Exception:
        pass

# --- Main Report (summary only) ---
md_main = []
md_main.append("# Incident Response Report\n")

md_main.append("## Summary")
md_main.append(f"- **Time Range:** {time_range}")
md_main.append(f"- **Total Events:** {len(events)}")
md_main.append(f"- **Event Breakdown:** " + ", ".join(f"{k} ({v})" for k,v in event_counts.items()))
md_main.append("")

md_main.append("## Observations")
md_main.append("- Multiple event types observed including DNS, TLS, HTTP, Flows, Alerts, and File transfers.")
if alerts:
    md_main.append("- !! Alerts present: see detailed report.")
if file_transfers:
    md_main.append("- File transfers detected, some may contain executables.")
if anomalies:
    md_main.append("- Anomaly events logged, worth investigation.")
md_main.append("")

md_main.append("## Recommended Actions")
md_main.append("- Block suspicious domains and IPs.")
md_main.append("- Isolate impacted hosts.")
md_main.append("- Investigate suspicious file downloads.")
md_main.append("- Perform threat intel lookups on JA3 hashes, anomalous flows, and rare domains.\n")

# Save Main Report
main_report_path = Path("IR_Main_Report.md")
main_report_path.write_text("\n".join(md_main), encoding="utf-8")

# --- Separate Detailed Reports ---
def save_list_md(title, records, fields, filename, simple=False):
    md = [f"# {title}\n"]
    if records:
        if simple:
            for r in records:
                line = r.get(fields[0]) if isinstance(r, dict) else r
                md.append(str(line))
        else:
            for i, r in enumerate(records, 1):
                md.append(f"## Entry {i}")
                for field in fields:
                    md.append(f"- **{field.capitalize()}:** {r.get(field)}")
                md.append("")
    else:
        md.append("No data found.\n")
    Path(f"{filename}").write_text("\n".join(md), encoding="utf-8")

# Alerts
def save_alerts():
    md = ["# Detailed Alerts Report\n"]
    if alerts:
        for i,a in enumerate(alerts,1):
            md.append(f"### Alert {i}")
            for k,v in a.items():
                md.append(f"- **{k.capitalize()}:** {v}")
            md.append("")
    else:
        md.append("No alerts found.\n")
    Path("IR_Report_Alerts.md").write_text("\n".join(md), encoding="utf-8")

save_alerts()
save_list_md("DNS Queries", [{"domain": d} for d in dns_queries], ["domain"], "IR_Report_DNS.md", simple=True)
save_list_md("TLS Sessions", tls_sessions, ["src","dst","sni","subject","issuer","ja3"], "IR_Report_TLS.md")
save_list_md("File Transfers", file_transfers, ["src","dst","filename","size","type","url","hostname"], "IR_Report_Files.md")
save_list_md("Flows", flows, ["src","dst","sport","dport","proto","bytes_toserver","bytes_toclient"], "IR_Report_Flows.md")
save_list_md("HTTP Logs", http_logs, ["src","dst","method","url","status","hostname"], "IR_Report_HTTP.md")
save_list_md("Anomalies", anomalies, anomalies[0].keys() if anomalies else [], "IR_Report_Anomalies.md")
