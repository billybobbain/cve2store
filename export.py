#!/usr/bin/env python
"""export.py: monthly CSVs and an index of the days that have mobile-app CVEs.

    .venv/bin/python export.py          # rebuild everything from cves.sqlite + reports/

  data/YYYY-MM.csv   one row per (CVE, store listing); a CVE with no store match
                     gets one row with an empty store.  Sorted by publish date.
  digests/README.md  every month with its CSV, and only the days that have
                     mobile-app CVEs, newest first.

daily.py runs this after each day, so the files stay current.
"""
import csv
import json
import os
import sqlite3

import cve2store as cs

HERE = cs.HERE
COLUMNS = ["published", "cve", "cve_url", "app", "platform", "summary", "store",
           "package_or_bundle_id", "store_url", "store_version", "current_version",
           "affected_versions", "developer", "match_confidence", "needs_review"]


def rows_for(cve_id, day, app, summary):
    path = os.path.join(HERE, "reports", f"{cve_id}.json")
    base = {"published": day, "cve": cve_id, "cve_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "app": app, "summary": summary}
    if not os.path.exists(path):
        return [dict(base, current_version="store lookup failed")]
    with open(path) as f:
        rep = json.load(f)
    out = []
    for e in rep["entries"]:
        rng = " ".join(x for x in (
            f">= {e['affected_from']}" if e.get("affected_from") and e.get("affected_from_inclusive")
            else (f"> {e['affected_from']}" if e.get("affected_from") else ""),
            f"< {e['fixed_in']}" if e.get("fixed_in") else "",
            f"<= {e['affected_through']}" if e.get("affected_through") else "") if x)
        for store, m in (e.get("matches") or {}).items():
            if not m or m["match_id"] == "none":
                continue
            c = m["listing"]
            hit, why = cs.verdict(e, c["version"])
            review = []
            if not m.get("stable", True):
                review.append(f"unstable match (alt: {m.get('second_answer')})")
            if m["confidence"] != "high":
                review.append(f"{m['confidence']} confidence")
            if hit is None and "formats differ" in why:
                review.append("version formats differ")
            out.append(dict(base, platform="android" if store == "Google Play" else "ios",
                            store=store, package_or_bundle_id=c["id"], store_url=c["url"],
                            store_version=c["version"],
                            current_version={True: "affected", False: "fixed",
                                             None: "unknown"}[hit],
                            affected_versions=rng, developer=c["developer"],
                            match_confidence=m["confidence"], needs_review="; ".join(review)))
    return out or [dict(base, current_version="no store match")]


def export():
    con = sqlite3.connect(os.path.join(HERE, "cves.sqlite"))
    apps = con.execute("select id, day, app, summary from cve where category='mobile_app' "
                       "order by day, id").fetchall()
    days = con.execute("select day, mobile_app, published from day order by day desc").fetchall()
    by_month = {}
    for cid, day, app, summary in apps:
        by_month.setdefault(day[:7], []).extend(rows_for(cid, day, app, summary))
    os.makedirs(os.path.join(HERE, "data"), exist_ok=True)
    for month, rows in by_month.items():
        with open(os.path.join(HERE, "data", f"{month}.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=COLUMNS)
            w.writeheader()
            w.writerows(rows)

    L = ["# Digests", "",
         "Mobile-app CVEs by day (UTC, NVD publish date), with the store links. "
         "Only days that have any are listed; every day processed has a file here.", ""]
    months = sorted({d[:7] for d, _, _ in days}, reverse=True)
    for month in months:
        n = sum(1 for a in apps if a[1].startswith(month))
        csvlink = f" · [CSV](../data/{month}.csv)" if month in by_month else ""
        L += [f"## {month}: {n} mobile-app CVEs{csvlink}", ""]
        for day, _, published in days:
            todays = [a for a in apps if a[1] == day]
            if day.startswith(month) and todays:
                n_app = len(todays)
                names = sorted({a[2] for a in todays})
                shown = ", ".join(names[:6]) + (f" +{len(names) - 6} more" if len(names) > 6 else "")
                L.append(f"- [{day}]({day}.md): {n_app} ({shown})")
        L.append("")
    with open(os.path.join(HERE, "digests", "README.md"), "w") as f:
        f.write("\n".join(L) + "\n")
    return {m: len(r) for m, r in by_month.items()}


if __name__ == "__main__":
    for month, n in sorted(export().items()):
        print(f"data/{month}.csv: {n} rows")
