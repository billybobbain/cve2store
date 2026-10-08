#!/usr/bin/env python
"""daily.py: each day's new CVEs -> the mobile apps they affect -> store links.

    .venv/bin/python daily.py                 # catch up: every day since the last one done
    .venv/bin/python daily.py --day 2026-10-05
    .venv/bin/python daily.py --from 2026-10-01 --to 2026-10-05

For each day (UTC, by NVD publish date):
  1. NVD: every CVE published that day (NVD_API_KEY from ~/.config/cve2store/*.env
     is used if present; without it NVD allows 5 requests / 30 s).
  2. cve.org: each CVE's own record -- affected products and platforms, which NVD's
     copy lacks and which arrive long before NVD adds CPEs.
  3. Cheap filter: keep CVEs that mention Android / iOS anywhere (description,
     product names, platforms, CPE target platform).
  4. LLM: classify each as a mobile app, a platform (OS / kernel / firmware /
     chipset -- skipped) or not mobile.
  5. cve2store on the mobile apps: store links, IDs, versions.
  6. digests/YYYY-MM-DD.md, links first; everything also kept in cves.sqlite.

A day counts as done only if every step succeeded, so a failed or skipped run is
picked up by the next catch-up.
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.request

import cve2store as cs

HERE = cs.HERE
DB = os.path.join(HERE, "cves.sqlite")
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MOBILE = re.compile(r"\b(android|ios|iphone|ipad|ipados|watchos|google play|app store|apk|"
                    r"mobile app|mobile application)\b", re.I)
CPE_MOBILE = re.compile(r":(android|iphone_os|ipados|ios):", re.I)

CLASSIFY_SYSTEM = """You triage vulnerability records for a list of MOBILE APP vulnerabilities.
Classify the record:
- "mobile_app": an app a user installs or that ships on a phone as an app (including
  vendor/preinstalled apps), on Android or iOS.
- "platform": the operating system, kernel, firmware, drivers, chipsets, basebands or
  OS components (e.g. Android framework, Bluetooth/NFC stacks, WebKit/iOS itself).
- "not_mobile": anything else (servers, desktop software, libraries not specific to a
  mobile app, web services).
Also give the platforms the app runs on, the app's name, and a summary of at most
12 words, plain and specific (what an attacker can do, in what app)."""

CLASSIFY_SCHEMA = {
    "type": "object", "required": ["category", "platforms", "app", "summary"],
    "properties": {
        "category": {"type": "string", "enum": ["mobile_app", "platform", "not_mobile"]},
        "platforms": {"type": "array", "items": {"type": "string", "enum": ["android", "ios"]}},
        "app": {"type": "string"},
        "summary": {"type": "string"}}}


# ---- storage ----------------------------------------------------------------------
def db():
    con = sqlite3.connect(DB)
    con.execute("""create table if not exists cve (
        id text primary key, day text, source text, description text, mentions_mobile int,
        category text, platforms text, app text, summary text, links text, processed text)""")
    con.execute("create table if not exists day (day text primary key, done text, "
                "published int, mentions_mobile int, mobile_app int, platform int)")
    return con


# ---- 1-2. fetch -------------------------------------------------------------------
def nvd_day(day):
    out, start = [], 0
    while True:
        q = (f"{NVD}?pubStartDate={day}T00:00:00.000Z&pubEndDate={day}T23:59:59.999Z"
             f"&resultsPerPage=2000&startIndex={start}")
        for attempt in range(5):           # NVD is slow and returns 503s at times
            try:
                d = cs.get(q, headers=cs.nvd_headers(), timeout=180)
                break
            except Exception as e:
                if attempt == 4:
                    raise
                wait = 30 * (attempt + 1)
                print(f"  NVD request failed ({e}); retrying in {wait}s", file=sys.stderr)
                time.sleep(wait)
        out += [v["cve"] for v in d["vulnerabilities"]]
        start += d["resultsPerPage"]
        if start >= d["totalResults"]:
            return out
        time.sleep(1 if cs.nvd_headers() else 6)


def cna_record(cve_id):
    for attempt in range(3):
        try:
            return cs.get(f"https://cveawg.mitre.org/api/cve/{cve_id}")
        except Exception:
            time.sleep(2 * (attempt + 1))
    return None


# ---- 3. filter --------------------------------------------------------------------
def mobile_text(nvd_cve, rec):
    """Everything that could say 'this is mobile', as one string."""
    parts = [d["value"] for d in nvd_cve.get("descriptions", []) if d["lang"] == "en"]
    parts += [m["criteria"] for c in nvd_cve.get("configurations", [])
              for n in c["nodes"] for m in n["cpeMatch"]]
    if rec:
        for a in rec["containers"]["cna"].get("affected", []):
            parts += [a.get("product", ""), a.get("vendor", "")] + a.get("platforms", [])
    return " | ".join(parts)


def mentions_mobile(text):
    return bool(MOBILE.search(text) or CPE_MOBILE.search(text))


# ---- 4. classify -------------------------------------------------------------------
def classify(cve_id, nvd_cve, rec):
    cna = rec["containers"]["cna"] if rec else {}
    payload = {"id": cve_id, "assigner": nvd_cve.get("sourceIdentifier"),
               "description": " ".join(d["value"] for d in nvd_cve["descriptions"]
                                      if d["lang"] == "en"),
               "affected": [{k: a.get(k) for k in ("vendor", "product", "platforms")}
                            for a in cna.get("affected", [])],
               "cpes": [m["criteria"] for c in nvd_cve.get("configurations", [])
                        for n in c["nodes"] for m in n["cpeMatch"]][:10]}
    return cs.llm(CLASSIFY_SYSTEM, json.dumps(payload, indent=1), CLASSIFY_SCHEMA, "classify")


# ---- the model server ----------------------------------------------------------------
def llm_up():
    base = cs.LLM_URL.split("/v1/")[0]
    try:
        with urllib.request.urlopen(base + "/health", timeout=5) as r:
            return b"ok" in r.read()
    except Exception:
        return False


def gpu_busy():
    """Another program (not the model server) holding >1 GB of GPU memory -- e.g. a
    long render.  Waking a large model next to it could run the GPU out of memory, so
    the day is deferred instead.  No nvidia-smi -> never busy.  LLM_GPU_GUARD=0 disables."""
    if os.environ.get("LLM_GPU_GUARD", "1") == "0":
        return None
    try:
        out = subprocess.run(["nvidia-smi", "--query-compute-apps=process_name,used_memory",
                              "--format=csv,noheader,nounits"], capture_output=True,
                             text=True, timeout=20).stdout
    except Exception:
        return None
    for line in out.strip().splitlines():
        name, _, mem = line.rpartition(",")
        if "llama" not in name.lower() and mem.strip().isdigit() and int(mem) > 1000:
            return f"{os.path.basename(name.strip())} ({mem.strip()} MiB)"
    return None


def ensure_llm():
    """-> (ok, process we started or None).  Use the server if it's up; else run
    LLM_START_CMD (from the config) and wait."""
    busy = gpu_busy()
    if busy:
        print(f"GPU in use by {busy}; deferring", file=sys.stderr)
        return False, None
    if llm_up():
        return True, None
    cmd = os.environ.get("LLM_START_CMD")
    if not cmd:
        print("LLM server not reachable and no LLM_START_CMD configured", file=sys.stderr)
        return False, None
    print(f"starting the model: {cmd}", file=sys.stderr)
    proc = subprocess.Popen(cmd, shell=True, start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(90):
        time.sleep(4)
        if llm_up():
            return True, proc
    print("model server did not come up", file=sys.stderr)
    stop_llm(proc)
    return False, None


def stop_llm(proc):
    """Stop a server we started (its whole process group), leaving others alone."""
    if proc:
        import signal
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=30)
        except Exception:
            pass


# ---- 6. digest ---------------------------------------------------------------------------
def digest(con, day):
    rows = con.execute("select id, app, platforms, summary, links from cve where day=? and "
                       "category='mobile_app' order by id", (day,)).fetchall()
    stats = con.execute("select published, mentions_mobile, mobile_app, platform from day "
                        "where day=?", (day,)).fetchone()
    L = [f"# Mobile-app CVEs published {day}", "",
         f"{stats[2]} mobile-app CVEs · {stats[3]} platform (skipped) · "
         f"{stats[1]} mention Android/iOS · {stats[0]} published", ""]
    for cid, app, plats, summary, links in rows:
        L.append(f"**[{cid}](https://nvd.nist.gov/vuln/detail/{cid})** {app} "
                 f"({', '.join(json.loads(plats)) or '?'}): {summary}")
        L += [f"- {x}" if not x.startswith("! ") else f"- ⚠ {x[2:]}"
              for x in (links or "lookup failed").splitlines()[1:]] or ["- no store match"]
        L.append("")
    if not rows:
        L.append("_None today._")
    os.makedirs(os.path.join(HERE, "digests"), exist_ok=True)
    path = os.path.join(HERE, "digests", f"{day}.md")
    with open(path, "w") as f:
        f.write("\n".join(L) + "\n")
    return path


# ---- one day -------------------------------------------------------------------------------
def run_day(con, day, country, llm_ok):
    t0 = time.time()
    cves = nvd_day(day)
    with cf.ThreadPoolExecutor(8) as ex:
        recs = dict(zip([c["id"] for c in cves], ex.map(cna_record, [c["id"] for c in cves])))
    flagged = [(c, recs[c["id"]]) for c in cves if mentions_mobile(mobile_text(c, recs[c["id"]]))]
    print(f"{day}: {len(cves)} published, {len(flagged)} mention Android/iOS "
          f"({time.time() - t0:.0f}s)", flush=True)
    if flagged and not llm_ok:
        print(f"{day}: model unavailable, leaving the day for the next run", file=sys.stderr)
        return False
    n_app = n_plat = 0
    for c, rec in flagged:
        cid = c["id"]
        done = con.execute("select category, links from cve where id=?", (cid,)).fetchone()
        if done and done[0] and (done[0] != "mobile_app" or done[1]):
            cat = done[0]
        else:
            k = classify(cid, c, rec)
            cat, links = k["category"], None
            if cat == "mobile_app":
                try:
                    cve, entries, _ = cs.lookup(cid, country)
                    links = cs.short(cve, entries)
                except Exception as e:
                    links = f"{cid}\n! store lookup failed: {e}"
            con.execute("insert or replace into cve values (?,?,?,?,?,?,?,?,?,?,?)",
                        (cid, day, c.get("sourceIdentifier"),
                         " ".join(d["value"] for d in c["descriptions"] if d["lang"] == "en"),
                         1, cat, json.dumps(k["platforms"]), k["app"], k["summary"], links,
                         dt.datetime.now().isoformat(timespec="seconds")))
            con.commit()
            print(f"  {cid}: {cat}  {k['app']}", flush=True)
        n_app += cat == "mobile_app"
        n_plat += cat == "platform"
    con.execute("insert or replace into day values (?,?,?,?,?,?)",
                (day, dt.datetime.now().isoformat(timespec="seconds"), len(cves), len(flagged),
                 n_app, n_plat))
    con.commit()
    print(f"{day}: {n_app} mobile-app CVEs -> {digest(con, day)}  ({time.time() - t0:.0f}s)")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--day")
    ap.add_argument("--from", dest="frm")
    ap.add_argument("--to")
    ap.add_argument("--max-days", type=int, default=7, help="catch-up limit")
    ap.add_argument("--country", default="us")
    a = ap.parse_args()
    con = db()
    yesterday = dt.date.today() - dt.timedelta(days=1)          # NVD days are UTC; run after midnight UTC
    if a.day:
        days = [dt.date.fromisoformat(a.day)]
    elif a.frm:
        d0, d1 = dt.date.fromisoformat(a.frm), dt.date.fromisoformat(a.to or str(yesterday))
        days = [d0 + dt.timedelta(n) for n in range((d1 - d0).days + 1)]
    else:
        last = con.execute("select max(day) from day").fetchone()[0]
        start = dt.date.fromisoformat(last) + dt.timedelta(1) if last else yesterday
        days = [start + dt.timedelta(n) for n in range((yesterday - start).days + 1)][-a.max_days:]
    if not days:
        print("nothing to do: up to date")
        return
    llm_ok, started = ensure_llm()
    try:
        ok = all([run_day(con, str(d), a.country, llm_ok) for d in days])
    finally:
        stop_llm(started)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
