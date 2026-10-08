#!/usr/bin/env python
"""cve2store: from a CVE ID to app-store package / bundle IDs and versions.

    .venv/bin/python cve2store.py CVE-2026-23866 [--country us]

Division of labour -- the model proposes, the code verifies:

  1. code   fetch the CVE record (cve.org API) and any CPEs (NVD API)
  2. LLM    extract: per affected product -> platform, store search terms, likely
            developer names, version range, IDs *literally* in the text
  3. code   search Google Play and the App Store with those terms; fetch details
  4. LLM    match: which real listing is the affected app (or none), with evidence;
            same-developer listings as "related, not named"
  5. code   check the match: the ID must be a listing the code found, quoted
            evidence must appear in that listing; developer website vs the CVE's
            reference domains; compare versions (normalising e.g. a dropped "2.")

Determinism: coder27 (llama.cpp, --parallel 1) with temperature 0, top-k 1, a fixed
seed, thinking off and a JSON schema per call.  The match is asked twice, with the
listings in opposite orders; if the answers differ the report says so.  Every LLM
answer is cached under cache/, so re-running a CVE gives the same report.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

LLM_URL = os.environ.get("LLM_URL", "http://localhost:8090/v1/chat/completions")
LLM_MODEL = os.environ.get("LLM_MODEL", "coder27")
UA = {"User-Agent": "Mozilla/5.0 (cve2store)"}
HERE = os.path.dirname(os.path.abspath(__file__))


def load_config(path=os.path.expanduser("~/.config/cve2store")):
    """KEY=VALUE lines from every *.env file there (e.g. NVD_API_KEY) into the environment.
    Values already in the environment win.  Nothing secret lives in the repo."""
    if os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            if name.endswith(".env"):
                with open(os.path.join(path, name)) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_config()


# ---- plumbing ------------------------------------------------------------------
def get(url, as_json=True, timeout=30, headers=None):
    h = dict(UA, **(headers or {}))
    with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
        data = r.read().decode("utf-8", "replace")
    return json.loads(data) if as_json else data


def llm(system, user, schema, name):
    """One deterministic, schema-constrained call; cached on disk by its inputs."""
    body = {"model": LLM_MODEL, "temperature": 0, "top_k": 1, "seed": 0, "max_tokens": 2048,
            "chat_template_kwargs": {"enable_thinking": False},
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": name, "schema": schema}},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}]}
    key = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:24]
    path = os.path.join(HERE, "cache", "llm", f"{name}_{key}.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    req = urllib.request.Request(LLM_URL, json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        out = json.loads(json.load(r)["choices"][0]["message"]["content"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    return out


def host_root(url):
    """'https://www.whatsapp.com/x' -> 'whatsapp.com' (last two labels)."""
    h = urllib.parse.urlparse(url if "//" in url else "//" + url).hostname or ""
    return ".".join(h.lower().split(".")[-2:])


# ---- 1. the CVE ----------------------------------------------------------------
def nvd_headers():
    key = os.environ.get("NVD_API_KEY")
    return {"apiKey": key} if key else {}


def fetch_cve(cve_id):
    rec = get(f"https://cveawg.mitre.org/api/cve/{cve_id}")
    cna = rec["containers"]["cna"]
    cpes = []
    try:
        nvd = get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                  headers=nvd_headers())
        for v in nvd.get("vulnerabilities", []):
            for conf in v["cve"].get("configurations", []):
                for node in conf.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        cpes.append({k: m[k] for k in m if k in (
                            "criteria", "versionStartIncluding", "versionStartExcluding",
                            "versionEndIncluding", "versionEndExcluding")})
    except Exception as e:                                  # NVD is slow / rate-limited
        print(f"(NVD lookup failed, continuing without CPEs: {e})", file=sys.stderr)
    return {"id": cve_id,
            "description": " ".join(d["value"] for d in cna.get("descriptions", [])
                                    if d.get("lang", "en").startswith("en")),
            "affected": cna.get("affected", []),
            "references": [r["url"] for r in cna.get("references", [])],
            "cpes": cpes}


# ---- 2. extract ----------------------------------------------------------------
EXTRACT_SYSTEM = """You read vulnerability records and identify the MOBILE APPS they affect.
For each affected product, return:
- product, vendor: as written in the record.
- platform: "android" or "ios" if the record says so (product name, description or CPE
  target_sw), else "unknown".
- search_terms: 1-3 short queries for an app-store search (the app's name as users
  know it; no version numbers).
- developer_names: names the publisher might use on the stores. Include the vendor as
  written AND any well-known publisher name for this product (e.g. a subsidiary). These
  are only search hints; they will be checked against the real store listings.
- version ranges: copy version strings EXACTLY as they appear in the record. Use
  null when a bound is not given.
- ids_in_text: package names / bundle IDs ONLY if they appear literally in the record.
  Never supply an ID from memory; if none appear, return [].
Skip products that are clearly not mobile apps (servers, libraries, desktop software)."""

EXTRACT_SCHEMA = {
    "type": "object", "required": ["entries"],
    "properties": {"entries": {"type": "array", "items": {
        "type": "object",
        "required": ["product", "vendor", "platform", "search_terms", "developer_names",
                     "affected_from", "affected_from_inclusive", "fixed_in", "affected_through",
                     "ids_in_text"],
        "properties": {
            "product": {"type": "string"}, "vendor": {"type": "string"},
            "platform": {"type": "string", "enum": ["android", "ios", "unknown"]},
            "search_terms": {"type": "array", "items": {"type": "string"}, "maxItems": 3},
            "developer_names": {"type": "array", "items": {"type": "string"}, "maxItems": 4},
            "affected_from": {"type": ["string", "null"]},
            "affected_from_inclusive": {"type": "boolean"},
            "fixed_in": {"type": ["string", "null"],
                         "description": "first version NOT affected (a 'lessThan' bound)"},
            "affected_through": {"type": ["string", "null"],
                                 "description": "last version affected (inclusive bound)"},
            "ids_in_text": {"type": "array", "items": {"type": "string"}}}}}}}


def extract(cve):
    user = json.dumps({k: cve[k] for k in ("id", "description", "affected", "references", "cpes")},
                      indent=1)
    out = llm(EXTRACT_SYSTEM, user, EXTRACT_SCHEMA, "extract")
    blob = json.dumps(cve)
    for e in out["entries"]:              # verify: versions and IDs must be in the record
        e["warnings"] = []
        for k in ("affected_from", "fixed_in", "affected_through"):
            if e[k] and e[k] not in blob:
                e["warnings"].append(f"{k} '{e[k]}' is not in the record; dropped")
                e[k] = None
        bad = [i for i in e["ids_in_text"] if i not in blob]
        if bad:
            e["warnings"].append(f"IDs not in the record, dropped: {bad}")
        e["ids_in_text"] = [i for i in e["ids_in_text"] if i in blob]
    return out["entries"]


# ---- 3. the stores ---------------------------------------------------------------
def appstore_search(term, country, limit=8):
    q = urllib.parse.urlencode({"term": term, "entity": "software", "country": country,
                                "limit": limit})
    out = []
    for r in get(f"https://itunes.apple.com/search?{q}")["results"]:
        out.append({"store": "App Store", "id": r["bundleId"], "title": r["trackName"],
                    "developer": r.get("sellerName") or r.get("artistName"),
                    "developer_site": r.get("sellerUrl") or "",
                    "version": r.get("version"), "url": r["trackViewUrl"].split("?")[0],
                    "store_id": f"id{r['trackId']}"})
    return out


def play_search(term, country, limit=8):
    """IDs from the search page (the scraper drops the featured hit's ID), then details."""
    from google_play_scraper import app as play_app
    q = urllib.parse.urlencode({"q": term, "c": "apps", "hl": "en", "gl": country.upper()})
    html = get(f"https://play.google.com/store/search?{q}", as_json=False)
    ids = list(dict.fromkeys(re.findall(r"details\?id=([A-Za-z0-9._]+)", html)))[:limit]
    out = []
    for pid in ids:
        try:
            d = play_app(pid, lang="en", country=country)
        except Exception:
            continue
        out.append({"store": "Google Play", "id": pid, "title": d.get("title"),
                    "developer": d.get("developer"), "developer_site": d.get("developerWebsite") or "",
                    "version": d.get("version"), "url": f"https://play.google.com/store/apps/details?id={pid}",
                    "store_id": pid})
    return out


def cached_search(fn, term, country, ttl=12 * 3600):
    """Store searches cached for ttl seconds: a release day can bring 20+ CVEs for one
    app (e.g. Chrome), and each would otherwise repeat the same slow lookups."""
    key = hashlib.sha256(f"{fn.__name__}|{term}|{country}".encode()).hexdigest()[:20]
    path = os.path.join(HERE, "cache", "store", f"{key}.json")
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < ttl:
        with open(path) as f:
            return json.load(f)
    hits = fn(term, country)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(hits, f)
    return hits


def candidates(entry, country):
    stores = {"android": [play_search], "ios": [appstore_search]}.get(
        entry["platform"], [play_search, appstore_search])
    terms = list(dict.fromkeys(entry["search_terms"] + entry["ids_in_text"]))[:4]
    seen, out = set(), []
    for fn in stores:
        for t in terms:
            try:
                hits = cached_search(fn, t, country)
            except Exception as e:
                print(f"(search '{t}' failed: {e})", file=sys.stderr)
                continue
            for h in hits:
                if (h["store"], h["id"]) not in seen:
                    seen.add((h["store"], h["id"])); out.append(h)
    return out


# ---- 4. match --------------------------------------------------------------------
MATCH_SYSTEM = """You match a vulnerability record to real app-store listings.
You get one affected product from the record and the listings a store search returned.
- match_id: the "id" of the listing that IS the affected app, or "none" if no listing is.
  Only ids from the listings given are allowed.
- confidence: high / medium / low.
- evidence: short facts copied from the chosen listing (developer, title, developer
  site) that connect it to the record. Copy them exactly as they appear in the listing.
- related_ids: other listings from the same developer that might share the affected
  code but are NOT named in the record (e.g. a "Business" or "Lite" edition).
- version_note: if the store version and the record's versions are written in
  different formats (e.g. one drops a leading "2."), say how; else "".
The vendor in a record is often a parent company while the store shows a subsidiary;
that is fine if the developer's website or the app title connects them."""

MATCH_SCHEMA = {
    "type": "object", "required": ["match_id", "confidence", "evidence", "related_ids", "version_note"],
    "properties": {"match_id": {"type": "string"},
                   "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                   "evidence": {"type": "array", "items": {"type": "string"}, "maxItems": 5},
                   "related_ids": {"type": "array", "items": {"type": "string"}},
                   "version_note": {"type": "string"}}}


def match(entry, cands, cve, store):
    pool = [c for c in cands if c["store"] == store]
    if not pool:
        return None
    listing = [{k: c[k] for k in ("id", "title", "developer", "developer_site", "version")}
               for c in pool]
    ctx = {"product": entry["product"], "vendor": entry["vendor"], "platform": entry["platform"],
           "record_description": cve["description"], "record_reference_urls": cve["references"]}
    answers = [llm(MATCH_SYSTEM, json.dumps({"affected": ctx, "listings": L}, indent=1),
                   MATCH_SCHEMA, "match") for L in (listing, listing[::-1])]
    a = dict(answers[0])
    a["stable"] = answers[0]["match_id"] == answers[1]["match_id"]
    a["second_answer"] = answers[1]["match_id"]
    ids = {c["id"]: c for c in pool}
    a["problems"] = []
    if a["match_id"] != "none" and a["match_id"] not in ids:
        a["problems"].append(f"model chose '{a['match_id']}', which no search returned; rejected")
        a["match_id"] = "none"
    a["related_ids"] = [i for i in a["related_ids"] if i in ids and i != a["match_id"]]
    if a["match_id"] in ids:
        c = ids[a["match_id"]]
        text = json.dumps(c).lower()
        def found(ev):                    # "title: X" -> check X; the label isn't in the data
            val = re.sub(r"^\s*(title|developer|developer_site|developer site|id|version)\s*:\s*",
                         "", ev, flags=re.I)
            return val.lower() in text
        a["evidence_checked"] = [(e, found(e)) for e in a["evidence"]]
        refs = {host_root(u) for u in cve["references"]}
        a["site_matches_reference"] = bool(c["developer_site"]) and host_root(c["developer_site"]) in refs
        a["listing"] = c
    return a


# ---- 5. versions -----------------------------------------------------------------
def vt(s):
    return tuple(int(x) for x in re.findall(r"\d+", s or ""))


def verdict(entry, store_version):
    """-> (affected?, explanation).  None = can't tell."""
    bounds = [b for b in (entry["affected_from"], entry["fixed_in"], entry["affected_through"]) if b]
    sv = vt(store_version)
    if not sv:
        return None, f"store does not publish a version ('{store_version}')"
    if not bounds:
        return None, "the record gives no version range"
    note = ""
    refs = [vt(b) for b in bounds]
    if any(len(r) != len(sv) for r in refs):
        # Does the store drop k leading components that every bound shares (e.g. the
        # "2." of WhatsApp's 2.26.15.72 vs the store's 26.39.74)?  Accept only if the
        # store's first number is in the neighbourhood of the bounds' next number.
        for k in (1, 2):
            if all(len(r) == len(sv) + k for r in refs) and len({r[:k] for r in refs}) == 1:
                nxt = [r[k] for r in refs]
                if min(nxt) - 2 <= sv[0] <= max(nxt) + 10:
                    sv = refs[0][:k] + sv
                    note = (f"store {store_version} read as {'.'.join(map(str, sv))} (the store "
                            f"drops the leading {'.'.join(map(str, refs[0][:k]))}.)")
                    break
        else:
            return None, (f"version formats differ (store {store_version}, record "
                          f"{', '.join(bounds)}); not compared automatically")
    lo = vt(entry["affected_from"]) if entry["affected_from"] else None
    if lo and (sv < lo or (sv == lo and not entry["affected_from_inclusive"])):
        return False, (note + "; " if note else "") + "older than the first affected version"
    if entry["fixed_in"]:
        hit = sv < vt(entry["fixed_in"])
        return hit, (note + "; " if note else "") + \
            f"{'below' if hit else 'at or above'} the fixed version {entry['fixed_in']}"
    if entry["affected_through"]:
        hit = sv <= vt(entry["affected_through"])
        return hit, (note + "; " if note else "") + \
            f"{'at or below' if hit else 'above'} the last affected version {entry['affected_through']}"
    return None, "only a lower bound is given"


# ---- report ---------------------------------------------------------------------
def report(cve, entries, country):
    L = [f"# {cve['id']} → app stores", "", cve["description"], "",
         "References: " + ", ".join(cve["references"]), ""]
    if cve["cpes"]:
        L += ["CPEs: " + ", ".join(c["criteria"] for c in cve["cpes"]), ""]
    for e in entries:
        rng = " ".join(x for x in (
            f"from {e['affected_from']}{'' if e['affected_from_inclusive'] else ' (exclusive)'}"
            if e["affected_from"] else "",
            f"before {e['fixed_in']}" if e["fixed_in"] else "",
            f"through {e['affected_through']}" if e["affected_through"] else "") if x)
        L += [f"## {e['product']} ({e['vendor']}, {e['platform']})", "",
              f"Affected: {rng or 'no version range given'}", ""]
        L += [f"> ⚠ {w}" for w in e["warnings"]]
        for store, m in e["matches"].items():
            if m is None:
                continue
            L.append(f"### {store}")
            if m["match_id"] == "none":
                L.append(f"No listing matched (searched {len(e['cands_by_store'][store])} listings). "
                         + " ".join(m["problems"]))
            else:
                c = m["listing"]
                hit, why = verdict(e, c["version"])
                status = {True: "**AFFECTED**", False: "not affected", None: "unknown"}[hit]
                L += [f"| | |", "|---|---|",
                      f"| app | [{c['title']}]({c['url']}) |",
                      f"| package / bundle ID | `{c['id']}`" +
                      (f" ({c['store_id']})" if c["store_id"] != c["id"] else "") + " |",
                      f"| developer | {c['developer']} ({c['developer_site'] or 'no site'}) |",
                      f"| current store version | {c['version']} |",
                      f"| current version affected? | {status}: {why} |",
                      f"| match confidence | {m['confidence']}" +
                      ("" if m["stable"] else f" — ⚠ **unstable**: with the listings reversed "
                                              f"the model chose `{m['second_answer']}`") + " |",
                      f"| developer site matches a CVE reference domain | "
                      f"{'yes' if m['site_matches_reference'] else 'no'} |",
                      f"| evidence | " + "; ".join(f"{t}{'' if ok else ' ⚠(not in listing)'}"
                                                  for t, ok in m["evidence_checked"]) + " |"]
                if m["version_note"]:
                    L.append(f"| model's version note | {m['version_note']} |")
                if m["related_ids"]:
                    L.append("| related, not named in the CVE | " + ", ".join(
                        f"`{i}`" for i in m["related_ids"]) + " |")
            L.append("")
    L.append(f"_Store searches: country `{country}`. Store listings show only the current "
             f"version; neither store publishes version history._")
    return "\n".join(L)


def short(cve, entries):
    """Links first, a few words each; warnings only when something needs a look."""
    L, flags, related = [cve["id"]], [], []
    for e in entries:
        for store, m in e["matches"].items():
            if m is None:
                continue
            plat = "Android" if store == "Google Play" else "iOS"
            if m["match_id"] == "none":
                L.append(f"{plat}: no store match for {e['product']}")
                continue
            c = m["listing"]
            hit, why = verdict(e, c["version"])
            state = {True: "AFFECTED", False: "fixed", None: "version unknown"}[hit]
            ver = c["version"] if hit is not None else ""
            L.append(f"{c['url']}  {c['id']}  {ver + ' ' if ver else ''}{state}")
            related += m["related_ids"]
            if not m["stable"]:
                flags.append(f"{plat} match unstable (other answer: {m['second_answer']})")
            if m["confidence"] != "high":
                flags.append(f"{plat} match confidence {m['confidence']}")
            if not m["site_matches_reference"]:
                flags.append(f"{plat} developer site doesn't match the CVE's references")
            if hit is None and "formats differ" in why:
                flags.append(f"{plat}: {why}")
        flags += [f"{e['product']}: {w}" for w in e["warnings"]]
    if related:
        L.append("related (not named in CVE): " + ", ".join(dict.fromkeys(related)))
    L += [f"! {f}" for f in flags]
    return "\n".join(L)


def lookup(cve_id, country="us"):
    """The whole pipeline for one CVE; saves reports/<CVE>.md/.json.
    -> (cve, entries, full markdown report)"""
    cve = fetch_cve(cve_id.upper())
    entries = extract(cve)
    for e in entries:
        cands = candidates(e, country)
        e["cands_by_store"] = {s: [c for c in cands if c["store"] == s]
                               for s in ("Google Play", "App Store")}
        e["matches"] = {s: match(e, cands, cve, s) for s in ("Google Play", "App Store")}
    md = report(cve, entries, country)
    os.makedirs(os.path.join(HERE, "reports"), exist_ok=True)
    stem = os.path.join(HERE, "reports", cve["id"])
    with open(stem + ".md", "w") as f:
        f.write(md + "\n")
    with open(stem + ".json", "w") as f:
        json.dump({"cve": cve, "entries": entries}, f, indent=1, default=str)
    return cve, entries, md


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cve")
    ap.add_argument("--country", default="us")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print the full report (it is always saved to reports/)")
    a = ap.parse_args()
    cve, entries, md = lookup(a.cve, a.country)
    print(md if a.verbose else short(cve, entries))


if __name__ == "__main__":
    main()
