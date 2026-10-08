# cve2store

From a CVE ID to the Google Play package name / App Store bundle ID of the affected
mobile app, with store links, current store versions, and whether the current version
is still affected. Plus a daily job that does this for every new CVE.

**Start here: [`digests/`](digests/)**, an index of the days with mobile-app CVEs,
plus **monthly CSVs in [`data/`](data/)**: one row per app with the store link,
package / bundle ID, current store version and whether it's still affected.

```bash
.venv/bin/python cve2store.py CVE-2026-23866        # links + one line each; -v for the full report
                                                     # (full report always saved to reports/<CVE>.md/.json)
```

```bash
.venv/bin/python daily.py                    # catch up: each day since the last one done
.venv/bin/python daily.py --day 2026-10-05   # one day;  --from/--to for a range
```

## Setup

```bash
python3 -m venv .venv && .venv/bin/pip install google-play-scraper
```

- **A local LLM** behind an OpenAI-compatible API that supports JSON-schema output.
  Developed with llama.cpp's `llama-server` and Qwen3.8-27B (UD-Q3_K_XL) on a 16 GB GPU.
- **Config** in `~/.config/cve2store/*.env` (`KEY=value` lines; keep it `chmod 600`):

  | key | default | |
  |---|---|---|
  | `NVD_API_KEY` | none | [free from NVD](https://nvd.nist.gov/developers/request-an-api-key); without it, 5 requests / 30 s |
  | `LLM_URL` | `http://localhost:8090/v1/chat/completions` | |
  | `LLM_MODEL` | `coder27` | |
  | `LLM_START_CMD` | none | how `daily.py` starts the model server if it's down (it stops it again afterwards) |
  | `LLM_GPU_GUARD` | `1` | defer the day if another program holds >1 GB of GPU memory (e.g. a long render) |
  | `PUSH` | `1` | `run_daily.sh`: push the digest commit (`0` = commit only) |

## Run it every day

`run_daily.sh` catches up, then commits and pushes new digests; logs go to `logs/`.

```
crontab -e
0 6 * * *  /path/to/cve2store/run_daily.sh
```
(06:00 local is after midnight UTC, so yesterday's NVD day is complete.)

## The daily job

For each day: every CVE NVD published; each CVE's own cve.org record (affected
products and platforms arrive there long before NVD adds CPEs); a cheap filter for
Android/iOS mentions; the model classifies **mobile app**, **platform** (OS, kernel,
firmware, chipsets: skipped) or **not mobile**; the store lookup runs on the apps.
State is kept in `cves.sqlite`; a day is marked done only if every step succeeded,
so failed runs are retried by the next catch-up.

## How it works: the model proposes, the code verifies

1. **Fetch** the CVE record (cve.org API) and CPEs (NVD API, optional).
2. **Extract (LLM):** per affected product, platform, store search terms, likely
   developer names, version range. Versions and IDs it returns must appear verbatim in
   the record or they are dropped; it is told never to supply IDs from memory.
3. **Search (code):** App Store via the iTunes Search API; Google Play by reading the
   search page for app IDs (the scraper loses the featured hit's ID), then details via
   `google-play-scraper`.
4. **Match (LLM):** which real listing is the affected app, or none; evidence; other
   listings from the same developer as "related, not named in the CVE".
5. **Check (code):** the chosen ID must be one the search returned; quoted evidence must
   be in the listing; the developer website is compared with the CVE's reference
   domains; versions are compared in code, normalising a dropped leading component
   (WhatsApp's store `26.39.74` = `2.26.39.74`), and refusing to guess when the
   formats can't be reconciled.

**Repeatability:** temperature 0, top-k 1, fixed seed, thinking off, a JSON schema
per call, and llama.cpp with `--parallel 1`. The match is asked twice with the
listings in opposite orders, and the report flags disagreement. LLM answers are
cached in `cache/`, so re-running a CVE gives the same report.

## Limits

- Stores show only the **current** version, never history.
- Google Play often hides the version of big apps ("Varies with device"), so those
  are reported as unknown.
- Store search is per country (`--country`, default `us`).
- The daily filter only sees CVEs that mention Android/iOS somewhere in the record.
  An app CVE that names neither platform (nor has CPEs yet) is missed.
- Google Play has no official search API; the store lookup reads public pages and
  may break when they change.
- The model is Qwen3.8-27B at ~3-bit (UD-Q3_K_XL); the checks above exist so its
  mistakes are caught, not trusted.
