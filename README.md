# cve2store

From a CVE ID to the Google Play package name / App Store bundle ID of the affected
mobile app, with store links, current store versions, and whether the current version
is still affected.

```bash
.venv/bin/python cve2store.py CVE-2026-23866        # report printed + reports/<CVE>.md/.json
```

Needs coder27 (llama.cpp on :8090; `systemctl --user start coder27`). Override with
`LLM_URL` / `LLM_MODEL` for another OpenAI-compatible server.

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
- The model is Qwen3.8-27B at ~3-bit (UD-Q3_K_XL); the checks above exist so its
  mistakes are caught, not trusted.
