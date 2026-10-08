#!/usr/bin/env bash
# run_daily.sh -- for cron: catch up on new days, then commit and push the digests.
#
#   crontab -e, then e.g. (06:00 local, after midnight UTC so yesterday is complete):
#   0 6 * * *  /path/to/cve2store/run_daily.sh
#
# Logs to logs/daily-YYYY-MM-DD.log. Set PUSH=0 in ~/.config/cve2store/*.env to
# commit without pushing.
set -u -o pipefail
cd "$(dirname "$(readlink -f "$0")")"
mkdir -p logs
LOG="logs/daily-$(date +%F).log"
for f in ~/.config/cve2store/*.env; do [ -f "$f" ] && set -a && . "$f" && set +a; done
{
  echo "=== $(date '+%F %T') start"
  .venv/bin/python -u daily.py
  rc=$?
  git add digests reports data
  if ! git diff --cached --quiet; then
    git commit -q -m "digests: $(git diff --cached --name-only digests | xargs -r -n1 basename | sed 's/\.md$//' | paste -sd, -)"
    [ "${PUSH:-1}" = 1 ] && git push -q && echo "pushed"
  fi
  echo "=== $(date '+%F %T') end (daily.py rc=$rc)"
} >> "$LOG" 2>&1
