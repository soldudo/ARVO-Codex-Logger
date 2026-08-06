# CARO Campaign Cheatsheet

Enqueue → run → check → fix. Full docs: `RUN_EXPERIMENTS.md`, `LEDGER.md`.

## One-time setup

```bash
# clone the shared ledger (omit --remote for a local-only ledger)
python ledger.py init --ledger-dir ~/repos/caro-ledger \
    --remote git@github.com:soldudo/caro-ledger.git

# make the ledger settings permanent
cat >> ~/.bashrc <<'EOF'

# CARO ledger configuration
export CARO_LEDGER_DIR="$HOME/repos/caro-ledger"
export CARO_LEDGER_MACHINE="nico_splab"
EOF
source ~/.bashrc
```

`CARO_LEDGER_DIR` turns on automatic ledger reporting after every run.
`CARO_LEDGER_MACHINE` names this machine in the ledger (defaults to the hostname).

## Enqueue

By explicit ids:

```bash
python run_experiments.py enqueue --campaign full-md-pairs-jul25-1 \
    --experiment-tag discrete-loc-patch-pairs-fullmd \
    --loc-mode --patch-mode --ids 42541443
```

By coverage gaps — picks vulns nobody on the team has run under this tag, and
claims them so other machines skip them:

```bash
python run_experiments.py enqueue --campaign baseline-fill-jul23-1 \
    --experiment-tag baseline-patch-envmd --patch-mode \
    --fill-gaps 2 --project ffmpeg --id-min 42536326
```

| flag | meaning |
|---|---|
| `--campaign` | unique campaign tag; add to an existing one with `--append` |
| `--experiment-tag` | must exist in the `experiments` table; fixed at creation |
| `--loc-mode` / `--patch-mode` | at least one required. use both flags for pair runs |
| `--ids` / `--ids-file` / `--fill-gaps N` | pass ids individually or by file, or automatically fill gaps |
| `--project` / `--id-min` / `--id-max` | narrow `--fill-gaps` candidates by project or min/max arvo_id |
| `--retry-failed` | let `--fill-gaps` re-pick vulns whose only runs failed |

Preview what a gap-fill would choose without enqueueing anything:

```bash
python ledger.py gaps --tag baseline-patch-envmd --count 2 --project ffmpeg
```

## Run

```bash
nohup python run_experiments.py run --campaign full-md-pairs-jul27-1 > campaign.log 2>&1 &
```

Waits out usage-limit resets and resumes cut-off sessions on its own. Safe to
kill and re-invoke at any point — state lives in `arvo_loc_runs.db`.

| flag | meaning |
|---|---|
| `--max-runs N` | stop after N caro invocations this session |
| `--no-wait` | exit instead of sleeping when a usage limit blocks progress |
| `--run-timeout N` | per-run seconds (default 5400); a hung run is killed and marked `error` |
| `--max-attempts N` | give up on an item after N usage-limited attempts (default 4) |

## Check

```bash
python run_experiments.py status --campaign baseline-fill-jul22-4   # per-item table
python run_experiments.py list                                      # all campaigns
python ledger.py coverage --tag baseline-patch-envmd                # team-wide coverage
```

Statuses: `pending` → `running` → `complete` | `usage_limited` (auto-resumes) |
`error`.

## Fix

Retry everything that errored:

```bash
python run_experiments.py requeue --campaign baseline-fill-jul22-4 --status error
nohup python run_experiments.py run --campaign baseline-fill-jul22-4 > campaign.log 2>&1 &

```

`--ids <id> ...` limits the requeue to specific vulns; `--status complete --ids <id>`
re-runs a finished vuln. A requeued item starts fresh — it does **not** resume its
old session.

| problem | fix |
|---|---|
| "Another runner appears to be active" but none is | `rm runs/.run_experiments.lock` |
| runner killed mid-run | just re-run `run`; stale `running` items self-heal on startup |
| item stuck in `error` | `status` shows the reason in the detail column; fix, then requeue |
| limit hit under `--no-wait` | re-run `run` after the printed reset time |
| rootainer out of disk | `docker exec rootainer docker system df`; stale arvo images are pruned automatically at each run's start, so a hard clear is `docker exec rootainer docker image prune -af` |
| ledger looks stale | `python ledger.py report` (reporting is idempotent and offline-tolerant) |

Logs: `campaign.log` (this session), `run_experiments.log` (all runner activity),
`runs/<run_id>/agent_<run_id>.log` (per agent run).
