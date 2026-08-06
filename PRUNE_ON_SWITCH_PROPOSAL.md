# Prune-on-Switch — Proposal

> **Status:** Implemented. `prune_dind_images()` lives in `arvo_tools.py` and is
> called from `conduct_run` in `agent_tools.py`; tests are in `test_arvo_tools.py`.
> The optional `cleanup_dind -v` change was deliberately skipped — anonymous
> volumes are not accumulating. The optional `CARO_PRUNE_DIND` toggle was not
> added; the prune always runs.

A plan to stop `rootainer`'s inner Docker storage from filling up over the course
of a campaign by pruning stale ARVO images, while preserving the image cache for
the runs that actually benefit from it.

## Background — why disk fills up

`rootainer` is a Docker-in-Docker (DinD) container: it runs its own inner docker
daemon, and each experiment stands up the ARVO image as `vulnscan` *inside* it.
The per-run lifecycle in `agent_tools.py`/`arvo_tools.py` is:

- `standby_dind()` → `docker exec rootainer docker run --name vulnscan
  n132/arvo:<id>-vul …`. This is a plain `docker run` (default `--pull missing`),
  so it **pulls the image only if it isn't already cached** in rootainer's inner
  docker. ARVO images are multi-GB (full build toolchain + sanitized build +
  reproducer).
- `cleanup_dind('vulnscan')` → `docker exec rootainer docker rm -f vulnscan`.
  This removes the **container only** — never the image.

Because the image is never removed, each distinct vuln id leaves a large image
behind in rootainer's inner `/var/lib/docker`. Since different vulns are different
projects with little layer sharing, they don't dedupe. After several runs the
inner storage fills and the next `docker run`/`docker pull` fails.

Note the cache is not pure waste: **re-running the same vuln reuses its cached
image** (no re-download). This matters most for usage-limit resumes, which re-run
the same id after the limit resets. So the goal is not "delete all images" but
"keep the one we're likely to reuse next, drop the rest."

## Mechanism — stateless "keep current, prune the rest"

At the **start of each run**, query rootainer's inner docker for resident
`n132/arvo:*` images and `docker rmi` every one whose tag doesn't belong to the
current vuln.

This is deliberately **stateless** rather than remembering the previous vuln id in
a variable, because `caro.py` runs as a fresh subprocess per run (the runner
re-invokes it each time), so in-memory state does not survive between runs.
Deriving the prune set from what's actually resident:

- produces exact prune-on-switch behavior — a same-vuln resume keeps its cached
  image; a switch to a new vuln drops the old one;
- is self-correcting — the first run after this ships clears the entire existing
  backlog (keeping only that run's image), fixing current disk pressure
  immediately;
- needs no state file, no cross-run coordination.

## Files affected

| File | Change | Approx size |
|---|---|---|
| `arvo_tools.py` | New `prune_dind_images()` helper (optionally add `-v` to `cleanup_dind`'s `docker rm`) | ~15 lines |
| `agent_tools.py` | One call to the helper inside `conduct_run`, plus the import | ~2 lines |
| `test_arvo_tools.py` | Unit test for the helper with mocked docker calls | ~30 lines |

No changes to `run_experiments.py`, `caro.py`, the database, or the ledger — the
feature lives entirely in caro's docker-lifecycle layer, so the runner stays
unaware of it.

## Change 1 — `arvo_tools.py`: the helper

A new function alongside `cleanup_dind` / `standby_dind`, using the same
`run_command`, best-effort style:

```
prune_dind_images(keep_vuln_id, rootainer_name='rootainer', keep_flags=('vul', 'fix')):
    # 1. list resident arvo images in the inner docker:
    #    docker exec rootainer docker images n132/arvo --format '{{.Repository}}:{{.Tag}}'
    # 2. keep-set = {f'n132/arvo:{keep_vuln_id}-{flag}' for flag in keep_flags}
    # 3. for each resident tag not in keep-set:
    #    docker exec rootainer docker rmi -f <tag>   (check=False, log warnings)
```

Key details:

- **Enumerate-and-exclude, not blanket `prune -a`.** A plain
  `docker image prune -a` would delete the current vuln's image too — at this
  point its container has already been removed, so nothing references the image —
  which would defeat the resume-cache benefit. The explicit keep-list is what
  makes this "prune-on-switch" rather than "prune-everything."
- **`--format '{{.Repository}}:{{.Tag}}'`** on the `n132/arvo` repo yields clean
  tags to compare against, avoiding fragile table parsing.
- **Keep both `-vul` and `-fix` of the current id** defensively. The campaign path
  only pulls `-vul`, but other code paths (`get_original`, `load_container`) can
  pull `-fix`, so this avoids surprising re-pulls.
- **Best-effort**: `check=False` + warning logs, mirroring `cleanup_dind`, so a
  docker hiccup never fails the run.

Optional secondary change in the same file: add `-v` to `cleanup_dind`'s
`docker rm -f vulnscan` (→ `docker rm -f -v`) so anonymous volumes are removed with
the container. Only worthwhile if `docker system df` shows volumes accumulating —
measure first.

## Change 2 — `agent_tools.py`: the call site

`conduct_run`'s current startup sequence:

```
cleanup_dind('vulnscan')                 # remove any leftover container
standby_dind('vulnscan', vuln_id=...)    # pulls the image if absent, starts it
```

Insert the prune **between** these two:

```
cleanup_dind('vulnscan')
prune_dind_images(vuln_id)               # NEW: drop stale images, keep current vuln's
standby_dind('vulnscan', vuln_id=...)
```

Why exactly here:

- **After `cleanup_dind`**: the container is already gone, so `rmi` on stale images
  is clean (nothing references them).
- **Before `standby_dind`**: frees disk *before* the new image is pulled, so peak
  usage stays low — you never need room for the old and new images at once.
- `vuln_id` is already in scope, so it's a one-liner plus the import.

The end-of-run `cleanup_dind('vulnscan')` in the `finally` block stays exactly as
is (removes the container, keeps the current image cached for a possible resume).
Pruning happens only at the *start* of the next run.

## Change 3 — `test_arvo_tools.py`: unit test

Testable without a live rootainer by mocking the docker calls (the module shells
out through `run_command`/`subprocess.run`):

- **Prunes the right things**: given a faked `docker images` output listing
  `[A-vul, B-vul, C-vul]` with `keep_vuln_id=B`, assert `rmi` is invoked for
  `A-vul` and `C-vul` and **not** for `B-vul`.
- **Resume case**: resident `[B-vul]`, `keep_vuln_id=B` → no `rmi` calls.
- **Empty case**: no resident images → no-op, no error.
- **Best-effort**: a failing `rmi` (non-zero return) does not raise.

## Resulting behavior

- **Steady state ≈ one image resident** (the current vuln's), so disk stays flat
  across a long campaign of distinct ids.
- **Self-healing**: the first run prunes the entire existing backlog.
- **Usage-limit resumes stay cheap**: the runner pauses on a limit and resumes the
  *same* vuln next, so `prune_dind_images(same_id)` keeps that image and the resume
  reuses it — no re-download.
- **Lower peak disk**: freeing before pulling means never holding two big images at
  once.

## Considerations and edge cases

- **Serial-execution assumption.** Safe because the runner's lockfile guarantees one
  campaign at a time and caro runs serially, so no other run is using an image when
  the prune fires. A *manually* launched concurrent caro run could make the prune
  target an in-use image — docker refuses to remove an image with a live container,
  so the worst case is a logged warning, not breakage. Worth a one-line caveat in
  the helper's docstring.
- **Data safety is not a concern.** Results are streamed to the host-side log and
  parsed before the next run starts, so pruning at the start of a subsequent run
  cannot affect any prior run's captured results.
- **A trailing image lingers.** After a campaign's final run, that last image stays
  resident until the next run prunes it — acceptable, and clearable manually with
  `docker exec rootainer docker image prune -af`.
- **Optional toggle.** Some setups have ample disk and prefer a warm cache. Consider
  gating the prune behind an env var (e.g. `CARO_PRUNE_DIND`, default on) or an
  `experiment_setup.json` field, so it can be disabled without code changes. Not
  required.
- **Volumes are secondary.** The primary consumer is images; pursue the
  `cleanup_dind -v` / `docker volume prune` angle only if `docker system df`
  confirms volumes are growing.

## Verification steps

1. Baseline `docker exec rootainer docker system df` to record image count/size.
2. Run vuln A, then vuln B; confirm A's image is gone and only B's remains after B
   starts.
3. Simulate a resume (same id twice); confirm the image is **not** re-pulled the
   second time.
4. Re-check `system df` across several runs to confirm the count stays flat rather
   than climbing.
