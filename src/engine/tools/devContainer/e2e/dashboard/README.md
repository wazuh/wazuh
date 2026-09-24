# Dashboard E2E — reproducible captures with Playwright

Screenshots of the Wazuh dashboard that are **evidence**, not decoration: every view is asserted
against the data of the run that produced it — the agents `global.db` reports as active, an event
carrying a nonce minted for this run, **one concrete package (name and version) sampled from the
indexer for this run's 5.x agent**, **one concrete CVE of that same agent** — and the proof is
**one row of the view's table, matched column by column with exact equality**, in a screenshot of
the **whole page**. A dashboard rendering stale, empty, foreign or merely *similar* data, or
silently ignoring the filter it was given, cannot produce a green run.

The script prints the same parseable grammar as `../wazuh_verify_manager.sh` and
`../agents/verify_agents.sh`, so an evidence package can consume it unchanged.

```
dashboard/
├── capture.py             the CLI: checks, browser session, PNGs, sidecars, captures.md
├── capture_logic.py       the decisions (pure functions: no I/O, no network, no Playwright)
├── test_capture_logic.py  unit tests of those decisions (143 tests, no network, no browser)
├── test_capture_dom.py    DOM tests of the extraction scripts (14 tests, a real Chromium on
│                          HTML fixtures; SKIPped without the venv)
├── views.json             per view: route, landing, table, selectors, query, assertions
└── README.md              this file
```

## What v4 changed (design D-8b / D-9b / D-10b)

The three rounds of review of this tool all failed on the same three things — a view "landed" by
substring, a row "matched" by tokens, and a credential that could still be printed — so v4 replaces
each of them with something a wrong page cannot satisfy:

| v3 | v4 |
|---|---|
| `row_text: [...]` — every value somewhere on the same row, as a whole token | `row: {"<column>": "<value>"}` — **exact equality per column**, **exactly one** matching row, inside the frame (v6: measured and noted, not a verdict — see below), in **exactly one** table of the scope |
| `hits_min` / `count_min` — at least N, counter looked up page-wide | `rows_eq: N` (exact number of data rows) and `hits_eq: N` (counter resolved **inside the scope**, unique, exact) |
| `url_must_contain: ["tabView=software", …]` — substrings of the whole decoded URL | `landing: {path, hash_route, hash_params, state}` — same **origin**, exact path, exact `#` route, every `#` parameter **equal**, every `state` entry compared inside the parsed rison of **its own** parameter (v8: exact, never a substring) |
| credentials redacted after `json.dumps`, header printed outside the Reporter | credentials in `--dashboard-url`/`--indexer-url` **refused** (`FAIL 0.`), `redact_obj()` **before** serializing, and a static test that no `print(` of `capture.py` lives outside `class Reporter` |
| `--agent-5x-id 001` accepted any active agent | the override must be active **and** `v5*`, else `FAIL 3.` |
| provenance = HEAD + sha256 of `git diff` | provenance = **sha256 of each source that ran** (`capture.py`, `capture_logic.py`, `views.json`, `--views-file`) + `git status --porcelain` |
| the manifest was written after the summary | the manifest is written **before** the summary; a failure is `FAIL 10. manifest`, counted, and the exit status follows the count |

## What v5 changed (fourth review)

| v4 | v5 |
|---|---|
| `--out` emptied whatever it was pointed at, as root | it is emptied **only** when every entry in it is one of this tool's own (`NN-<view>[-FAIL].png/.json`, `captures.md`), and `/`, `$HOME`, anything inside the checkout and any path with fewer than 2 components are **refused** before being read (see Safety) |
| the three extraction scripts had no automated cover at all | `test_capture_dom.py`: a real Chromium over HTML fixtures copied from the measured DOM |
| the frame was vertical only, and a cell cut with `…` still passed | every cell reports `left`/`right`/`truncated`, on both axes (in v5 an asserted column outside the viewport or truncated was a FAIL; **v6 turned that into a note** — see below) |
| `state` was a substring of the decoded rison | it is compared against the parameter's own `query:(language:kuery,query:'…')`, exactly: a filter's `meta.alias` label no longer passes for the view's query |
| `--agent-ids 001` could still report `5x=002` | the 5.x agent is picked **among** the requested ids |
| the sidecar of a FAIL always said `api_request_calls.total: 0` | the session's real counters are written on both paths |
| `--out` that could not be created was a `#` note; the manifest's own `listdir` was silent | both are counted (`FAIL 0.` / `FAIL 10.`) |
| `| dashboard | 5.0.0-latest |` was a constant | the version is read from an authenticated `GET /api/status`, or printed as `declared 5.0.0-latest` |
| the route rendered its values raw (`g++` came back as `g  `) | values are percent-encoded into the route, and check 4b samples a package with **exactly one** document |
| `pip install playwright` | `pip install playwright==1.63.0` |

## What v6 changed (decision V11)

> Cropping the screenshot is not a requirement: a good-quality capture of the whole page is enough
> (decision V11, 2026-09-20).

| v5 | v6 |
|---|---|
| `page.screenshot(full_page=False)` — the PNG was the 1280×800 viewport | **`full_page=True`**: the **viewport stays 1280×800** and the PNG comes out at whatever the page occupies — measured `1283×1064` for IT Hygiene and `1280×800` for the agents and Discover views (in each run's `captures.md`), which is why the size is **read from each file** and never promised |
| a matched row outside the viewport was `FAIL … row outside the frame …` / `column <c> outside the frame …` | the row is **still measured** on both axes, and the answer is reported as `frame_note.in_viewport` |
| an asserted column drawn truncated (`Ubuntu Develop…`) was `FAIL … column <c> truncated in frame` | it is reported as `frame_note.truncated_columns`, next to the value that was compared |
| — | both travel to the **sidecar** (`assertions[].frame_note`) and to the **PASS line** and the manifest (`…; frame: in_viewport=false, truncated=[package.vendor]`) |
| `captures.md` listed `fichero / bytes / sha256` | it lists `fichero / sha256 / tamaño / WxH`, the pixel size **read from each PNG's own IHDR header** (`capture_logic.png_size`) — a full-page height is not a constant anybody may assume |

Why cropping is no longer a requirement: the frame check existed because a capture that stopped at
the fold could not show a row drawn below it, so "the proof is in the PNG" had to be enforced by
failing the view. A full-page capture shows whatever the *document* holds below the fold or past
the right edge (with the limit stated in the next paragraph), so the same measurement becomes **information** about the layout — worth writing down (a column cut with `…`
means the pixels show less than the text the assertion compared), never a verdict. What still
proves a view is untouched (D-8b): the **exact row, column by column, exactly once**, in exactly
one table of the scope, on a page that landed where it was asked to.

What `full_page=True` does **not** promise: it grows the capture to the size of the *document*, so
content that only scrolls **inside a container** (a virtualised `euiDataGrid` body, a panel with its
own `overflow`) is still photographed as that container was drawn — a row the grid has not rendered
yet is in neither the DOM nor the PNG. That is why the framing measurement is kept and reported
(`frame_note`) instead of dropped: it is the informative part (V11), and the verdict remains the
per-column match over the rows that were really read.

## What v7 changed (fifth review)

| v6 | v7 |
|---|---|
| `--out` resolved with `abspath`, so `/tmp/alias -> <checkout>/out` escaped the refused roots | `--out`, `$HOME`, `$WAZUH_REPO` and the script's `git rev-parse --show-toplevel` are all **canonicalised** (`os.path.realpath`) before being compared |
| exclusivity was judged by **name**, and a `captures.md` **directory** was removed with `shutil.rmtree` | it is judged by name **and kind**: every entry must be a **regular file** with an artifact's name, or `FAIL 0. setup (got: out dir not exclusive: captures.md (dir))` and nothing is deleted. Removal is `os.remove` on those files — there is **no recursive delete left in `capture.py`** (a unit test greps for it) |
| the `state` clause was found with a regex at **any depth** (`metadata:(query:(…))` satisfied it) and only `got[0]` was read | the rison is **parsed** (`parse_rison`) and the kuery is read from the **root's own** `query:(language:kuery,query:'…')` (`root_kuery`); a state parameter carried **twice** is `duplicated state parameter _a` |
| `vd` asserted `hits_eq: 1` only | `vd` asserts `rows_eq: 1` too, like `discover` and `inventory`: a grid holding the right finding **and** a foreign one no longer passes with a counter reading 1 |
| an artifact the manifest could not read left a loud row under `failed=0`, `rc=0` | every read/hash/size error is accumulated and counted: `FAIL 10. manifest (got: unreadable: 08-inventory.json (PermissionError))`, before the summary, `rc=1` |
| the README promised "1280 px wide" | the **viewport** is 1280×800 and the PNG is whatever the page occupies (measured `1283×1064`), read from its IHDR header |

## What v8 changed (sixth review)

| v7 | v8 |
|---|---|
| a `state` entry that was not `query:'…'` (Discover's `indexPattern:'wazuh-events-v5*'`) only had to **appear** in the rison text, so `metadata:(indexPattern:'wrong-index'),decoy:(indexPattern:'wazuh-events-v5*')` passed | it is declared as the **path** it lives at, `metadata.indexPattern:'wazuh-events-v5*'`, and compared with **exact equality** against that path of the **parsed** rison, from its root (`rison_path`): a decoy, a prefix (`wazuh-events-v5`) or a longer pattern is `#_a without metadata.indexPattern:'wazuh-events-v5*'`; an entry of any other shape is `unsupported state entry` — no substring rule is left |
| the manifest reused the sha256 cached when the view passed, and `png_dimensions` turned an `OSError` into `—`: a PNG that could not be opened any more published with `failed=0`, `rc=0` | every file of the 'Every file' table is **read again at publication** (sha256 and IHDR); an `OSError` is `FAIL 10. manifest (got: unreadable: 08-inventory.png (PermissionError))` and bytes that are not the ones hashed then are `changed since capture: …`, both before the summary |
| the README promised the matched row "is in the PNG either way" | it does not: `full_page=True` grows the capture to the document, not to a container that scrolls on its own (see v6 and Limitations) |


## What v9 changed (review of the branch)

| v8 | v9 |
|---|---|
| publication re-read only the files `listdir` returned: a PNG or sidecar that vanished after its view passed left no trace and the run could still end `failed=0` | every artifact the run produced (each hashed PNG, its sidecar, each captured file) must still exist: otherwise `FAIL 10. manifest (got: missing since capture: <file>)` and a `(missing)` row |
| with `--exec-docker --nonce <reused>` the index count accepted the previous run's document at once, and it did not check which agent sent it | the nonce must be **absent** from the events index before this run writes it (else `FAIL 4 … already indexed … use a fresh --nonce`), and check 4 counts only documents with `wazuh.agent.id` = the chosen 5.x agent |

## Prerequisites

- **root**: `queue/sockets/vd-http.sock` is `0660` and `queue/db/global.db` is not world readable.
- The indexer + dashboard stack up (`../docker-compose.yml`, project `dev-env-engine`: `443`, `9200`)
  and a manager installed at `--home` (7/7 daemons).
- Real agents enrolled (`../agents/README.md`), **including one 5.x agent**: its id, its name, its
  inventory and its findings are what the `inventory` and `vd` views are asserted against.
- The venv, created once: `python3 capture.py --setup`. It lives outside the repo
  (`${DASHBOARD_VENV:-$WORKSPACE/venv-dashboard}`, `$WORKSPACE` = the parent of the checkout), so a
  capture run never leaves anything under `git status`. `--setup` creates it, installs
  **`playwright==1.63.0`** (pinned: this tool asserts layout, and layout moves with the browser —
  every live run so far used 1.63.0 / chromium-1243) and runs `playwright install chromium --with-deps`, which **installs system packages with `apt`** —
  this is the only mode of the script that installs anything; if `--with-deps` fails it retries
  without it and prints the `apt` command that was missing. It then **launches chromium once**
  (headless, `about:blank`): an installed browser that cannot start must not look like a successful
  setup, so it ends either with `# chromium launch: ok` or with
  `FAIL  0. setup (got: chromium launch failed: …)` and a non-zero exit status.
- Credentials come from the environment **only**: `DASHBOARD_USER` / `DASHBOARD_PASSWORD` and
  `INDEXER_USER` / `INDEXER_PASSWORD` (the demo stack ships `admin`/`admin` hardcoded in the indexer
  image). A `https://user:pass@host` in `--dashboard-url` or `--indexer-url` is **refused**
  (`FAIL 0. setup (got: credentials in --dashboard-url are not accepted; use
  DASHBOARD_USER/PASSWORD)`), because such a value is not in the redaction list and the header, the
  manifest and every sidecar would print it. TLS is not verified (`ignore_https_errors`,
  self-signed lab certificates).

Any invocation re-executes itself inside the venv (`os.execv`) before importing Playwright, so
`python3 capture.py …` with the system interpreter is the normal way to run it.
`PLAYWRIGHT_BROWSERS_PATH` is **set** (not defaulted) to `<venv>/browsers` on both paths — already
inside the venv and after the re-exec — or to `--browsers-path`.

## Safety (what this script can and cannot do to your machine)

- **No shell.** `--exec-docker` runs the argv
  `docker exec -i <container> sh -c 'cat >> /var/log/dpkg.log'` and feeds the nonce line through
  **stdin**; nothing from the command line is interpolated into a shell program. `--nonce` must match
  `^e2e-capture-[A-Za-z0-9._-]{4,32}$` and `--agent-container` `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`,
  or check 4 fails with the reason and nothing is executed. The log path is a constant, not a flag.
- **No credential is ever printed or written.** Credentials come from the environment (one in a URL
  is refused outright); the login wraps every step and reports only the exception *type* and the
  step name (Playwright's own error text quotes the value it was told to fill, i.e. the password);
  **every** line of stdout is printed by `Reporter`, which redacts it — a unit test parses
  `capture.py` and fails if a single `print(` lives outside that class — and every object is passed
  through `capture_logic.redact_obj()` **before** `json.dumps`, so a password containing a quote
  cannot survive as `s\"ecret`.
- **`--out` is emptied, so it is guarded twice.** Both the target and the roots it must stay out
  of are **canonicalised** (`os.path.realpath`) first, so a symlink is not a way around the list.
  The run refuses outright — `FAIL 0. setup (got: --out refuses <path>: <reason>)`, before reading
  the directory at all — the filesystem root, `$HOME`, anything inside `$WAZUH_REPO` or the
  checkout this script lives in (`/tmp/alias -> <checkout>/out` included: the reason names the
  **resolved** path), and any path with fewer than two components (`/tmp`). Then it looks inside:
  the directory is emptied **only if every entry in it is a regular file this tool wrote**
  (`NN-<view>[-FAIL].png`, `NN-<view>.json`, `captures.md`) — the **kind** is read from the
  filesystem, because a *directory* called `captures.md` and a *symlink* called `06-agents.png`
  wear an artifact's name and are somebody else's. Anything else and **nothing is deleted** —
  `FAIL 0. setup (got: out dir not exclusive: captures.md (dir), precious.txt (file))`, up to three
  entries with their kind — and not even the manifest is written into it. What is deleted is
  deleted with `os.remove`, file by file: **there is no recursive delete in `capture.py`**, on any
  path, and a unit test greps the source to keep it that way.
- **Read-only** on the manager, the indexer and the dashboard. Besides `--out`, the single write
  it can make is the nonce line inside the agent container, and only with `--exec-docker`.

## Usage

```bash
WORKSPACE=$(dirname "$WAZUH_REPO"); D=$WAZUH_REPO/src/engine/tools/devContainer/e2e/dashboard
sudo python3 $D/capture.py --setup                        # once (installs apt deps)
sudo python3 $D/capture.py --views agents,discover,inventory,vd --exec-docker
(cd $D && python3 -m unittest -v test_capture_logic)      # the decision logic, no stack needed
(cd $D && $WORKSPACE/venv-dashboard/bin/python -m unittest -v test_capture_dom)  # the DOM
```

### Tests

| suite | interpreter | what it covers |
|---|---|---|
| `test_capture_logic.py` (143) | any `python3` | every decision: the plan, the landing (including the rison parser, the root query clause, the exact `metadata.indexPattern` path and a duplicated `_a`), the row matcher, the frame note, the counter, the verdicts, the `--out` guard (refused roots through a symlink, exclusivity by name **and** kind), the manifest's counted failures (a PNG that cannot be re-read at publication included), the pixel size of a PNG, the `full_page=True` of `shoot()`, the orchestration and the report — with a fake page and a temporary directory, no network, no browser, no manager |
| `test_capture_dom.py` (14) | the venv's (`$WORKSPACE/venv-dashboard/bin/python`) | the three **extraction scripts**, in a real headless Chromium (`--no-sandbox`) over HTML fixtures copied from the measured DOM (probes probe-columns and probe-canvas, 2026-09-20): column identity by `left` and by `<th>` position, the visible text minus `.euiScreenReaderOnly`, `left`/`right`/`truncated`, `ambiguous table (2)`, `table missing`, `scope missing`. Nothing is fetched: only `page.set_content()`. With any other interpreter every test **SKIPs** (`playwright not importable …`), never errors |

Both suites read `views.json`, so the fixtures are asserted through the **real selectors of the
views**: a scope or a table that moves there fails here first.

Output (stdout, one line per check):

```
# capture.py — 2026-09-20T16:04:11Z — https://localhost:443
# run_id: 20260920T160411Z-e2e-capture-1a2b3c4d
# out: /workspaces/.../e2e-dashboard-out/20260920T160411Z-e2e-capture-1a2b3c4d
PASS  1. indexer cluster health (got: green)
...
PASS  4b. inventory sample (got: agent 002: package wget 1.21.4-1ubuntu4 in wazuh-states-inventory-packages*)
PASS  8. inventory (got: app=it-hygiene url=… (row={'wazuh.agent.name': 'agent-5x-ubuntu', 'package.name': 'wget', 'package.version': '1.21.4-1ubuntu4'}; rows_eq=1; hits_eq=1; frame: in_viewport=true, truncated=[]))
# manifest: /workspaces/.../e2e-dashboard-out/20260920T160411Z-e2e-capture-1a2b3c4d/captures.md
# summary: executed=10 passed=10 failed=0 skipped=1
```

`executed` counts PASS + FAIL, SKIP is counted apart and never hides a check, and the exit status is
`0` iff `failed=0`. Each check runs inside its own `try/except`: an unexpected error becomes
`FAIL n. … (got: <exception>)` and the run still reaches its summary. The **manifest is written
before the summary**, so a manifest that could not be written is `FAIL 10. manifest (got: OSError)`
— counted, inside the summary and reflected in the exit status.

## Flags

| Flag | Default | What it does |
|---|---|---|
| `--setup` | — | create the venv, install `playwright==1.63.0` + its chromium (**apt**), exit |
| `--venv DIR` | `${DASHBOARD_VENV:-$WORKSPACE/venv-dashboard}` | venv holding playwright and its browsers |
| `--browsers-path DIR` | `<--venv>/browsers` | value forced into `PLAYWRIGHT_BROWSERS_PATH` |
| `--out DIR` | `$WORKSPACE/e2e-dashboard-out/<run_id>` | PNGs, sidecars and `captures.md` (not tmpfs). Without the flag, **one directory per run** (`<ISO compact>-<nonce>`); with an explicit directory its contents are **emptied** first — but only if the **resolved** path is not refused outright and **every entry in it is a regular file this tool wrote** (name *and* kind — see Safety), otherwise nothing is deleted and the run aborts (`FAIL 0. setup (got: --out refuses …)` / `(got: out dir not exclusive: captures.md (dir))`). A file that cannot be removed, a directory that cannot be listed or one that cannot be created aborts it too (`out dir not cleared: …`, `cannot create …`), rather than let a previous PNG pass for this run's |
| `--views a,b` | `agents,discover,inventory,vd` | which views to capture |
| `--dashboard-url URL` | `https://localhost:443` | dashboard under test; **credentials in the URL are refused** (`FAIL 0.`) |
| `--indexer-url URL` | `https://localhost:9200` | indexer queried for counts and samples; credentials in the URL are refused too |
| `--home DIR` | `/var/wazuh-manager` | installed manager (`global.db`, `vd-http.sock`) |
| `--agent-container NAME` | `wazuh-agent-5x-ubuntu` | container the nonce line is appended in (validated) |
| `--agent-ids 001,002` | every active agent of `global.db` | ids to filter by; **each one must be active in `global.db`** or check 3 fails naming it |
| `--agent-5x-id 002` | the first `v5` agent **among `--agent-ids`** | id behind `{{agent_id_5x}}`; must be **active AND a v5 agent**, and must belong to `--agent-ids` — `--agent-5x-id 001` on a 4.x agent is `FAIL 3. active agents (got: --agent-5x-id 001 is not an active 5.x agent (v4.14.3))`, and `--agent-ids 001` alone is `(got: no active 5.x agent among --agent-ids 001)` instead of quietly driving the views with an agent nobody asked about |
| `--inventory-index PAT` | `wazuh-states-inventory-packages*` | index the package sample of check 4b comes from |
| `--events-mode agents\|benchmark\|none` | `agents` | how the nonce event reaches the pipeline |
| `--nonce STR` | `e2e-capture-<uuid8>` | reuse a nonce (validated; an invalid one is `FAIL 4.` and never reaches the run directory's name) |
| `--nonce-written` | off | the nonce line was already appended (check 4 goes straight to the poll) |
| `--exec-docker` | off | append the nonce line with `docker exec` (argv, line on stdin) |
| `--vd-deadline N` | `900` | seconds to wait for the vulnerability-detector feed |
| `--vd-poll N` | `15` | seconds between VD probes (one `#` line each) |
| `--vd-socket PATH` | `<--home>/queue/sockets/vd-http.sock` | the VD UDS socket; pointing it at a missing path isolates the probe negative (a valid `--home` keeps check 3 green) |
| `--views-file FILE` | `views.json` next to the script | routes, landings, tables and assertions (its sha256 is added to the manifest when it is not the default) |
| `--probe-json FILE` | — | use this JSON as the VD probe answer (the socket is never opened) |
| `--findings-json FILE` | — | use this `{agent_id: count}` instead of querying the indexer |

### Fixtures (`--probe-json` / `--findings-json`) — what they really need

They exercise the verdicts a live manager will not produce on demand: a feed in `failed`, one with
`enabled:false`, one `ready` with zero findings for the 5.x agent. **Check 9's feed verdict is the
only part that runs without the stack**: with `--probe-json` it is evaluated even when checks 1, 2,
3 or 5 failed, and its line is the verdict itself (`FAIL 9. vd (got: feed status=failed, …)`).
Everything else still needs what it needs — the browser part of the view needs the dashboard and a
login, so when the feed is ready but the stack is not, check 9 reports the blocker and appends the
feed verdict it did measure. A `failed` feed is settled **before** any findings query: the indexer
is not consulted at all.

The unreachable-probe negative does not use a fixture: `--vd-socket /tmp/no-existe.sock` leaves
every other check on its real source and yields exactly `FAIL 9. vd (got: probe unreachable …)`.

## Checks (fixed numbering)

| # | Check | Verdict |
|---|---|---|
| 0 | `setup` | credentials in a URL (`FAIL 0.`, nothing else runs), the `--out` guard (refused path / not exclusive / not cleared / not created), the venv entered and chromium present (else `venv missing; run --setup`) |
| 1 | indexer cluster health | `_cluster/health` is `green` or `yellow` (polled up to 120 s) |
| 2 | dashboard api status | `GET /api/status` answers **200 or 401** (401 without credentials still proves the server is alive; a refused connection or a timeout is a FAIL). The same endpoint is then read **with** credentials for the dashboard version the manifest reports — best effort: `, version not readable` in the line and `declared <package>` in the manifest when it cannot be |
| 3 | active agents | every id (`--agent-ids`, or all of them) is crossed with `global.db` and must be **active** there, and an active **5.x** agent must exist — and `--agent-5x-id`, when given, must name one: `FAIL 3. active agents (got: not active in global.db: 003 …)` / `(got: --agent-5x-id 001 is not an active 5.x agent (v4.14.3))` |
| 4 | nonce event indexed | only with `discover` and `--events-mode agents`: prints the argv that injects the nonce line, then waits up to 120 s for `_count` on `wazuh-events-v5-*` with a `term` on `user.name` |
| 4b | inventory sample | only with `inventory` or `vd`: `_search` on `--inventory-index` (`term wazuh.agent.id = <5x>`, sorted by `package.name`) and then, name by name, the first whose `_count` for this agent is **exactly 1** ⇒ the `{{package_name}}` / `{{package_version}}` the inventory view is filtered by and asserted on (polled up to 300 s; 0 documents ⇒ FAIL; no unique name among the first 25 ⇒ FAIL, because the view asserts `rows_eq: 1`) |
| 5 | dashboard login | `[data-test-subj="user-name"]` / `[data-test-subj="password"]` / `[data-test-subj="submit"]` (or `button[type=submit]`), landing on `/app/wz-home`; a failure reports only the exception type and the step |
| 6 | `agents` view | one row **per active agent** reading that `name` and `status: active` (exactly one row each), and `rows_eq = {{agent_count}}`: the table lists this run's active agents and nothing else |
| 7 | `discover` view | the nonce query is in the URL state, the counter reads exactly **1**, the table has exactly **1** row and that row reads `user.name = <nonce>`, `wazuh.agent.name = <5.x agent>`, `wazuh.protocol.location = /var/log/dpkg.log` |
| 8 | `inventory` view | the view filtered by `wazuh.agent.id:"<5x>" and package.name:"<sampled>"` lands with that filter in `_a`, the counter reads **1**, there is exactly **1** row and it reads the 5.x agent's name, that package **and that version** |
| 9 | `vd` view | the feed verdict (below); then one `vulnerability.id` of the 5.x agent is sampled from `wazuh-states-vulnerabilities*` and the view, filtered by `wazuh.agent.id:"<5x>" and vulnerability.id:"<CVE>"`, must show **exactly one** row with that agent and that CVE (`rows_eq: 1`), with the counter reading 1 |
| 10 | `manifest` | only when the evidence index could not be published: writing `captures.md` raised (`FAIL 10. manifest (got: OSError)`), its `--out` never came to exist (`no out dir: …`), the directory could not be listed for the 'Every file' table (`listing … failed: PermissionError`) or one of the artifacts could not be read, hashed or measured (`unreadable: 08-inventory.json (PermissionError)`, every offender named in the same reason). Always **before** the summary |

A check that was not asked for is reported as `SKIP n. <name> (not requested)`. A failure in 1, 2 or
5 turns every view into `SKIP n. <view> (blocked by <m>)`, so a dead stack produces one root-cause
FAIL instead of a cascade — but a failure in **3** turns them into
`FAIL n. <view> (got: blocked: check 3 failed)`: the stack may be perfectly alive while the agents
this run claims to prove are not there, and a SKIP would hide exactly that.
`--events-mode none` ⇒ `SKIP 4. … (events disabled by flag)`; `--events-mode benchmark` ⇒
`SKIP 4. … (benchmark mode not implemented in this stage)`.

### The nonce (check 4 and the `discover` view)

The nonce is `e2e-capture-<uuid8>`, minted per run (or given with `--nonce`). A free-form line in a
watched log would be dropped (`index_unclassified_events: false`, no `dpkg` decoder), so it travels
inside a line the `system-auth` decoder classifies:

```
<Mon DD HH:MM:SS> <host> sshd[4242]: Failed password for invalid user e2e-capture-<uuid8> from 203.0.113.7 port 4242 ssh2
```

appended to `/var/log/dpkg.log` (a `localfile` of the 5.x agent) inside the agent container. The
script **prints** the argv it would run and, by default, expects the line to be there already: pass
`--nonce-written`, or `--exec-docker` to let the script append it (argv + stdin, no shell). Without
either, check 4 is a SKIP naming the container — the capturer does not depend on `docker` being
usable from where it runs.

### The vulnerability-detector verdict (check 9)

`GET /vulnerability-detector/status` over `--vd-socket` is polled every `--vd-poll` seconds up to
`--vd-deadline`, one `#` progress line per probe. Then `capture_logic.vd_verdict(probe, findings,
agent_id_5x)` decides, with `findings` = `_count` on `wazuh-states-vulnerabilities*` **one query per
agent id**:

| Probe | Verdict |
|---|---|
| unreachable / `{"error": …}` | FAIL `probe unreachable…` (no findings query) |
| `enabled: false` | SKIP `vulnerability-detector disabled in config` (no findings query) |
| `status: failed` | FAIL immediately (no findings query) |
| `available`, `ready`, `offset > 0`, `last_successful_update > 0`, ≥ 1 finding **for the 5.x agent** | PASS (the CVE is sampled and the view is opened) |
| the same, with 0 findings for the 5.x agent | FAIL `feed ready, 0 findings indexed for agent 002`, plus the last `scan completed` line of the manager log when there is one |
| anything else (still `updating`, or `available:false`, or `offset`/`last_successful_update` still 0) | FAIL with `available=` and the last `status/offset/last_successful_update` |

Another agent's findings never count: the view is filtered by the 5.x agent, so the verdict counts
that agent alone.

## `views.json`

One entry per view. The placeholders resolved per run are `{{nonce}}`, `{{agent_names}}`,
`{{agent_count}}`, `{{agent_id_5x}}`, `{{agent_name_5x}}` (from `global.db`, never a hardcoded name),
`{{package_name}}` / `{{package_version}}` (check 4b) and `{{cve_5x}}` (check 9). **A placeholder
that resolves to nothing is a FAIL naming it** (`unresolved placeholder {{agent_id_5x}}`), never an
empty filter:

```json
"<view>": {
  "app": "it-hygiene",
  "route": "/app/it-hygiene#/overview/?tab=it-hygiene&tabView=software&tabSubView=packages&_a=(filters:!(),query:(language:kuery,query:'wazuh.agent.id:%22{{agent_id_5x}}%22%20and%20package.name:%22{{package_name}}%22'))",
  "ready_selector": ".euiPage",
  "landing": {
    "path": "/app/it-hygiene",
    "hash_route": "/overview/",
    "hash_params": {"tab": "it-hygiene", "tabView": "software", "tabSubView": "packages"},
    "state": {"_a": "query:'wazuh.agent.id:\"{{agent_id_5x}}\" and package.name:\"{{package_name}}\"'"}
  },
  "alternatives": [{"app": "…", "route": "…", "ready_selector": "…", "landing": {"…": "…"}}],
  "query": "",
  "search_selector": "",
  "scope_selector": ".euiDataGrid",
  "table": {"kind": "grid", "selector": ".euiDataGrid"},
  "count_selector": "[data-test-subj=\"discoverQueryHits\"]",
  "wait_selector": ".euiDataGrid [data-test-subj=\"dataGridRowCell\"]",
  "assertions": [
    {"row": {"wazuh.agent.name": "{{agent_name_5x}}", "package.name": "{{package_name}}", "package.version": "{{package_version}}"}},
    {"rows_eq": 1},
    {"hits_eq": 1}
  ],
  "fallback_clicks": []
}
```

| key | meaning |
|---|---|
| `app` / `route` / `ready_selector` | where to go and what to wait for (30 s); `app` is only used in the report line |
| `landing` | **where the view must be**, checked structurally (see below). Also valid inside each alternative |
| `query` / `search_selector` | typed into the query bar + Enter, then 5 s. A view whose tab has no query bar (IT Hygiene, VD) puts its filter in the route's URL state instead (`&_a=(filters:!(),query:(language:kuery,query:'…'))`) |
| `wait_selector` | bounded wait (25 s) for the first data cell; if it does not appear, the query bar's Refresh (`querySubmitButton`) is pressed once and it waits again |
| `scope_selector` | the container the table and the counter are looked for in. **Required**: a missing scope is a FAIL, never a pass |
| `table` | `kind` (`grid`, `table` or `doctable`) and `selector`. The scope must contain **exactly one** such element (`table missing` / `ambiguous table (N)`) |
| `count_selector` | the element `hits_eq` reads the count from, resolved **inside the scope** and required to be unique there (`counter missing` / `ambiguous counter (N)`); its text is parsed as the **first integer** (`Result (0/10)` ⇒ 0, `116 hits` ⇒ 116) |
| `assertions` | `row`, `rows_eq`, `hits_eq` (below); an assertion may carry its own `scope` |

### Landing (`landing`)

`scheme + host + port` must be the `--dashboard-url` this run was pointed at (the default port is
normalised, so `https://localhost:443` and the `https://localhost/…` the browser reports are the
same origin); `path` must be **exactly** the app's path; the fragment is split into its route and
its parameters, and then `hash_route` must be that route, every `hash_params` entry must be **equal**
(`tabView=hardware` never satisfies `tabView=software`) and every `state` entry must be carried by
the **decoded rison value of that very parameter** (`_a`, `_q`). Each state parameter
(`_a`, `_q`, `_g`) must appear **exactly once** in the fragment: two of them are two contradictory
states and nothing says which one the view rendered, so it is `duplicated state parameter _a`, not
the first value. The value itself is **parsed as a structure** (`capture_logic.parse_rison`: `(k:v)`
objects, `!(…)` arrays, `'…'` strings with `!` escapes, `!t`/`!f`/`!n`), and an entry written as
`query:'<kuery>'` is compared with **exact equality** against the **root's own**
`query:(language:kuery,query:'…')` clause (`root_kuery`) — a clause nested anywhere else carries the
same text and is **not** the view's query: neither Discover's `metadata:(query:(…))` nor a filter
chip's label (`filters:!((meta:(alias:'query:…')))`) can stand in for it, which a regex searching at
any depth could not tell apart. A value that is not readable rison is `#_a is not readable rison`
(a loud failure, never a pass). Any other entry is written `<dotted.path>:'<value>'` —
Discover's `metadata.indexPattern:'wazuh-events-v5*'` — and the string at **that path of the parsed
rison, walked from its root** (`rison_path`), must be **equal** to the value: a
`decoy:(indexPattern:'wazuh-events-v5*')` next to `metadata:(indexPattern:'wrong-index')`, a prefix
(`wazuh-events-v5`) or a longer pattern (`wazuh-events-v5*-archive`) is
`#_a without metadata.indexPattern:'wazuh-events-v5*'`, and an entry of any other shape is
`#_a has an unsupported state entry …` (v8: there is no substring rule left). Anything outside the fragment — a
`?note=…`, a `/app/wz-home?next=/app/it-hygiene` redirect — is **ignored**: it is not the view's
state, and reading it is exactly what used to accept the wrong page. The landing is checked when the
candidate is chosen **and again after the query and the final wait** (`landed on … after wait`): a
view that dropped its filter or navigated itself elsewhere is not the view that was asked for.

### Row extraction and assertions

The table is read in the browser, one function per `kind`, into rows of `{column: visible value}`
plus the `top`/`bottom` each row was drawn at and, per cell, its `left`/`right` and whether it was
**truncated** on screen (the visible value is the cell's `innerText` **minus** its
`.euiScreenReaderOnly` text, which reads `Row: 1, Column: 2:`; a `.euiScreenReaderOnly` span is 1 px
wide by design and never counts as truncated). These three scripts are the part a fake page cannot
test, so they have their own suite against a real browser: `test_capture_dom.py`.

| `kind` | column identity | row identity |
|---|---|---|
| `grid` (EuiDataGrid: IT Hygiene, VD) | the header `[data-test-subj="dataGridHeaderCell-<field>"]` the cell shares its `left` with | the **exact** `top` its cells share — no tolerance: 100 px and 101 px are two rows (grouped by `capture_logic.grid_rows`, which is what the unit tests pin) |
| `table` (EuiBasicTable: agents) | `thead th[data-test-subj="tableHeaderCell_<field>_<n>"]` ⇒ the `<td>` at **that `<th>`'s own position among the `<th>`s**, not at index `<n>`: EUI numbers `<n>` over its data columns only, so a leading selection column (a `<th>` without `data-test-subj`) shifts every `<td>` by one — `name_1` is the 3rd `<th>`/`<td>`, `status_6` the 8th (measured live; `test_capture_dom.py` pins it) | the `<tr>` |
| `doctable` (OSD Discover) | the i-th `th[data-test-subj="docTableHeaderField"]` ⇒ the i-th `td[data-test-subj="docTableField"]`; the columns are fixed by the route (`columns:!(user.name,wazuh.agent.name,wazuh.protocol.location)`) | the `<tr>` |

- `row: {"<column>": "<value>"}` — **exactly one** row must have **every** column equal to its value
  (after `strip()`). No substrings and no tokens: `wget.old` is not `wget`, `3.118ubuntu5.1` is not
  `3.118ubuntu5`, `inactive` is not `active`, and a value in the wrong column does not count. Two
  matches are a failure (`2 rows match …`), because the filter promised one. `{{agent_names}}` as a
  value expands to **one required row per active agent** (and, with no names at all, to **no**
  requirement, which is reported as a failure, not a vacuous pass).
  Where that row was drawn is **measured, not judged** (v6 / V11): whether it was inside the
  viewport on both axes (`top ≥ 0`, `bottom ≤ viewport height`; each asserted column's cell measured
  and within `[0, viewport width]` — a grid wider than the window still returns every cell's text)
  and which asserted columns the dashboard drew truncated (`innerText` hands back the whole value of
  a cell rendered as `Ubuntu Develop…`). Both go to `frame_note` in the sidecar and to the report
  line (`frame: in_viewport=false, truncated=[package.vendor]`). The capture is full-page, which
  shows what the *document* holds below the fold or past the right edge; a row inside a container
  that scrolls on its own is photographed as that container drew it, so `frame_note` is what says
  where to look — the PNG is not promised to show it.
- `rows_eq: N` — the table must have exactly N data rows (`{{agent_count}}` is allowed).
- `hits_eq: N` — the view's counter, read inside the scope, must read exactly N.

A view only reports PASS with its evidence on disk: the PNG must exist and be non-empty, the sidecar
must be written and the sha256 must be computable, or the view FAILs (`screenshot failed: …`,
`screenshot empty (0 bytes)`, `sidecar not written`). The PNG is `NN-<view>.png`, a capture of the
**whole page** (`full_page=True`, decision V11): the viewport is 1280×800 and the file comes out
at whatever the page occupies — `1283×1064` in IT Hygiene, `1280×800` in the agents and Discover
views — which is why `captures.md` **reads** the size out of each PNG instead of stating a constant.
A container that scrolls on its own (a virtualised grid body) is still captured as it was drawn;
when something fails the screenshot is still attempted, as `NN-<view>-FAIL.png`.

## Output

Under `--out`, which by default is a **fresh directory per run**,
`$WORKSPACE/e2e-dashboard-out/<run_id>/` with `run_id = <YYYYMMDDTHHMMSSZ>-<nonce>` (printed as
`# run_id:` / `# out:`), so two runs never mix their PNGs:

- `NN-<view>.png` — the capture (or `NN-<view>-FAIL.png`).
- `NN-<view>.json` — sidecar: `run_id`, `view`, `app_used`, `route_requested`,
  `landing_requested` (rendered), `routes_tried` (one entry per candidate: `app`, `route`, `url`,
  `url_ok`, `missing`), `final_url`, `ready_selector`, `table`, `assertions` (each with its value,
  its verdict, the number of rows read and the scope it was read in), `agent_ids`, `agent_id_5x`,
  `agent_name_5x`, `package_5x`, `cve_5x`, `counts_by_agent`, `index`, `category`, `nonce`,
  `api_request_calls` (`total` and every `POST /api/request` with `status >= 400` seen during the
  session — on the FAIL path too, which is the one worth reading). Each `row` assertion also
  carries `matched`, its `frame_note`
  (`{"in_viewport": false, "truncated_columns": ["package.vendor"]}` — the measurement, never a
  verdict) and, when it failed, the reason (`N rows match …`). The whole object is redacted
  **before** it is serialized.
- `captures.md` — provenance header (`run_id`, `HEAD`, the **dashboard version** as read from an
  authenticated `GET /api/status` — or `declared <package>` when it could not be read, never a
  constant passed off as a measurement —, **`sources`**: the sha256 of `capture.py`,
  `capture_logic.py`, `views.json` and, when it is not the default, `--views-file`; **`git status`**:
  the porcelain lines, which cover staged, unstaged *and* untracked changes, or `clean`; dashboard
  package, timestamp, URLs, nonce, agent ids, the 5.x agent, the sampled package, the sampled CVE,
  the resolved events index), the table `| vista | fichero | sha256 | qué prueba | assertions |`
  (the `assertions` cell carries the same `frame: in_viewport=…, truncated=[…]` note as the report
  line) and a second table, `| fichero | sha256 | tamaño | WxH |`, with **every file the run wrote**,
  its bytes and — for a PNG — the **pixel size read from its own IHDR header** (`—` for anything
  that is not a PNG). Every file is **read again when the manifest is published** (sha256 and
  IHDR, never the hash cached when the view passed): one that cannot be opened is
  `FAIL 10. manifest (got: unreadable: <file> (<type>))` and one whose bytes changed is
  `changed since capture: <file>`. The captures are full-page, so their height is the page's and no constant
  describes it. The directory is exclusive to the run, so a file in it that is not in that table
  means it was not.

## Limitations

- **v4 ran live on 2026-09-20 22:08:14 UTC (runs v4b/v4c, 23/23 verifier checks):**
  `agents` (`row={'name': 'agent-4x-ubuntu', 'status': 'active'}`, same for the 5.x, `rows_eq=2`),
  `discover` (`user.name` = nonce, `wazuh.agent.name`, `wazuh.protocol.location`, `hits_eq=1`, `rows_eq=1`) and
  `inventory` (`adduser 3.118ubuntu5` of agent 002 both in the backend sample and in the grid row, `hits_eq=1`,
  `rows_eq=1`) PASSed with the exact per-column matcher; `vd` FAILed before opening the view (0 findings, see
  below). One live correction was needed on the way: EUI numbers `tableHeaderCell_<field>_<n>` over its data
  columns only, so `<n>` is **not** the `<td>` index when a selection column leads the row — the header's own
  DOM position is used instead. That correction, and the other two extraction rules, are now pinned by
  `test_capture_dom.py` instead of by a live run.
- **Live runs are dated, never "the latest"**: v8 ran live on 2026-09-23 03:59:55 UTC and again at
  14:18:59 UTC (25/25 verifier checks both times) — `agents`, `discover` and `inventory` PASS, `vd` FAIL
  with 0 findings (feed ready, scan completed, nothing indexed for the 5.x agent). v9's two changes are
  pinned by the suites (143 + 14 tests; removing either check makes its regression test fail), and
  `test_discover_queries_the_declared_index_pattern_and_no_other` replays the Discover URL of the
  v7c live run (2026-09-21) against the exact-index rule.
- **The capture is the whole page and the crop is not a requirement** (V11), so where the row was
  drawn never fails a view. That is **not** a promise that the row is in the PNG: `full_page=True`
  grows the capture to the document, and a row inside a container that scrolls on its own (a
  virtualised grid body) is photographed as that container drew it. Both measurements are written
  into the sidecar's `frame_note` and the report line — a truncated cell means the pixels show less
  than the text that was compared. The evidence remains the exact per-column match; `frame_note`
  says where on the page to look for it.
- **Selectors that fail loudly (naming themselves) rather than silently passing** when the dashboard
  moves them:
  - `scope_selector` of `discover` is `.dscCanvas`, confirmed live (`probes/probe-canvas.py`: it holds both
    `table[data-test-subj=docTable]` and `discoverQueryHits`, one table). If a dashboard release changes it
    the view FAILs with `scope missing: .dscCanvas`.
  - the `vd` view's columns are declared as `wazuh.agent.name` and `vulnerability.id`: **the real
    column names of the VD data grid were never measured** (the live runs failed before opening the
    view, with 0 findings). Expect the first VD run with findings to correct them; the failure will
    read `0 rows match {…}` and the sidecar lists the columns that were read.
  - `doctable` header names are taken from `[data-test-subj^="docTableHeader-"]` when the header
    carries one, else from the first word of the header's text.
- **`views.json` was corrected by two live runs (2026-09-20, dashboard `5.0.0-latest`)**; a dashboard
  upgrade may move any of it, and the sidecar (`assertions[].rows`, `scope`, `routes_tried`,
  `value`) is what to read first:
  - the result counter of Discover, IT Hygiene and VD is `[data-test-subj="discoverQueryHits"]`
    (`count_selector`), unique per view; in IT Hygiene and VD it hangs from
    `.euiDataGrid > .euiDataGrid__controls`, which is why `.euiDataGrid` is both the scope and the
    table there. Its visible label varies with the version and the view, so only its first integer
    is read — nothing here promises the string `Result (1/1)`;
  - IT Hygiene (`tabView=software&tabSubView=packages`) and VD (`tabView=inventory`) have **no**
    `queryInput` in those tabs: the agent filter travels in the URL (`_a=(…query…)`) and the landing
    check requires it. The `table tbody tr` rows of the software tab are a vendor summary; the
    packages live in the `euiDataGrid`;
  - events carry the agent under `wazuh.agent.name` (not `agent.name`), and the nonce is decoded by
    `system-auth` into `user.name` — `event.original` is `index:false`, so it is not searchable.
- **The Discover alternative was dropped.** Threat Hunting
  (`/app/threat-hunting#/overview/?tab=general&tabView=findings`) stayed in v3 as a declared
  alternative that was never used; with v4 a candidate would also need its own `table`/`scope`, which
  nobody measured, so `alternatives` is empty for every view. The mechanism is still in the code (an
  alternative carries its own `landing`) and a measured entry can be added back.
- **`rows_eq: {{agent_count}}` on the agents view** means the endpoints table must list exactly the
  agents `global.db` reports as active: an agent in another state (or a second page of results) is a
  loud FAIL (`N data row(s) …, expected exactly M`), not a silent pass.
- **Runs as root**, and therefore launches chromium with `--no-sandbox`.
- `--events-mode benchmark` is not implemented in this stage (it SKIPs, naming the reason).
- Freshness: the sampled package and CVE prove that the dashboard shows **the document the indexer
  has for this agent**, not that the document was written today. Only the `discover` view proves
  freshness, through the per-run nonce.
- Redaction replaces secrets of 3 characters or more; a 1- or 2-character password would not be
  redacted (it would also turn the report into asterisks). Use real credentials.
- Nothing here restarts, installs or reconfigures anything — except `--setup`, which installs
  playwright's apt dependencies.

## Verified live (2026-09-20, dashboard `5.0.0-latest`, runs v3b 21:17 UTC and v4b/v4c 22:08 UTC)

- **Captured (PNG + sidecar + sha256): `agents`, `discover`, `inventory`.** The `vd` view was
  **never opened**: it FAILed before that, with evidence and not a SKIP — the feed was ready
  (`available`, `offset > 0`, `last_successful_update > 0`) and the agents had 0 findings indexed,
  with the manager's own `scan completed` line appended to the reason.
- `event.original` is stored with `index: false` in `wazuh-events-v5-*`: it cannot be searched. The
  nonce carrier (an sshd `Failed password` syslog line appended to `/var/log/dpkg.log`) is decoded by
  `system-auth`, so the nonce lands in `user.name` (keyword); check 4 and the Discover query use
  `user.name:"<nonce>"`. Those events are indexed in `wazuh-events-v5-system-activity`.
- Routes that really landed (the three URLs the unit tests replay):
  agents `/app/endpoints-summary` → `#/agents-preview/`; discover `/app/data-explorer/discover` →
  `#?_a=(…indexPattern:'wazuh-events-v5*'…)&_q=(…query:'user.name:"<nonce>"')` (the OSD Discover, not
  Threat Hunting); inventory `/app/it-hygiene` →
  `#/overview/?tab=it-hygiene&tabView=software&tabSubView=packages&_a=(…)`.
- Column identity measured with a one-off DOM probe (probe-columns): the IT Hygiene page holds
  **one** `.euiDataGrid`; its header cells are `[data-test-subj="dataGridHeaderCell-<field>"]` at
  `left` 8/48/293/538/782/1027 (`inspectCollapseColumn`, `wazuh.agent.name`, `package.vendor`,
  `package.name`, `package.version`, `package.type`) and each `[data-test-subj="dataGridRowCell"]`
  shares the `left` of its header and the `top` of its row. The agents table is `table.euiTable`
  with `thead th[data-test-subj="tableHeaderCell_<field>_<n>"]` (`id_0`, `name_1`, `version_5`,
  `status_6`). Discover renders `table[data-test-subj="docTable"]` with `th[docTableHeaderField]` /
  `td[docTableField]`, and its `discoverQueryHits` is unique on the page.
- The 5.x agent's inventory lives in `wazuh-states-inventory-packages*` (`wazuh.agent.id`,
  `wazuh.agent.name`, `package.name`, `package.version`, `package.type`) and its findings in
  `wazuh-states-vulnerabilities*` (`vulnerability.id`).
