# Dashboard E2E: reproducible captures with Playwright

Screenshots of the Wazuh dashboard that are **evidence**, not decoration: every view is asserted
against the data of the run that produced it (the agents `global.db` reports as active, an event
carrying a nonce minted for this run, **one concrete package, name and version, sampled from the
indexer for this run's 5.x agent**, **one concrete CVE of that same agent**), and the proof is
**one row of the view's table, matched column by column with exact equality**, in a screenshot of
the **whole page**. A dashboard rendering stale, empty, foreign or merely *similar* data, or
silently ignoring the filter it was given, cannot produce a green run.

The script prints the same parseable grammar as `../wazuh_verify_manager.sh` and
`../agents/verify_agents.sh`, so an evidence package can consume it unchanged.

```
dashboard/
├── capture.py             the CLI: checks, browser session, PNGs, sidecars, captures.md
├── capture_logic.py       the decisions (pure functions: no I/O, no network, no Playwright)
├── test_capture_logic.py  unit tests of those decisions (146 tests, no network, no browser)
├── test_capture_dom.py    DOM tests of the extraction scripts (15 tests, a real Chromium on
│                          HTML fixtures; SKIPped without the venv)
├── views.json             per view: route, landing, table, selectors, query, assertions
└── README.md              this file
```

## Design decisions

The code comments cite these ids.

| Id | Decision |
|---|---|
| D-8b | A view is proven by `row: {"<column>": "<value>"}` matched with **exact equality per column**, by **exactly one** row, in **exactly one** table of the view's scope; `rows_eq` and `hits_eq` are exact, and the counter is resolved inside the scope and must be unique there. |
| D-9b | The landing is checked **structurally** (origin, path, `#` route, every `#` parameter equal, every state entry against the parsed rison of its own parameter), never as a substring of the URL; a state parameter carried twice is a failure. |
| D-10b | No credential is printed or written: credentials come from the environment or `../.credentials.env` (one in a URL is refused), every line goes through `Reporter`, every object is redacted before `json.dumps`. Provenance is what was measured (the sha256 of each source that ran, `git status`, the dashboard version read from `GET /api/status`), and the manifest is written before the summary, so a manifest failure is counted. The "5.x agent" must be active and `v5*`. |
| V11 | The capture is the **whole page** (`full_page=True`); cropping to the viewport is not a requirement. Where the matched row was drawn is measured and reported as `frame_note`, never a verdict. |

## Prerequisites

- **root**: `queue/sockets/vd-http.sock` is `0660` and `queue/db/global.db` is not world readable.
- The indexer + dashboard stack up (`../docker-compose.yml`, project `dev-env-engine`: ports `443`
  and `9200`) and a manager installed and running at `--home`, every daemon up
  (`../wazuh_verify_manager.sh` check 1): check 9 probes modulesd's `vd-http.sock`.
- Real agents enrolled ([../agents/README.md](../agents/README.md)), **including one 5.x agent**:
  its id, its name, its inventory and its findings are what the `inventory` and `vd` views are
  asserted against.
- The venv, created once: `python3 capture.py --setup`. It lives outside the repo
  (`${DASHBOARD_VENV:-$WORKSPACE/venv-dashboard}`, `$WORKSPACE` = the parent of the checkout), so a
  capture run never leaves anything under `git status`. `--setup` creates it, installs
  **`playwright==1.63.0`** (pinned: this tool asserts layout, and layout moves with the browser)
  and runs `playwright install chromium --with-deps`, which **installs system packages with
  `apt`**; this is the only mode of the script that installs anything. If `--with-deps` fails it
  retries without it and prints, as `# apt: …` lines, what `playwright install-deps --dry-run
  chromium` reports. It then **launches chromium once** (headless, `about:blank`) and ends either
  with `# chromium launch: ok` or with `FAIL  0. setup (got: chromium launch failed: …)` and exit
  status 1.
- Credentials come from the environment first: `DASHBOARD_USER` / `DASHBOARD_PASSWORD` and
  `INDEXER_USER` / `INDEXER_PASSWORD`. Any that is unset falls back to the stack's generated
  `../.credentials.env` (user `admin`, password `WAZUH_INDEXER_ADMIN_PASSWORD` for both the indexer
  and the dashboard; the line is split at the first `=`); if the file is missing or unreadable, or
  the key absent, to the `admin`/`admin` literals of stacks generated before it existed. Values are
  never printed. A `https://user:pass@host` in `--dashboard-url` or `--indexer-url` is **refused**
  (`FAIL  0. setup (got: credentials in --dashboard-url are not accepted; use
  DASHBOARD_USER/PASSWORD)`), because such a value is not in the redaction list. TLS is not
  verified (self-signed lab certificates).

Any invocation re-executes itself inside the venv (`os.execv`) before importing Playwright, so
`python3 capture.py …` with the system interpreter is the normal way to run it.
`PLAYWRIGHT_BROWSERS_PATH` is **set** (not defaulted) to `<venv>/browsers`, or to
`--browsers-path`, on both paths: already inside the venv and after the re-exec.

## Safety

- **No shell.** `--exec-docker` runs the argv
  `docker exec -i <container> sh -c 'cat >> /var/log/dpkg.log'` and feeds the nonce line through
  **stdin**; nothing from the command line is interpolated into a shell program. `--nonce` must match
  `^e2e-capture-[A-Za-z0-9._-]{4,32}$` and `--agent-container` `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`,
  or check 4 fails with the reason and nothing is executed. The log path is a constant, not a flag.
- **No credential is ever printed or written.** The login wraps every step and reports only the
  exception *type* and the step name (Playwright's own error text quotes the value it was told to
  fill). **Every** line of stdout is printed by `Reporter`, which redacts it (`test_no_bare_print`
  fails if a `print(` of `capture.py` lives outside that class), and every object is passed through
  `capture_logic.redact_obj()` **before** `json.dumps`, so a password containing a quote cannot
  survive as `s\"ecret`.
- **`--out` is emptied, so it is guarded twice.** The target and the roots it must stay out of are
  **canonicalised** (`os.path.realpath`) first, so a symlink is not a way around the list. The run
  refuses outright, `FAIL  0. setup (got: --out refuses <path>: <reason>)`, before reading the
  directory: the filesystem root, `$HOME`, anything inside `$WAZUH_REPO` or the checkout this script
  lives in, and any path with fewer than two components (`/tmp`). Then the directory is emptied
  **only if every entry in it is a regular file this tool wrote** (`NN-<view>[-FAIL].png`,
  `NN-<view>.json`, `captures.md`); the **kind** is read from the filesystem, because a directory
  called `captures.md` or a symlink called `06-agents.png` wears an artifact's name. Anything else
  and **nothing is deleted**: `FAIL  0. setup (got: out dir not exclusive: captures.md (dir),
  precious.txt (file))`, up to three entries, and not even the manifest is written into it. Files
  are removed with `os.remove`, one by one: there is **no recursive delete in `capture.py`**, and a
  unit test greps the source for `rmtree`.
- **Read-only** on the manager, the indexer and the dashboard. Besides `--out`, the single write
  it can make is the nonce line inside the agent container, and only with `--exec-docker`.

## Usage

```bash
WORKSPACE=$(dirname "$WAZUH_REPO"); D=$WAZUH_REPO/tools/devContainer/e2e/dashboard
sudo python3 $D/capture.py --setup                        # once (installs apt deps)
sudo python3 $D/capture.py --views agents,discover,inventory,vd --exec-docker
(cd $D && python3 -m unittest -v test_capture_logic)      # the decision logic, no stack needed
(cd $D && $WORKSPACE/venv-dashboard/bin/python -m unittest -v test_capture_dom)  # the DOM
```

VS Code: `E2E Scripts: [Dashboard] Setup` once, then `E2E Scripts: [Dashboard] Capture` (the four views with
`--exec-docker`, venv `${workspaceFolder}/venv-dashboard`); add `--agent-5x-id <id>` to the task when two
5.x agents are enrolled.

### Tests

| suite | interpreter | what it covers |
|---|---|---|
| `test_capture_logic.py` (146) | any `python3` | every decision: the plan, the landing (the rison parser, the root query clause, the exact `metadata.indexPattern` path, a duplicated `_a`), the row matcher, the frame note, the counter, the verdicts, the `--out` guard (refused roots through a symlink, exclusivity by name **and** kind), the manifest's counted failures, the pixel size of a PNG, the `full_page=True` of `shoot()`, the orchestration and the report, with a fake page and a temporary directory: no network, no browser, no manager |
| `test_capture_dom.py` (15) | the venv's (`$WORKSPACE/venv-dashboard/bin/python`, or `$DASHBOARD_VENV`) | the three **extraction scripts**, in a real headless Chromium (`--no-sandbox`) over HTML fixtures copied from the measured DOM: column identity by `left` and by `<th>` position, the visible text minus `.euiScreenReaderOnly`, `left`/`right`/`truncated`, `ambiguous table (2)`, `table missing`, `scope missing`. Nothing is fetched: only `page.set_content()`. Without the venv or without `playwright` importable every test **SKIPs** (`venv missing: …` / `playwright not importable …`), never errors |

Both suites read `views.json`, so the fixtures are asserted through the **real selectors of the
views**: a scope or a table that moves there fails here first.

CI runs both in [5_testunit_dev-tools.yml](../../../../.github/workflows/5_testunit_dev-tools.yml) (job
`dashboard-capture`, on a change to `dashboard/*.py` or `views.json`) with the venv's interpreter, built
the way `--setup` builds it (`playwright==1.63.0`, Chromium under `<venv>/browsers`, `DASHBOARD_VENV`
pointing at it), and fails when the output contains `skipped=`: a DOM case that skips is a failure there.

Output (stdout, one line per check):

```
# capture.py — 2026-09-20T16:04:11Z — https://localhost:443
# run_id: 20260920T160411Z-e2e-capture-1a2b3c4d
# out: /workspaces/.../e2e-dashboard-out/20260920T160411Z-e2e-capture-1a2b3c4d
PASS  1. indexer cluster health (got: green)
...
PASS  4b. inventory sample (got: agent 002: package wget 1.21.4-1ubuntu4 (1 document) in wazuh-states-inventory-packages*)
PASS  8. inventory (got: app=it-hygiene url=… (row={'wazuh.agent.name': 'agent-5x-ubuntu', 'package.name': 'wget', 'package.version': '1.21.4-1ubuntu4'}; rows_eq=1; hits_eq=1; frame: in_viewport=true, truncated=[]))
# manifest: /workspaces/.../e2e-dashboard-out/20260920T160411Z-e2e-capture-1a2b3c4d/captures.md
# summary: executed=10 passed=10 failed=0 skipped=1
```

`executed` counts PASS + FAIL, SKIP is counted apart, and the exit status is `0` iff `failed=0`.
Each check runs inside its own `try/except`: an unexpected error becomes
`FAIL n. … (got: <exception>)` and the run still reaches its summary. The **manifest is written
before the summary**, so a manifest that could not be written is `FAIL 10. manifest (got: OSError)`:
counted, inside the summary and reflected in the exit status.

## Flags

| Flag | Default | What it does |
|---|---|---|
| `--setup` | off | create the venv, install `playwright==1.63.0` + its chromium (**apt**), exit |
| `--venv DIR` | `${DASHBOARD_VENV:-$WORKSPACE/venv-dashboard}` | venv holding playwright and its browsers |
| `--browsers-path DIR` | `<--venv>/browsers` | value forced into `PLAYWRIGHT_BROWSERS_PATH` |
| `--out DIR` | `$WORKSPACE/e2e-dashboard-out/<run_id>` | PNGs, sidecars and `captures.md`. Without the flag, **one directory per run**; an explicit directory is **emptied** first, under the guard of Safety. A file that cannot be removed, a directory that cannot be listed or one that cannot be created aborts the run (`out dir not cleared: …`, `cannot create …`) |
| `--views a,b` | `agents,discover,inventory,vd` | which views to capture (an unknown name is ignored with a `#` note) |
| `--dashboard-url URL` | `https://localhost:443` | dashboard under test; **credentials in the URL are refused** (`FAIL 0.`) |
| `--indexer-url URL` | `https://localhost:9200` | indexer queried for counts and samples; credentials in the URL are refused too |
| `--home DIR` | `/var/wazuh-manager` | installed manager (`global.db`, `vd-http.sock`, `logs/wazuh-manager.log`) |
| `--agent-container NAME` | `wazuh-agent-5x-ubuntu` | container the nonce line is appended in (validated) |
| `--agent-ids 001,002` | every active agent of `global.db` | ids to filter by; **each one must be active in `global.db`** or check 3 fails naming it |
| `--agent-5x-id 002` | the first `v5` agent **among `--agent-ids`** | id behind `{{agent_id_5x}}`; must be **active AND a v5 agent** and belong to `--agent-ids`: on a 4.x agent it is `FAIL 3. active agents (got: --agent-5x-id 001 is not an active 5.x agent (v4.14.3))`, and `--agent-ids 001` alone is `(got: no active 5.x agent among --agent-ids 001 …)` |
| `--inventory-index PAT` | `wazuh-states-inventory-packages*` | index the package sample of check 4b comes from |
| `--events-mode agents\|benchmark\|none` | `agents` | how the nonce event reaches the pipeline |
| `--nonce STR` | `e2e-capture-<uuid8>` | reuse a nonce (validated; an invalid one is `FAIL 4.` and never reaches the run directory's name) |
| `--nonce-written` | off | the nonce line was already appended (check 4 goes straight to the poll) |
| `--exec-docker` | off | append the nonce line with `docker exec` (argv, line on stdin) |
| `--vd-deadline N` | `900` | seconds to wait for the vulnerability-detector feed |
| `--vd-poll N` | `15` | seconds between VD probes (one `#` line each) |
| `--vd-socket PATH` | `<--home>/queue/sockets/vd-http.sock` | the VD UDS socket; ignored with `--probe-json` |
| `--views-file FILE` | `views.json` next to the script | routes, landings, tables and assertions (its sha256 is added to the manifest when it is not the default) |
| `--probe-json FILE` | none | use this JSON as the VD probe answer (the socket is never opened) |
| `--findings-json FILE` | none | use this `{agent_id: count}` instead of querying the indexer |

### Fixtures (`--probe-json` / `--findings-json`)

They exercise the verdicts a live manager will not produce on demand: a feed in `failed`, one with
`enabled:false`, one `ready` with zero findings for the 5.x agent. **Check 9's feed verdict is the
only part that runs without the stack**: with `--probe-json` it is evaluated even when checks 1, 2,
3 or 5 failed, and its line is the verdict itself (`FAIL 9. vd (got: feed status=failed, …)`).
Everything else still needs what it needs: when the feed is ready but the browser is blocked,
check 9 reports the blocker and appends the feed verdict it did measure. A `failed` feed is settled
**before** any findings query.

The unreachable-probe negative does not need a fixture: `--vd-socket /tmp/no-existe.sock` leaves
every other check on its real source and yields `FAIL 9. vd (got: probe unreachable: …)`.

## Checks (fixed numbering)

| # | Check | Verdict |
|---|---|---|
| 0 | `setup` | credentials in a URL (`FAIL 0.`, nothing else runs), the `--out` guard (refused path / not exclusive / not cleared / not created), the venv entered (else `venv missing; run --setup`) and chromium present (else `chromium missing at …; run --setup`) |
| 1 | indexer cluster health | `_cluster/health` is `green` or `yellow` (polled up to 120 s) |
| 2 | dashboard api status | `GET /api/status` answers **200 or 401** (401 without credentials still proves the server is alive; a refused connection or a timeout is a FAIL). The same endpoint is then read **with** credentials for the dashboard version the manifest reports, best effort: `, version not readable` in the line and `declared 5.0.0-latest` in the manifest when it cannot be |
| 3 | active agents | every id (`--agent-ids`, or all of them) is crossed with `global.db` and must be **active** there, and an active **5.x** agent must exist among them; `--agent-5x-id`, when given, must name one: `FAIL 3. active agents (got: not active in global.db: 003 …)` |
| 4 | nonce event indexed | only with `discover` and `--events-mode agents`: prints the argv that injects the nonce line; with `--exec-docker` the nonce must not be indexed yet (else `already indexed … use a fresh --nonce`); then waits up to 120 s for `_count` on `wazuh-events-v5-*` with a `term` on `user.name` and on `wazuh.agent.id` = the 5.x agent |
| 4b | inventory sample | only with `inventory` or `vd`: `_search` on `--inventory-index` (`term wazuh.agent.id = <5x>`, sorted by `package.name`, polled up to 300 s), then, name by name, the first whose `_count` for this agent is **exactly 1** gives the `{{package_name}}` / `{{package_version}}` the inventory view is filtered by and asserted on. 0 documents is a FAIL; no unique name among the first 25 is a FAIL, because the view asserts `rows_eq: 1`. SKIPped when check 1 failed, FAILed (`blocked: check 3 failed`) when check 3 did |
| 5 | dashboard login | `[data-test-subj="user-name"]` / `[data-test-subj="password"]` / `[data-test-subj="submit"]` (or `button[type=submit]`) on `/app/login`, landing on `/app/wz-home`; a failure reports only the exception type and the step |
| 6 | `agents` view | one row **per active agent** reading that `name` and `status: active` (exactly one row each), and `rows_eq = {{agent_count}}`: the table lists this run's active agents and nothing else |
| 7 | `discover` view | the nonce query is in the URL state, the counter reads exactly **1**, the table has exactly **1** row and that row reads `user.name = <nonce>`, `wazuh.agent.name = <5.x agent>`, `wazuh.protocol.location = /var/log/dpkg.log` |
| 8 | `inventory` view | the view filtered by `wazuh.agent.id:"<5x>" and package.name:"<sampled>"` lands with that filter in `_a`, the counter reads **1**, there is exactly **1** row and it reads the 5.x agent's name, that package **and that version** |
| 9 | `vd` view | the feed verdict (below); then one finding of the 5.x agent is sampled from `wazuh-states-vulnerabilities*`: the first `vulnerability.id` + `package.name` pair (sorted by id) whose `_count` for this agent is **exactly 1** (a CVE alone can be a finding of several packages built from the same source). The view, filtered by `wazuh.agent.id:"<5x>" and vulnerability.id:"<CVE>" and package.name:"<package>"`, must show **exactly one** row with that agent, package and CVE (`rows_eq: 1`), with the counter reading 1; no unique pair among the first 25 is a FAIL |
| 10 | `manifest` | only when the evidence index could not be published: writing `captures.md` raised (`FAIL 10. manifest (got: OSError)`), `--out` never came to exist (`no out dir: …`), the directory could not be listed (`listing … failed: PermissionError`), or an artifact could not be read, hashed or measured (`unreadable: <file> (<type>)`), changed after its view hashed it (`changed since capture: <file>`) or vanished (`missing since capture: <file>`); every offender is named in the same reason. Always **before** the summary |

A check that was not asked for is reported as `SKIP n. <name> (not requested)`. A failure in 1, 2 or
5 turns every view into `SKIP n. <view> (blocked by <m>)`, so a dead stack produces one root-cause
FAIL instead of a cascade; a failure in **3** turns them into
`FAIL n. <view> (got: blocked: check 3 failed)`, because the stack may be alive while the agents
this run claims to prove are not there, and a SKIP would hide that.
`--events-mode none` gives `SKIP 4. … (events disabled by flag)`; `--events-mode benchmark` gives
`SKIP 4. … (benchmark mode not implemented in this stage)`.

### The nonce (check 4 and the `discover` view)

The nonce is `e2e-capture-<uuid8>`, minted per run (or given with `--nonce`). A free-form line in a
watched log would be dropped (`index_unclassified_events: false`, no `dpkg` decoder), so it travels
inside a line the `system-auth` decoder classifies, which puts the nonce in `user.name`
(`event.original` is stored with `index: false` and cannot be searched):

```
<Mon DD HH:MM:SS> <container> sshd[4242]: Failed password for invalid user e2e-capture-<uuid8> from 203.0.113.7 port 4242 ssh2
```

appended to `/var/log/dpkg.log` (a `localfile` of the 5.x agent) inside the agent container. The
script **prints** the argv it would run and, by default, expects the line to be there already: pass
`--nonce-written`, or `--exec-docker` to let the script append it (argv + stdin, no shell). Without
either, check 4 is a SKIP naming the container, so the capturer does not depend on `docker` being
usable from where it runs.

### The vulnerability-detector verdict (check 9)

`GET /vulnerability-detector/status` over `--vd-socket` is polled every `--vd-poll` seconds up to
`--vd-deadline`, one `#` progress line per probe. Then `capture_logic.vd_verdict(probe, findings,
agent_id_5x)` decides, with `findings` = `_count` on `wazuh-states-vulnerabilities*`, **one query per
agent id**:

| Probe | Verdict |
|---|---|
| unreachable / `{"error": …}` | FAIL `probe unreachable…` (no findings query) |
| `enabled: false` | SKIP `vulnerability-detector disabled in config` (no findings query) |
| `status: failed` | FAIL `feed status=failed, …` immediately (no findings query) |
| `available`, `ready`, `offset > 0`, `last_successful_update > 0`, ≥ 1 finding **for the 5.x agent** | PASS (the CVE is sampled and the view is opened) |
| the same, with 0 findings for the 5.x agent | FAIL `feed ready, 0 findings indexed for agent 002`, plus the last vulnerability-scanner `scan completed` line of the manager log (live or the two newest rotated) when there is one |
| anything else (still `updating`, `available:false`, or `offset`/`last_successful_update` still 0) | FAIL `feed not ready before deadline, available=…` with the last `status/offset/last_successful_update` |

Another agent's findings never count: the view is filtered by the 5.x agent, so the verdict counts
that agent alone.

## `views.json`

One entry per view. The placeholders resolved per run are `{{nonce}}`, `{{agent_names}}`,
`{{agent_count}}`, `{{agent_id_5x}}`, `{{agent_name_5x}}` (from `global.db`, never a hardcoded name),
`{{package_name}}` / `{{package_version}}` (check 4b) and `{{cve_5x}}` / `{{cve_package_5x}}` (check 9). **A placeholder
that resolves to nothing is a FAIL naming it** (`unresolved placeholder {{agent_id_5x}}`), never an
empty filter. Values are percent-encoded into the route (a package called `g++` travels as
`g%2B%2B`); the landing is compared against the decoded value.

```json,fragment
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
| `alternatives` | further candidates (`app`, `route`, `ready_selector`, `landing`) tried in order when the route does not land; empty for every shipped view |
| `fallback_clicks` | selectors clicked once each, when present, after `ready_selector` and before the landing check |
| `query` / `search_selector` | typed into the query bar + Enter, then 5 s. A view whose tab has no query bar (IT Hygiene, VD) puts its filter in the route's URL state instead (`&_a=(filters:!(),query:(language:kuery,query:'…'))`) |
| `wait_selector` | bounded wait (25 s) for the first data cell; if it does not appear, the query bar's Refresh (`querySubmitButton`) is pressed once and it waits again |
| `scope_selector` | the container the table and the counter are looked for in. **Required**: a missing scope is a FAIL, never a pass |
| `table` | `kind` (`grid`, `table` or `doctable`) and `selector`. The scope must contain **exactly one** such element (`table missing` / `ambiguous table (N)`) |
| `count_selector` | the element `hits_eq` reads the count from, resolved **inside the scope** and required to be unique there (`counter missing` / `ambiguous counter (N)`); its text is parsed as the **first integer** (`Result (0/10)` is 0, `116 hits` is 116) |
| `assertions` | `row`, `rows_eq`, `hits_eq` (below); an assertion may carry its own `scope` |

### Landing (`landing`)

`scheme + host + port` must be the `--dashboard-url` this run was pointed at (the default port is
normalised, so `https://localhost:443` and the `https://localhost/…` the browser reports are the
same origin); `path` must be **exactly** the app's path; the fragment is split into its route and
its parameters, and then `hash_route` must be that route, every `hash_params` entry must be **equal**
(`tabView=hardware` never satisfies `tabView=software`) and every `state` entry must be carried by
the **parsed rison value of that very parameter** (`_a`, `_q`). Each state parameter
(`_a`, `_q`, `_g`) must appear **at most once** in the fragment: two are two contradictory states,
so it is `duplicated state parameter _a`, not the first value. The value is **parsed as a
structure** (`capture_logic.parse_rison`: `(k:v)` objects, `!(…)` arrays, `'…'` strings with `!`
escapes, `!t`/`!f`/`!n`), and an entry written as `query:'<kuery>'` is compared with **exact
equality** against the **root's own** `query:(language:kuery,query:'…')` clause (`root_kuery`): a
clause nested elsewhere (Discover's `metadata:(query:(…))`, a filter chip's
`filters:!((meta:(alias:'query:…')))`) is not the view's query. A value that is not readable rison
is `#_a is not readable rison`. Any other entry is written `<dotted.path>:'<value>'`, such as
Discover's `metadata.indexPattern:'wazuh-events-v5*'`, and the string at **that path of the parsed
rison, walked from its root** (`rison_path`), must be **equal** to the value: a
`decoy:(indexPattern:'wazuh-events-v5*')` next to `metadata:(indexPattern:'wrong-index')`, a prefix
(`wazuh-events-v5`) or a longer pattern (`wazuh-events-v5*-archive`) is
`#_a without metadata.indexPattern:'wazuh-events-v5*'`, and an entry of any other shape is
`#_a has an unsupported state entry …`. Anything outside the fragment (a `?note=…`, a
`/app/wz-home?next=/app/it-hygiene` redirect) is **ignored**: it is not the view's state. The
landing is checked when the candidate is chosen **and again after the query and the final wait**
(`landed on … after wait`): a view that dropped its filter or navigated elsewhere is not the view
that was asked for.

### Row extraction and assertions

The table is read in the browser, one function per `kind`, into rows of `{column: visible value}`
plus the `top`/`bottom` each row was drawn at and, per cell, its `left`/`right` and whether it was
**truncated** on screen (the visible value is the cell's `innerText` **minus** its
`.euiScreenReaderOnly` text, which reads `Row: 1, Column: 2:`; a `.euiScreenReaderOnly` span is 1 px
wide by design and never counts as truncated). These three scripts are the part a fake page cannot
test, so they have their own suite against a real browser: `test_capture_dom.py`.

| `kind` | column identity | row identity |
|---|---|---|
| `grid` (EuiDataGrid: IT Hygiene, VD) | the header `[data-test-subj="dataGridHeaderCell-<field>"]` the cell shares its `left` with | the **exact** `top` its cells share, no tolerance: 100 px and 101 px are two rows (`capture_logic.grid_rows`) |
| `table` (EuiBasicTable: agents) | `thead th[data-test-subj="tableHeaderCell_<field>_<n>"]` gives the `<td>` at **that `<th>`'s own position among the `<th>`s**, not at index `<n>`: EUI numbers `<n>` over its data columns only, so a leading selection column (a `<th>` without `data-test-subj`) shifts every `<td>` by one (`name_1` is the 3rd `<th>`/`<td>`, `status_6` the 8th; `test_capture_dom.py` pins it) | the `<tr>` |
| `doctable` (OSD Discover) | the i-th `th[data-test-subj="docTableHeaderField"]` gives the i-th `td[data-test-subj="docTableField"]`; the header name is the `docTableHeader-<field>` inside it when there is one, else the first word of its text; the columns are fixed by the route (`columns:!(user.name,wazuh.agent.name,wazuh.protocol.location)`) | the `<tr>` |

- `row: {"<column>": "<value>"}`: **exactly one** row must have **every** column equal to its value
  (after `strip()`). No substrings and no tokens: `wget.old` is not `wget`, `3.118ubuntu5.1` is not
  `3.118ubuntu5`, `inactive` is not `active`, and a value in the wrong column does not count. Two
  matches are a failure (`2 rows match …`), because the filter promised one. `{{agent_names}}` as a
  value expands to **one required row per active agent** (and, with no names at all, to **no**
  requirement, which is reported as a failure, not a vacuous pass).
  Where that row was drawn is **measured, not judged** (V11): whether it was inside the viewport
  on both axes (`top ≥ 0`, `bottom ≤ viewport height`; each asserted column's cell measured and
  within `[0, viewport width]`) and which asserted columns the dashboard drew truncated (`innerText`
  hands back the whole value of a cell rendered as `Ubuntu Develop…`). Both go to `frame_note` in
  the sidecar and to the report line (`frame: in_viewport=false, truncated=[package.vendor]`).
- `rows_eq: N`: the table must have exactly N data rows (`{{agent_count}}` is allowed).
- `hits_eq: N`: the view's counter, read inside the scope, must read exactly N.

A view only reports PASS with its evidence on disk: the PNG must exist and be non-empty, the sidecar
must be written and the sha256 must be computable, or the view FAILs (`screenshot failed: …`,
`screenshot empty (0 bytes)`, `sidecar not written`). The PNG is `NN-<view>.png`, a capture of the
**whole page** (`full_page=True`): the viewport is 1280×800 and the file comes out at whatever the
page occupies, which is why `captures.md` **reads** the size out of each PNG. When something fails
the screenshot is still attempted, as `NN-<view>-FAIL.png`.

## Output

Under `--out`, which by default is a **fresh directory per run**,
`$WORKSPACE/e2e-dashboard-out/<run_id>/` with `run_id = <YYYYMMDDTHHMMSSZ>-<nonce>` (printed as
`# run_id:` / `# out:`), so two runs never mix their PNGs:

- `NN-<view>.png`: the capture (or `NN-<view>-FAIL.png`).
- `NN-<view>.json`: sidecar with `run_id`, `view`, `app_used`, `route_requested`,
  `landing_requested` (rendered), `routes_tried` (one entry per candidate: `app`, `route`, `url`,
  `url_ok`, `missing`), `final_url`, `ready_selector`, `table`, `assertions` (each with its value,
  its verdict, the number of rows read and the scope it was read in), `agent_ids`, `agent_id_5x`,
  `agent_name_5x`, `package_5x`, `cve_5x`, `cve_package_5x`, `counts_by_agent`, `index`, `category`, `nonce`,
  `api_request_calls` (`total`, the responses to `/api/request` seen during the session, and
  `status_ge_400`, the `[status, url]` of each one with `status >= 400`; on the FAIL path too). Each `row` assertion also carries `matched`, its `frame_note`
  (`{"in_viewport": false, "truncated_columns": ["package.vendor"]}`) and, when it failed, the
  reason (`N rows match …`). The whole object is redacted **before** it is serialized.
- `captures.md`: a provenance table (`run_id`, `HEAD`, **`sources`**: the sha256 of `capture.py`,
  `capture_logic.py`, `views.json` and, when it is not the default, `--views-file`; **`git status`**:
  the porcelain lines, or `clean`; the **dashboard version** read from an authenticated
  `GET /api/status`, or `declared 5.0.0-latest` when it could not be read; the URLs, the nonce, the
  agent ids, the 5.x agent, the sampled package, the sampled CVE, the resolved events index), the
  table `| vista | fichero | sha256 | qué prueba | assertions |` (the `assertions` cell carries the
  same `frame: …` note as the report line) and a second table, `| fichero | sha256 | tamaño | WxH |`,
  with **every file the run wrote**, its bytes and, for a PNG, the **pixel size read from its own
  IHDR header** (`—` for anything else). Every file is **read again when the manifest is
  published** (sha256 and IHDR, never the hash cached when the view passed), and every file the run
  produced must still exist; otherwise check 10 fails (see Checks). The directory is exclusive to
  the run, so a file in it that is not in that table means it was not.

## Limitations

- **The capture is the whole page, not every row.** `full_page=True` grows the capture to the
  *document*; content that scrolls **inside a container** (a virtualised `euiDataGrid` body, a
  panel with its own `overflow`) is photographed as that container was drawn, and a row the grid
  has not rendered is in neither the DOM nor the PNG. `frame_note` says where on the page to look;
  a truncated cell means the pixels show less than the text that was compared. The evidence is the
  exact per-column match.
- **Selectors fail loudly, naming themselves**, when the dashboard moves them: a missing scope is
  `scope missing: <selector>` (for `discover`, `.dscCanvas`), and the sidecar (`assertions[].rows`,
  `scope`, `routes_tried`, `value`) is what to read first after a dashboard upgrade.
- **`rows_eq: {{agent_count}}` on the agents view** means the endpoints table must list exactly the
  agents `global.db` reports as active: an agent in another state (or a second page of results) is a
  FAIL (`N data row(s) …, expected exactly M`).
- **Runs as root**, and launches chromium with `--no-sandbox`.
- `--events-mode benchmark` is not implemented (it SKIPs, naming the reason).
- Freshness: the sampled package and CVE prove that the dashboard shows **the document the indexer
  has for this agent**, not that the document was written today. Only the `discover` view proves
  freshness, through the per-run nonce.
- Redaction replaces secrets of 3 characters or more; a 1- or 2-character password would not be
  redacted. Use real credentials.
- Nothing here restarts, installs or reconfigures anything, except `--setup`, which installs
  playwright's apt dependencies.

## What the views rely on (dashboard `5.0.0-latest`)

These are the dashboard structures `views.json` and the DOM fixtures of `test_capture_dom.py` were
written against:

- Routes: agents `/app/endpoints-summary` lands on `#/agents-preview/`; discover is the OSD Discover
  at `/app/data-explorer/discover` (`_a` carries `metadata.indexPattern:'wazuh-events-v5*'`, `_q`
  the query `user.name:"<nonce>"`); inventory `/app/it-hygiene`
  `#/overview/?tab=it-hygiene&tabView=software&tabSubView=packages`; vd
  `/app/vulnerability-detection` `#/overview/?tab=vuls&tabView=inventory`.
- The result counter of Discover, IT Hygiene and VD is `[data-test-subj="discoverQueryHits"]`; in
  IT Hygiene and VD it hangs from `.euiDataGrid > .euiDataGrid__controls`, which is why
  `.euiDataGrid` is both the scope and the table there. Its label varies, so only its first integer
  is read.
- IT Hygiene and VD have **no** `queryInput` in those tabs: the agent filter travels in the URL
  (`_a=(…query…)`) and the landing check requires it. In IT Hygiene the packages live in the
  `euiDataGrid`; the `table tbody tr` rows of the software tab are a vendor summary.
- The agents table is `table.euiTable` inside `[data-test-subj="table-with-search-bar"]`, with a
  leading selection column; its wait selector requires a second cell (`td:nth-child(2)`), which
  EUI's single-cell empty-state row (`No items found`) does not have.
- Discover renders `table[data-test-subj="docTable"]` inside `.dscCanvas`.
- Events carry the agent under `wazuh.agent.name` (not `agent.name`). The 5.x agent's inventory is
  in `wazuh-states-inventory-packages*` (`wazuh.agent.id`, `wazuh.agent.name`, `package.name`,
  `package.version`) and its findings in `wazuh-states-vulnerabilities*` (`vulnerability.id`,
  `package.name`).
