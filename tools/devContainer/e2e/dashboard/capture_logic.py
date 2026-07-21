#!/usr/bin/env python3
"""capture_logic.py — pure decision logic of capture.py.

Nothing in this module does I/O: no network, no files, no Playwright, no subprocesses.
Every function takes plain data and returns plain data, so the verdicts of a capture run
(which checks are requested, whether a view landed where it was asked to, whether the ONE
row this run's document must produce is really on screen, what the vulnerability-detector
probe means) can be unit-tested without a manager, without the indexer/dashboard stack and
without a browser:

    python3 -m unittest -v test_capture_logic

capture.py owns the I/O (HTTP, the unix socket probe, sqlite, Playwright, subprocess) and
calls into this module for every decision it prints.

v4 (design D-8b/D-9b/D-10b): a view is proven by ONE row matched COLUMN BY COLUMN with exact
equality (`rows_matching`), inside the frame (`row_in_frame`); the landing is structured, not
a substring search (`landing_ok`); and credentials never reach a URL, a line or a serialized
object (`url_credentials_problem`, `redact_obj`).

v5 adds what the fourth review found missing: the frame is measured on BOTH axes, per cell
(`row_in_frame`, `truncated_columns`); the landing's `state` is anchored to the rison
`query:(language:kuery,query:'...')` instead of any substring of it (`rison_kuery`); the run
refuses to empty an `--out` that is not exclusively its own (`out_dir_exclusive`,
`out_dir_refusal`); the 5.x agent is picked among the ids the run was asked about
(`pick_agent_5x`); and the values rendered into a route are percent-encoded (`render_query`
with `encode=True`), so a package called `g++` is not read back as `g  `.

v6 (decision V11): the screenshot is the WHOLE page, so the document below the fold or past the
right edge of the viewport is in the PNG (a container that scrolls on its own is not). `row_in_frame` and `truncated_columns`
are therefore a MEASUREMENT, not a verdict: capture.py writes what they answer into the
sidecar as `frame_note` and into the PASS line, and nothing about the frame can fail a view
any more. What still proves a view is unchanged (D-8b): the exact row, column by column, once.
`png_size` reads the real pixel size of each capture out of its own IHDR header, so the
manifest states the size of the evidence instead of promising one.

v8 (sixth review): no `state` entry is a substring any more. Discover's index pattern is
declared as the PATH it lives at (`metadata.indexPattern:'wazuh-events-v5*'`) and compared with
exact equality against that path of the parsed rison (`rison_path`), so a `decoy:(indexPattern:…)`
next to a `metadata:(indexPattern:'wrong-index')` — or a pattern that merely starts with the
declared one — is not the index the view queries.

v7 (fifth review) closes the two holes a probe walked straight through: the rison state is
PARSED (`parse_rison`) and the kuery is read from the root's own `query` clause
(`root_kuery`), so a `metadata:(query:(…))` buried at any depth no longer satisfies a landing,
and a state parameter that appears twice is a landing failure instead of a silent `got[0]`;
and `--out` is judged by TYPE as well as by name (`out_dir_exclusive` over `(name, kind)`
pairs), so a directory called `captures.md` or a symlink wearing an artifact's name is
somebody else's and nothing is deleted.
"""

import re
from urllib.parse import parse_qs, quote, urlsplit, urlunsplit

# The four views the capturer knows about, in check order.
VIEW_NAMES = ("agents", "discover", "inventory", "vd")

# Fixed check numbering: a check always keeps its number, whether it runs, is skipped or fails.
VIEW_CHECK = {"agents": 6, "discover": 7, "inventory": 8, "vd": 9}

# Check 4b samples one real inventory document, so the browser and the backend can be asked
# for the SAME document (that package, that version) instead of a bare total.
SAMPLE_CHECK = "4b"

# Writing the manifest is itself a check (10): a run whose evidence index could not be written
# has not produced evidence, and that must be counted, not raised after the summary.
MANIFEST_CHECK = 10

CHECK_NAMES = {
    0: "setup",
    1: "indexer cluster health",
    2: "dashboard api status",
    3: "active agents",
    4: "nonce event indexed",
    SAMPLE_CHECK: "inventory sample",
    5: "dashboard login",
    6: "agents",
    7: "discover",
    8: "inventory",
    9: "vd",
    MANIFEST_CHECK: "manifest",
}

# A failure in one of these blocks every view check (6-9) with a SKIP.
BLOCKING_CHECKS = (1, 2, 5)

# The only file the nonce line is ever appended to, inside the agent container. It is a
# constant, not an argument: it is interpolated into `sh -c`, and nothing interpolated into
# `sh -c` may come from the command line.
NONCE_LOG = "/var/log/dpkg.log"

# A nonce reaches a shell (inside the container, as the text of an echo/cat) and a kuery
# query, and a container name reaches `docker exec`: both are validated, never quoted-and-hoped.
NONCE_RE = re.compile(r"^e2e-capture-[A-Za-z0-9._-]{4,32}$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

# views.json placeholders, resolved per run from global.db and the indexer.
PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")

# A result counter reads "Result (1/1)", "116 hits" or just "1" depending on the view and the
# dashboard version: take the FIRST integer, never the concatenation of every digit on screen.
HITS_RE = re.compile(r"\d[\d,.]*")

# The 8 bytes every PNG starts with. The pixel size the manifest reports is read from the
# IHDR chunk that follows them (`png_size`), never assumed from the viewport.
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

# Shorter than this and a "secret" would redact half the report (a 1-char password would turn
# every line into asterisks); real credentials are longer.
MIN_SECRET_LEN = 3

# Credentials come from the environment, never from a URL a report will print (D-10b).
URL_CREDENTIAL_ENV = {
    "--dashboard-url": "DASHBOARD_USER/PASSWORD",
    "--indexer-url": "INDEXER_USER/PASSWORD",
}

DEFAULT_PORTS = {"http": 80, "https": 443}

# The only files a capture run writes into --out: `NN-<view>[-FAIL].png|.json` and the manifest.
# --out is EMPTIED before a run, so a directory holding anything else is somebody else's.
OUT_ARTIFACT_RE = re.compile(r"^\d{2}-[a-z]+(-FAIL)?\.(png|json)$")
OUT_MANIFEST = "captures.md"

# `--out /`, `--out $HOME` or `--out <anything with a single component>` is a mistake nobody
# recovers from: emptying it is not a capture, it is a wipe.
OUT_MIN_COMPONENTS = 2

# The parameters a dashboard URL carries its state in. Each one may appear EXACTLY ONCE in a
# fragment: two `_a=` are two contradictory states and nothing says which one the view rendered,
# so reading `got[0]` was a coin toss dressed as a check (D-9b).
STATE_PARAMS = ("_a", "_q", "_g")

# A `state` entry written as `query:'<kuery>'` is compared against the root's own query clause,
# exactly. Any other entry is `<dotted.path>:'<value>'` (`metadata.indexPattern:'wazuh-events-v5*'`)
# and is compared, exactly, against the string at that path of the PARSED rison, from its root (v8).
# There is no substring rule left: an entry of any other shape is a landing failure.
STATE_QUERY_RE = re.compile(r"^query:'(.*)'$", re.S)
STATE_PATH_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*):'(.*)'$", re.S)


def format_line(status, n, name, got):
    """One report line of the shared e2e grammar.

    PASS/FAIL carry the observed value ("(got: ...)"); SKIP carries a bare reason, exactly
    like wazuh_verify_manager.sh and agents/verify_agents.sh.
    """
    status = str(status).upper()
    body = "({0})".format(got) if status == "SKIP" else "(got: {0})".format(got)
    return "{0:<4}  {1}. {2} {3}".format(status, n, name, body)


def summary_line(executed, passed, failed, skipped):
    """The '# summary:' line. executed counts PASS+FAIL; SKIP is counted apart."""
    return "# summary: executed={0} passed={1} failed={2} skipped={3}".format(
        executed, passed, failed, skipped
    )


# --------------------------------------------------------------------------- secrets


def secrets_of(dashboard_user, dashboard_password, indexer_user, indexer_password):
    """Every string that must never reach stdout, a sidecar or the manifest.

    Both credentials plus the `user:pass@` form a URL would carry them in, so a redacted
    line cannot be reassembled from its pieces.
    """
    out = []
    for user, password in ((dashboard_user, dashboard_password), (indexer_user, indexer_password)):
        if user and password:
            out.append("{0}:{1}@".format(user, password))
            out.append("{0}:{1}".format(user, password))
        for value in (password, user):
            if value:
                out.append(value)
    return [s for s in out if len(s) >= MIN_SECRET_LEN]


def redact(text, secrets):
    """Replace every secret with '***'. Longest first, so `user:pass@` never survives as
    `user:***@`. Anything printed or persisted goes through this, including exception text:
    Playwright logs the value it was asked to fill (`fill("<password>")`) in its timeouts."""
    out = "" if text is None else str(text)
    for secret in sorted({str(s) for s in (secrets or []) if s and len(str(s)) >= MIN_SECRET_LEN},
                         key=len, reverse=True):
        out = out.replace(secret, "***")
    return out


def redact_obj(obj, secrets):
    """Redact a whole object BEFORE it is serialized (D-10b).

    json.dumps escapes what it writes, so a password containing a quote (`s"ecret`) survives
    a redaction applied to the serialized text (it is written `s\\"ecret` and no longer
    matches). Every dict, list and string is therefore redacted first, and the JSON is dumped
    from the redacted copy.
    """
    if isinstance(obj, dict):
        return {redact(k, secrets) if isinstance(k, str) else k: redact_obj(v, secrets)
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, secrets) for v in obj]
    if isinstance(obj, str):
        return redact(obj, secrets)
    return obj


def url_credentials_problem(url, flag):
    """'' when the URL carries no credentials, else the reason check 0 fails with.

    A `https://user:pass@host` on the command line would be printed by the header, the
    manifest and every sidecar, and it is NOT in `secrets` (those come from the environment),
    so redaction cannot save it: the run refuses it instead (D-10b).
    """
    parts = urlsplit(url or "")
    if not ("@" in (parts.netloc or "") or parts.username or parts.password):
        return ""
    return "credentials in {0} are not accepted; use {1}".format(
        flag, URL_CREDENTIAL_ENV.get(flag, "the environment")
    )


def safe_url(url):
    """The URL with any userinfo REMOVED — what a report may print before check 0 rejects it."""
    parts = urlsplit(url or "")
    if "@" not in (parts.netloc or ""):
        return url or ""
    netloc = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


# --------------------------------------------------------------------------- CLI inputs


def validate_nonce(nonce):
    """The nonce of this run, or ValueError. It ends up inside `echo`/`cat` in a container
    shell and inside a kuery query, so only the minted shape is accepted."""
    if not NONCE_RE.match(nonce or ""):
        raise ValueError("invalid nonce {0!r}: expected {1}".format(nonce, NONCE_RE.pattern))
    return nonce


def validate_container(name):
    """The agent container name, or ValueError. It is an argv entry of `docker exec`."""
    if not CONTAINER_RE.match(name or ""):
        raise ValueError("invalid container {0!r}: expected {1}".format(name, CONTAINER_RE.pattern))
    return name


def docker_exec_argv(container, log_path=NONCE_LOG):
    """argv (never a shell string) that appends one line, read from stdin, to the watched log.

    The line itself travels through stdin, so nothing from this run is interpolated into the
    `sh -c` program: the only shell word is the constant `cat >> /var/log/dpkg.log`.
    """
    validate_container(container)
    return ["docker", "exec", "-i", container, "sh", "-c", "cat >> {0}".format(log_path)]


def syslog_nonce_line(nonce, hostname, stamp):
    """The sshd line that carries the nonce into the pipeline.

    A free-form line is dropped (index_unclassified_events is false and there is no dpkg
    decoder), so the nonce travels inside a line the system-auth decoder classifies; it is
    then searchable with a term on user.name.
    """
    validate_nonce(nonce)
    return (
        '{0} {1} sshd[4242]: Failed password for invalid user {2} '
        "from 203.0.113.7 port 4242 ssh2".format(stamp, hostname, nonce)
    )


def browsers_dir(venv, override=""):
    """Where playwright must look for its browsers: --browsers-path, else <venv>/browsers."""
    return override or "{0}/browsers".format(str(venv or "").rstrip("/"))


def browsers_env(env, venv, override=""):
    """The environment playwright is run with: PLAYWRIGHT_BROWSERS_PATH is SET, not
    defaulted — a value inherited from the caller would send the re-exec'd interpreter to
    ~/.cache/ms-playwright while --setup installed under the venv."""
    out = dict(env or {})
    out["PLAYWRIGHT_BROWSERS_PATH"] = browsers_dir(venv, override)
    return out


# --------------------------------------------------------------------------- --out


def out_dir_artifact(name):
    """Is this entry of --out one this tool wrote? (`NN-<view>[-FAIL].png|.json`, `captures.md`)"""
    text = str(name or "")
    return text == OUT_MANIFEST or bool(OUT_ARTIFACT_RE.match(text))


def out_dir_entry_problem(name, kind):
    """'' when this entry is one this tool WROTE, else the kind that disqualifies it.

    An artifact of this tool is always a REGULAR FILE with one of its own names. The type is
    half the check: a directory called `captures.md` wears an artifact's name, and used to be
    removed with everything inside it; a symlink called `06-agents.png` names an artifact and
    points wherever its author chose. Both are somebody else's (v7).
    """
    kind = str(kind or "unknown")
    if kind != "file":
        return kind
    return "" if out_dir_artifact(name) else "file"


def out_dir_exclusive(entries, limit=3):
    """(ok, offenders) — may an explicit --out be EMPTIED before the run?

    `entries` is [(name, kind)] as the filesystem answered, with kind in
    file|dir|symlink|other|unreadable|missing: a name alone cannot say what will be deleted.
    The directory is ours only when EVERY entry is a regular file of ours (`out_dir_artifact`).
    `--out` deletes what it finds (that is how a leftover PNG of a previous run never passes
    for this run's evidence), so a directory holding anything else — a `precious.txt`,
    somebody's `subdir/`, a symlink — is not this tool's to empty: the run refuses it and
    deletes NOTHING. The offenders are returned as '<name> (<kind>)', sorted and capped,
    because the reason line is printed.
    """
    offenders = []
    for entry in entries or ():
        name, kind = (entry if isinstance(entry, (tuple, list)) and len(entry) == 2
                      else (entry, "unknown"))
        problem = out_dir_entry_problem(name, kind)
        if problem:
            offenders.append("{0} ({1})".format(name, problem))
    offenders.sort()
    return (not offenders, offenders[:limit])


def path_components(path):
    """The non-empty segments of an absolute path: '/tmp/x' -> ['tmp', 'x']."""
    return [p for p in str(path or "").replace("\\", "/").split("/") if p and p != "."]


def out_dir_refusal(path, home="", repo_roots=()):
    """'' when --out may be used at all, else WHY the run refuses it before touching it.

    This is the guard that runs BEFORE out_dir_exclusive: a directory can be perfectly empty
    (hence trivially "exclusive") and still be one nothing should ever write into, let alone
    empty — the filesystem root, the user's home, or anywhere inside the checkout, where the
    captures would show up in `git status` and the manifest's provenance would describe a tree
    this run had just modified. A single-component path (`/tmp`, `/home`) is refused too.

    `path`, `home` and every root are compared as TEXT and must therefore already be
    CANONICAL: capture.py resolves all of them with os.path.realpath (`canonical`) before
    calling, because `/tmp/alias -> <checkout>/out` is inside the checkout however innocent its
    spelling looks, and only the filesystem knows that (v7).
    """
    target = str(path or "").strip().rstrip("/")
    if not str(path or "").strip():
        return "no directory given"
    if not target:
        return "the filesystem root"
    if home and str(home).rstrip("/") == target:
        return "the home directory"
    for root in repo_roots or ():
        root = str(root or "").strip().rstrip("/")
        if root and (target == root or target.startswith(root + "/")):
            return "inside the checkout ({0})".format(root)
    if len(path_components(target)) < OUT_MIN_COMPONENTS:
        return "fewer than {0} path components".format(OUT_MIN_COMPONENTS)
    return ""


# --------------------------------------------------------------------------- plan


def plan_checks(views, events_mode="agents"):
    """Return [(number, name, requested)] for every check, always in number order.

    A check that is not requested is still reported, as 'SKIP n. <name> (not requested)'.
    Check 4 (the nonce event) only makes sense with the discover view and --events-mode
    agents; check 4b (the inventory sample) only with the inventory or vd views. Check 10
    (the manifest) is not planned: it is recorded only when writing it fails.
    """
    wanted = [v.strip() for v in (views or []) if v and v.strip()]
    plan = [(n, CHECK_NAMES[n], True) for n in (0, 1, 2, 3)]
    plan.append((4, CHECK_NAMES[4], "discover" in wanted and events_mode == "agents"))
    plan.append((SAMPLE_CHECK, CHECK_NAMES[SAMPLE_CHECK],
                 "inventory" in wanted or "vd" in wanted))
    plan.append((5, CHECK_NAMES[5], bool(wanted)))
    for view in VIEW_NAMES:
        n = VIEW_CHECK[view]
        plan.append((n, CHECK_NAMES[n], view in wanted))
    return plan


def blocked_by(failed_checks):
    """Which failed check blocks the views with a SKIP, if any (lowest of 1, 2, 5)."""
    failed = set(failed_checks or ())
    for n in BLOCKING_CHECKS:
        if n in failed:
            return n
    return None


def view_block(failed_checks, session_ready=True):
    """(status, reason) when a requested view must not be evaluated, else None.

    Check 3 is different in kind: the stack may be perfectly alive while the agents this run
    claims to prove are not there. A SKIP would hide that, so the views FAIL.
    """
    failed = set(failed_checks or ())
    if 3 in failed:
        return ("FAIL", "blocked: check 3 failed")
    n = blocked_by(failed)
    if n is not None:
        return ("SKIP", "blocked by {0}".format(n))
    if not session_ready:
        return ("SKIP", "blocked by 5")
    return None


# --------------------------------------------------------------------------- agents


def resolve_agents(requested_ids, active):
    """Cross --agent-ids with global.db. Returns (ids, names, problem).

    'active' is [(id, name, version)] of the agents global.db reports as active, so an id
    that is not in it either does not exist or is not active: either way the run cannot
    claim it. A non-empty problem means check 3 fails naming the offending ids.
    """
    index = {i: (n, v) for i, n, v in (active or [])}
    ids = [i for i in (requested_ids or []) if i]
    if ids:
        missing = [i for i in ids if i not in index]
        if missing:
            return ([], [], "not active in global.db: {0}".format(",".join(missing)))
    else:
        ids = [i for i, _n, _v in (active or [])]
    if not ids:
        return ([], [], "no active agent")
    return (ids, [index[i][0] for i in ids], "")


def is_5x(version):
    """global.db writes the agent version as 'v5.0.0' / 'v4.14.3': only 'v5…' is a 5.x agent."""
    return str(version or "").strip().startswith("v5")


def pick_agent_5x(active, override="", ids=()):
    """(id, name, problem) of this run's 5.x agent, chosen AMONG the ids this run was given.

    The override (--agent-5x-id) must be an ACTIVE agent AND a 5.x one: the inventory and vd
    views are filtered by {{agent_id_5x}} and the report calls it "the 5.x agent", so a 4.x
    id behind that name would make the whole run claim something it never proved (D-10b).

    `ids` is what --agent-ids resolved to (every active agent when the flag is not given).
    The 5.x agent is picked from THAT set and the override must belong to it: `--agent-ids 001`
    used to report `agents=001` and `5x=002` in the same run, an agent nobody asked about
    driving the inventory and vd views and the manifest.
    """
    chosen = [i for i in (ids or []) if i]
    pool = [(i, n, v) for i, n, v in (active or []) if not chosen or i in chosen]
    index = {i: (n, v) for i, n, v in pool}
    scope = " among --agent-ids {0}".format(",".join(chosen)) if chosen else ""
    if override:
        if override not in index:
            return ("", "", "--agent-5x-id {0} is not an active agent{1}".format(override, scope))
        name, version = index[override]
        if not is_5x(version):
            return ("", "", "--agent-5x-id {0} is not an active 5.x agent ({1})".format(
                override, version or "no version"))
        return (override, name, "")
    for agent_id, name, version in pool:
        if is_5x(version):
            return (agent_id, name, "")
    return ("", "", "no active 5.x agent{0}".format(scope))


# --------------------------------------------------------------------------- placeholders


def render_query(text, values, encode=False):
    """Substitute the per-run placeholders of views.json ({{nonce}}, {{agent_id_5x}},
    {{agent_name_5x}}, {{package_name}}, {{package_version}}, {{cve_5x}}, {{agent_names}},
    {{agent_count}}).

    An unknown or empty placeholder raises ValueError instead of rendering an empty string:
    `wazuh.agent.id:""` is a filter that matches nothing and a view that renders it would
    otherwise be asserted against whatever the dashboard decided to show.

    `encode=True` percent-encodes each substituted value, and ONLY the value: it is what goes
    into a route, where the browser (and `parse_qs` when the landing is checked back) reads
    `+` as a space — a package named `g++` rendered raw comes back as `g  ` and the view fails
    for a reason that has nothing to do with the dashboard. The template's own `%22`/`%20`
    are left alone.
    """
    source = "" if text is None else str(text)

    def substitute(match):
        key = match.group(1)
        value = (values or {}).get(key)
        if isinstance(value, (list, tuple)):
            value = ",".join(str(v) for v in value if v)
        value = "" if value is None else str(value)
        if not value:
            raise ValueError("unresolved placeholder {{{{{0}}}}}".format(key))
        return quote(value, safe="") if encode else value

    return PLACEHOLDER_RE.sub(substitute, source)


def expand_row(wanted, values):
    """Expand one `row` assertion into the rows that must exist, one per active agent when a
    column's value is {{agent_names}}.

    {"name": "{{agent_names}}", "status": "active"} with two agents becomes two required rows
    — and with no names at all it becomes NO requirement, which the caller turns into a
    failure rather than a vacuous pass.
    """
    spec = dict(wanted or {})
    vmap = dict(values or {})
    per_agent = [k for k, v in spec.items() if v == "{{agent_names}}"]
    if per_agent:
        names = vmap.get("agent_names") or []
        if isinstance(names, str):
            names = [n for n in names.split(",") if n]
        return [
            {k: (name if k in per_agent else render_query(v, vmap)) for k, v in spec.items()}
            for name in names
        ]
    return [{k: render_query(v, vmap) for k, v in spec.items()}]


def render_landing(landing, values):
    """The `landing` block of a view with its placeholders resolved (path, #route, #params
    and the state fragments each parameter must carry)."""
    spec = dict(landing or {})
    out = {
        "path": render_query(spec.get("path"), values),
        "hash_route": render_query(spec.get("hash_route"), values),
        "hash_params": {k: render_query(v, values)
                        for k, v in (spec.get("hash_params") or {}).items()},
        "state": {k: render_query(v, values) for k, v in (spec.get("state") or {}).items()},
    }
    return out


# --------------------------------------------------------------------------- landing


def origin_of(url):
    """'<scheme>://<host>:<port>' with the default port made explicit, so
    https://localhost:443 and https://localhost are the same origin (the browser drops the
    default port from the URL it reports)."""
    parts = urlsplit(url or "")
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        port = DEFAULT_PORTS.get(scheme)
    return "{0}://{1}:{2}".format(scheme, host, port if port is not None else "")


def split_fragment(fragment):
    """('<route>', {param: [values]}) of a hash route such as
    '#/overview/?tab=it-hygiene&_a=(…)'. Discover's '#?_a=(…)' has an EMPTY route."""
    text = fragment or ""
    route, _sep, query = text.partition("?")
    return route, parse_qs(query, keep_blank_values=True)


def landing_ok(url, dashboard_url, landing):
    """Did the browser land on the view that was asked for? Returns (ok, problems) — D-9b.

    Structured, never a substring search over the whole URL:
      - scheme + host + port must be the dashboard this run was pointed at (another origin
        serving the same path is not this dashboard);
      - the path must be exactly `path` (a login redirect /app/wz-home?next=/app/it-hygiene
        carries the string but is not the view);
      - the fragment is split into its route and its parameters: the route must be
        `hash_route`, every `hash_params` entry must be EQUAL (not contained: tabView=hardware
        never satisfies tabView=software), and every `state` entry must be carried by the
        PARSED rison value of THAT parameter — a `query:'<kuery>'` entry against the
        parameter's own `query:(language:kuery,query:'…')` clause and a `<path>:'<value>'` entry
        against the string at that path, both with EXACT equality (see state_problem).
    Anything outside the fragment (`?note=…`, a `next=` redirect) is ignored: it is not the
    view's state, and reading it is exactly what accepted the wrong page before.
    """
    spec = dict(landing or {})
    parts = urlsplit(url or "")
    problems = []
    if origin_of(url) != origin_of(dashboard_url):
        problems.append("origin {0} != {1}".format(origin_of(url), origin_of(dashboard_url)))
    want_path = str(spec.get("path") or "")
    if (parts.path or "").rstrip("/") != want_path.rstrip("/"):
        problems.append("path {0}".format(want_path or "(none)"))
    route, params = split_fragment(parts.fragment)
    want_route = spec.get("hash_route")
    if want_route is not None and route.rstrip("/") != str(want_route).rstrip("/"):
        problems.append("#route {0}".format(want_route or "(empty)"))
    for key, value in (spec.get("hash_params") or {}).items():
        got = [str(v) for v in (params.get(key) or [])]
        if got != [str(value)]:
            problems.append("#{0}={1}".format(key, value))
    # A state parameter carried TWICE is two contradictory states in one URL: whichever the
    # view rendered, this run cannot say which, and reading the first was a coin toss (v7).
    duplicated = [key for key in sorted(set(STATE_PARAMS) | set(spec.get("state") or {}))
                  if len(params.get(key) or []) > 1]
    problems.extend("duplicated state parameter {0}".format(key) for key in duplicated)
    for key, wanted in (spec.get("state") or {}).items():
        got = params.get(key) or []
        if not got:
            problems.append("#{0} missing".format(key))
            continue
        if key in duplicated:  # already reported, and there is no value to compare against
            continue
        # parse_qs already percent-decoded the value; decoding it a second time would turn a
        # literal '%20' inside a package name back into a space.
        problem = state_problem(key, str(wanted), got[0])
        if problem:
            problems.append(problem)
    return (not problems, problems)


class RisonError(ValueError):
    """The rison of a state parameter is not readable as a structure."""


def _rison_string(text, i):
    """A quoted rison string starting at text[i] == "'". `!` escapes the next character
    (`!'` is a literal quote, `!!` a literal bang), which is how a kuery with quotes travels."""
    i += 1
    out = []
    while i < len(text):
        char = text[i]
        if char == "!":
            if i + 1 >= len(text):
                raise RisonError("dangling escape")
            out.append(text[i + 1])
            i += 2
            continue
        if char == "'":
            return "".join(out), i + 1
        out.append(char)
        i += 1
    raise RisonError("unterminated string")


def _rison_array(text, i):
    """`!(a,b)` — text[i:i+2] == '!('."""
    i += 2
    out = []
    if i < len(text) and text[i] == ")":
        return out, i + 1
    while True:
        value, i = _rison_value(text, i)
        out.append(value)
        if i >= len(text):
            raise RisonError("unterminated array")
        if text[i] == ",":
            i += 1
            continue
        if text[i] == ")":
            return out, i + 1
        raise RisonError("unexpected {0!r} in array".format(text[i]))


def _rison_object(text, i):
    """`(k:v,k2:v2)` — text[i] == '('. A key repeated inside one object keeps the LAST value,
    exactly as a rison decoder would; the landing's own duplicate check is on the URL."""
    i += 1
    out = {}
    if i < len(text) and text[i] == ")":
        return out, i + 1
    while True:
        key, i = _rison_value(text, i)
        if i >= len(text) or text[i] != ":":
            raise RisonError("key without value")
        value, i = _rison_value(text, i + 1)
        out[str(key)] = value
        if i >= len(text):
            raise RisonError("unterminated object")
        if text[i] == ",":
            i += 1
            continue
        if text[i] == ")":
            return out, i + 1
        raise RisonError("unexpected {0!r} in object".format(text[i]))


_RISON_LITERALS = {"!t": True, "!f": False, "!n": None}
_RISON_DELIMITERS = ",:()'!"


def _rison_value(text, i):
    if i >= len(text):
        raise RisonError("value expected")
    char = text[i]
    if char == "'":
        return _rison_string(text, i)
    if char == "(":
        return _rison_object(text, i)
    if char == "!":
        if text[i:i + 2] == "!(":
            return _rison_array(text, i)
        if text[i:i + 2] in _RISON_LITERALS:
            return _RISON_LITERALS[text[i:i + 2]], i + 2
        raise RisonError("unknown literal {0!r}".format(text[i:i + 2]))
    end = i
    while end < len(text) and text[end] not in _RISON_DELIMITERS:
        end += 1
    if end == i:
        raise RisonError("unexpected {0!r}".format(char))
    return text[i:end], end


def parse_rison(text):
    """A rison state value as plain data, or None when it is not readable as a structure.

    The subset a dashboard URL uses: `(k:v,…)` objects, `!(…)` arrays, `'…'` strings with `!`
    escapes, `!t`/`!f`/`!n` and bare tokens. Parsing is the whole point of v7: the landing used
    to look for `query:(language:kuery,query:'…')` ANYWHERE in the text, so
    `metadata:(query:(language:kuery,query:'<the expected one>')),query:(language:kuery,
    query:'')` — a state whose real query was EMPTY — satisfied it (the probe of the fourth
    review). Structure is what tells a root clause from a nested one.

    Anything the parser cannot read whole (trailing junk included) is None, never a guess: the
    landing then says so and the view fails, loudly and with the parameter named.
    """
    source = str(text or "")
    try:
        value, end = _rison_value(source, 0)
    except (RisonError, RecursionError):
        return None
    return value if end == len(source) else None


def root_kuery(state):
    """The kuery of a PARSED rison state's OWN root `query:(language:kuery,query:'…')`, or None.

    Only the root clause is the view's query. `filters:!((meta:(alias:'query:…')))` is a filter
    chip's display label and `metadata:(query:(…))` is Discover's saved metadata: both carry the
    same text and neither renders anything (D-9b).
    """
    if not isinstance(state, dict):
        return None
    clause = state.get("query")
    if not isinstance(clause, dict) or str(clause.get("language") or "") != "kuery":
        return None
    value = clause.get("query")
    return value if isinstance(value, str) else None


def rison_kuery(state_value):
    """The kuery the root of a rison state carries, or None (parse + root_kuery)."""
    return root_kuery(parse_rison(state_value))


def rison_path(state, path):
    """The value at `a.b.c` of a PARSED rison state, walked from its ROOT, or None.

    Only objects are walked (an array or a scalar on the way is None): the path names one place,
    and nothing found anywhere else in the structure — a `decoy:(indexPattern:…)`, a filter chip —
    can answer for it (v8).
    """
    node = state
    for step in str(path or "").split("."):
        if not isinstance(node, dict) or step not in node:
            return None
        node = node[step]
    return node


def state_problem(key, wanted, value):
    """'' or the problem of ONE `state` entry (D-9b, v8).

    `query:'<kuery>'` is compared against the parameter's own ROOT query clause with exact
    equality — the rison is parsed, so no clause buried inside a filter label or inside
    `metadata:` can stand in for it. `<dotted.path>:'<value>'` is compared with exact equality
    against the STRING at that path of the parsed rison, from its root: Discover's
    `metadata.indexPattern:'wazuh-events-v5*'` is satisfied by `metadata:(indexPattern:
    'wazuh-events-v5*')` and by nothing else — not by `decoy:(indexPattern:'wazuh-events-v5*')`
    next to `metadata:(indexPattern:'wrong-index')`, and not by `wazuh-events-v5*-other`. An
    entry of any other shape is not a rule this function knows, and fails the landing.
    """
    text = str(wanted or "").strip()
    want_query = STATE_QUERY_RE.match(text)
    want_path = None if want_query else STATE_PATH_RE.match(text)
    if not (want_query or want_path):
        return "#{0} has an unsupported state entry {1}".format(key, wanted)
    state = parse_rison(value)
    if state is None:
        return "#{0} is not readable rison".format(key)
    if want_query:
        got = root_kuery(state)
        if got is None:
            return "#{0} without query:(language:kuery,query:…)".format(key)
        if got != want_query.group(1):
            return "#{0} without {1}".format(key, wanted)
        return ""
    got = rison_path(state, want_path.group(1))
    if not isinstance(got, str) or got != want_path.group(2):
        return "#{0} without {1}".format(key, wanted)
    return ""


def landing_reason(url, missing=None, suffix=""):
    """'landed on <url>' — plus '(missing <problem>)' when the landing was not what was asked."""
    text = "landed on {0}".format(url)
    if missing:
        text = "{0} (missing {1})".format(text, ", ".join(str(m) for m in missing))
    return "{0}{1}".format(text, suffix)


def view_verdict(app, final_url, landing, assertions_results):
    """Verdict of a view check from where the browser landed and how the assertions went.

    app:      the app id of the candidate that was used (for the reason line only).
    landing:  (ok, problems) as landing_ok returned for `final_url`.
    assertions_results: [{"kind", "value", "ok", "reason"}] as evaluated on the page.

    Returns (ok, reason).
    """
    ok, problems = landing if landing is not None else (False, ["no landing"])
    if not ok:
        return (False, landing_reason(final_url or "", problems))
    for assertion in assertions_results or []:
        if not assertion.get("ok"):
            return (False, assertion.get("reason") or "assertion failed: {0}".format(assertion))
    return (True, "app={0} url={1}".format(app, final_url))


# --------------------------------------------------------------------------- rows


def grid_rows(cells):
    """Rows of a virtualised EuiDataGrid from its cells —
    [[column, top, bottom, text, left, right, truncated], …].

    The grid renders NO row element: every cell is absolutely positioned, so a row is the set
    of cells drawn at the SAME top, exactly. There is no tolerance on purpose: 100 px and
    101 px are two rows, and a tolerance wide enough to merge them would let a value of the
    row below satisfy this row (which is what a token search over a joined text did).
    Column identity comes from the header the cell shares its `left` with, resolved in the
    browser; here it is already the column name.

    Each cell also keeps its own horizontal extent and whether it was TRUNCATED on screen, in
    `row["cells"][column]`: a value that reads `wazuh-states-inven…` in the PNG is not the
    value the assertion compared (the browser hands back the full innerText), and a column
    drawn past the right edge of the viewport is not in the screenshot at all (D-8b).
    """
    rows = []
    index = {}
    for cell in cells or []:
        values = list(cell) + [None] * 7
        column, top, bottom, text = values[0], values[1], values[2], values[3]
        left, right, truncated = values[4], values[5], values[6]
        if column is None or top is None:
            continue
        key = int(top)
        if key not in index:
            index[key] = {"columns": {}, "cells": {}, "top": key, "bottom": int(bottom or top)}
            rows.append(index[key])
        row = index[key]
        row["columns"][str(column)] = "" if text is None else str(text)
        row["cells"][str(column)] = {
            "left": None if left is None else int(left),
            "right": None if right is None else int(right),
            "truncated": bool(truncated),
        }
        row["bottom"] = max(row["bottom"], int(bottom if bottom is not None else top))
    return sorted(rows, key=lambda r: r["top"])


def row_values(row):
    """{column: value} of one extracted row, each value stripped."""
    return {str(k): str(v).strip() for k, v in ((row or {}).get("columns") or {}).items()}


def rows_matching(rows, wanted):
    """The rows whose columns EQUAL every wanted (column, value) — D-8b.

    Exact equality per column after strip(), never a substring and never a token over the
    joined row: `wget.old` is not `wget`, `3.118ubuntu5.1` is not `3.118ubuntu5`, `inactive`
    is not `active`, and a value of the next column is not this column's. A column the row
    does not have is a mismatch, not an absence.
    """
    spec = {str(k): str(v).strip() for k, v in (wanted or {}).items()}
    if not spec:
        return []
    out = []
    for row in rows or []:
        values = row_values(row)
        if all(column in values and values[column] == value for column, value in spec.items()):
            out.append(row)
    return out


def cell_of(row, column):
    """The geometry the browser measured for one column of a row ({left, right, truncated}),
    or {} when the extractor did not report it."""
    return ((row or {}).get("cells") or {}).get(str(column)) or {}


def row_in_frame(row, viewport_h, viewport_w=None, columns=()):
    """Was the matched row inside the VIEWPORT? — on both axes. A measurement (V11).

    Vertically the whole row must be in the frame (top >= 0, bottom <= viewport height).
    Horizontally it is the ASSERTED columns that matter: a grid 1600 px wide in a 1280 px
    viewport still returns every cell's text, so a row can match column by column while the
    column that carries the proof was drawn off the right edge. With a known viewport width,
    every asserted column must have been measured and lie inside [0, width] to answer True.

    False no longer fails a view: the capture is full-page (V11), which is not a promise that the
    row is in it (a container that scrolls on its own is photographed as drawn). capture.py reports this as `frame_note.in_viewport`, never as a verdict.
    """
    if not isinstance(row, dict):
        return False
    top, bottom = row.get("top"), row.get("bottom")
    if top is None or bottom is None or not viewport_h:
        return False
    if not (int(top) >= 0 and int(bottom) <= int(viewport_h)):
        return False
    if not viewport_w:
        return True
    for column in columns or ():
        cell = cell_of(row, column)
        left, right = cell.get("left"), cell.get("right")
        if left is None or right is None:
            return False
        if int(left) < 0 or int(right) > int(viewport_w):
            return False
    return True


def row_frame_reason(row, viewport_h, viewport_w=None, columns=()):
    """Why a matched row was not inside the viewport — naming the axis and, on the horizontal
    one, the column that fell outside (or was never measured).

    Kept as the readable form of the measurement (V11 turned it into a note, not a verdict):
    it is what a reader consults when `frame_note.in_viewport` is false.
    """
    row = row or {}
    top, bottom = row.get("top"), row.get("bottom")
    vertical = "row outside the frame (top={0} bottom={1} viewport={2})".format(
        top, bottom, viewport_h)
    if top is None or bottom is None or not viewport_h:
        return vertical
    if not (int(top) >= 0 and int(bottom) <= int(viewport_h)):
        return vertical
    for column in columns or ():
        cell = cell_of(row, column)
        left, right = cell.get("left"), cell.get("right")
        if left is None or right is None:
            return "column {0} not measured in the frame".format(column)
        if viewport_w and (int(left) < 0 or int(right) > int(viewport_w)):
            return "column {0} outside the frame (left={1} right={2} viewport width={3})".format(
                column, left, right, viewport_w)
    return vertical


def truncated_columns(row, columns):
    """The asserted columns the browser drew TRUNCATED ('…'), in order. A measurement (V11).

    `innerText` returns the whole value of a cell that shows `python3-distupgra…` on screen,
    so the text the assertion compared can be wider than what the pixels show. That is worth
    saying — it travels in `frame_note.truncated_columns` and in the PASS line — but it is not
    a verdict: the row is proven by the exact per-column match, and the full-page PNG shows the
    cell as the dashboard drew it (V11: the crop is not the requirement).
    """
    return [str(c) for c in (columns or ()) if cell_of(row, c).get("truncated")]


def parse_hits(text):
    """The result count a view's counter shows, or None when it shows no number.

    The FIRST integer wins: 'Result (0/10)' is zero results out of ten sampled, so it must
    read 0 — not 10, and certainly not the 010 a digit-by-digit reading would produce.
    """
    match = HITS_RE.search(text or "")
    if not match:
        return None
    digits = "".join(c for c in match.group(0) if c.isdigit())
    return int(digits) if digits else None


def artifacts_ok(png_bytes, sidecar_written):
    """(ok, reason) — may this view report PASS? Only with a non-empty PNG and its sidecar
    on disk: a PASS whose screenshot silently failed is exactly the evidence nobody has."""
    if not sidecar_written:
        return (False, "sidecar not written")
    if png_bytes is None:
        return (False, "screenshot missing")
    if png_bytes <= 0:
        return (False, "screenshot empty (0 bytes)")
    return (True, "")


def png_size(header):
    """(width, height) of a PNG read from its own IHDR header, or None.

    A PNG starts with the 8-byte signature, then the first chunk's 4-byte length, its 4-byte
    type (`IHDR`) and then the width and the height, each a big-endian uint32 — i.e. bytes
    16..24 of the file. The capture is full-page (V11), so its height is whatever the page
    was: the manifest states the size it MEASURED here instead of repeating a viewport
    constant that no longer describes the file (D-10b: provenance is what was read).

    Anything that is not a PNG (`b"PNG-bytes"`, a truncated write, a JSON sidecar) is None,
    never a guess.
    """
    blob = bytes(header) if isinstance(header, (bytes, bytearray)) else b""
    if len(blob) < 24 or not blob.startswith(PNG_MAGIC) or blob[12:16] != b"IHDR":
        return None
    width = int.from_bytes(blob[16:20], "big")
    height = int.from_bytes(blob[20:24], "big")
    if width <= 0 or height <= 0:
        return None
    return (width, height)


# --------------------------------------------------------------------------- provenance


def sources_row(entries):
    """'| sources | capture.py `<sha256>` · … |' — the files that PRODUCED the captures.

    The manifest's HEAD is not provenance when the sources are uncommitted (staged, unstaged
    or untracked), and a hash of `git diff` misses staged and untracked content entirely
    (D-10b): the hash of each file as it was read is what pins the run.
    """
    body = " · ".join("{0} `{1}`".format(name, digest) for name, digest in entries or [])
    return "| sources | {0} |".format(body or "(none)")


def dashboard_version(status_doc):
    """The version OpenSearch Dashboards reports in `GET /api/status`, or ''.

    `{"version": {"number": "2.19.1", …}}` (and the bare `{"version": "…"}` some builds answer)
    — the number is the measurement; DASHBOARD_PACKAGE is only what the environment was
    DECLARED to ship, which is not the same claim (D-10b: provenance is what was read).
    """
    version = (status_doc or {}).get("version")
    if isinstance(version, dict):
        return str(version.get("number") or "")
    return str(version or "")


def dashboard_row(measured, declared):
    """'| dashboard | `<version>` |' when the version was read from the stack, else
    '| dashboard | declared <package> |' — a constant is never passed off as a measurement."""
    if measured:
        return "| dashboard | `{0}` |".format(measured)
    return "| dashboard | declared {0} |".format(declared)


def git_status_row(porcelain):
    """'| git status | clean |' or the porcelain lines themselves, on one table row."""
    text = (porcelain or "").strip()
    if not text:
        return "| git status | clean |"
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "| git status | `{0}` |".format("; ".join(lines))


# --------------------------------------------------------------------------- vd


def probe_state(probe):
    probe = probe or {}
    return "status={0} offset={1} last_successful_update={2}".format(
        probe.get("status"), int(probe.get("offset") or 0),
        int(probe.get("last_successful_update") or 0),
    )


def probe_blocks(probe):
    """(status, reason) when the probe alone settles check 9, else None.

    capture.py asks this BEFORE querying the indexer: a feed that is unreachable, disabled or
    failed is the verdict, and counting findings first would both waste the query and let a
    findings error mask the real cause.
    """
    if not isinstance(probe, dict) or not probe:
        return ("FAIL", "probe unreachable")
    if probe.get("error"):
        return ("FAIL", "probe unreachable: {0}".format(probe["error"]))
    if probe.get("enabled") is False:
        return ("SKIP", "vulnerability-detector disabled in config")
    if probe.get("status") == "failed":
        return ("FAIL", "feed status=failed, {0}".format(probe_state(probe)))
    return None


def vd_verdict(probe, findings, agent_id_5x=""):
    """Verdict of check 9 from the probe and the per-agent findings.

    probe: the JSON of GET /vulnerability-detector/status
           {available, enabled, status: ready|updating|failed, offset, last_successful_update},
           None/{} when the socket could not be reached, or {"error": "..."}.
           capture.py only calls this once it has stopped polling, so a probe still in
           'updating' means the --vd-deadline was exhausted.
    findings: {agent_id: count} from _count on wazuh-states-vulnerabilities*, one query per
           agent. Only the count of THIS run's 5.x agent decides: a sum lets another agent's
           documents pass for the one the view is filtered by.

    Returns (status, reason) with status in PASS|FAIL|SKIP.
    """
    blocked = probe_blocks(probe)
    if blocked:
        return blocked
    state = probe_state(probe)
    available = bool(probe.get("available"))
    if not (available and probe.get("status") == "ready"
            and int(probe.get("offset") or 0) > 0
            and int(probe.get("last_successful_update") or 0) > 0):
        return ("FAIL", "feed not ready before deadline, available={0} {1}".format(available, state))
    if not agent_id_5x:
        return ("FAIL", "feed ready but no 5.x agent to count findings for, {0}".format(state))
    count = int((dict(findings or {})).get(agent_id_5x) or 0)
    if count >= 1:
        return ("PASS", "feed ready, {0} findings indexed for agent {1}".format(count, agent_id_5x))
    return ("FAIL", "feed ready, 0 findings indexed for agent {0}".format(agent_id_5x))


def probe_source(probe_json, vd_socket):
    """Where check 9's probe comes from: ("file", path) with --probe-json (the UDS socket is
    never opened), else ("socket", --vd-socket)."""
    if probe_json:
        return ("file", probe_json)
    return ("socket", vd_socket)


# --------------------------------------------------------------------------- documents


def dig(source, path):
    """source['a']['b'] for 'a.b', '' when any step is missing. The indexer answers nested
    objects; a flattened key ('package.name' as one key) is accepted too."""
    node = source or {}
    if isinstance(node, dict) and path in node:
        return node[path] if node[path] is not None else ""
    for step in str(path).split("."):
        if not isinstance(node, dict) or step not in node:
            return ""
        node = node[step]
    return "" if node is None else node


def first_source(response):
    """The _source of the first hit of an indexer _search answer, or None."""
    hits = ((response or {}).get("hits") or {}).get("hits") or []
    if not hits:
        return None
    return hits[0].get("_source") or {}


def inventory_candidates(response):
    """[(package_name, package_version)] of a sampled PAGE of inventory documents, in the order
    the indexer returned them (sorted by package.name), without the nameless ones.

    The view asserts `rows_eq: 1` and `hits_eq: 1` on `package.name:"<sampled>"`, so the
    sample has to be a package with exactly ONE document for this agent: a multi-arch package
    (the same name for amd64 and i386) has two, and the view would fail on a truth about the
    data rather than on the dashboard. capture.py walks these candidates and keeps the first
    whose `_count` is 1.
    """
    hits = ((response or {}).get("hits") or {}).get("hits") or []
    out = []
    for hit in hits:
        source = (hit or {}).get("_source") or {}
        name = str(dig(source, "package.name") or "")
        if name:
            out.append((name, str(dig(source, "package.version") or "")))
    return out


def vulnerability_sample(response):
    """vulnerability.id of the sampled finding, "" when the search returned nothing."""
    source = first_source(response)
    if source is None:
        return ""
    return str(dig(source, "vulnerability.id") or "")
