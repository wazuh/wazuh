#!/usr/bin/env python3
"""Unit tests of the capture decisions — no network, no browser, no manager.

    cd src/engine/tools/devContainer/e2e/dashboard && python3 -m unittest -v test_capture_logic

They cover what a green capture run must not be able to fake: a view that landed somewhere
else, on another tab or on another dashboard; a row that is merely SIMILAR to the document
this run sampled from the indexer (`wget.old` for `wget`, `3.118ubuntu5.1` for
`3.118ubuntu5`, `inactive` for `active`); two rows where the filter promised one; a capture
that is not the whole page (V11) or whose frame note was not measured; a counter read from
another panel or from a scope that does not exist; an agent nobody vouched for (a 4.x id
behind `--agent-5x-id`); a feed that is
'ready' without ever having updated; a PASS without a PNG; a manifest that failed to be
written after a report said failed=0 — plus the two things that must never reach a shell or
a log: an unvalidated container/nonce and a credential.

capture.py is imported on purpose: Playwright is imported lazily inside Session, so the
assertion evaluator, the row extraction, the counter reader and the run orchestration are
exercised against a fake page and a temporary directory. The only files these tests touch
are the ones they create under tempfile.mkdtemp() and the sources they read (capture.py for
the static print check, views.json for its structure).
"""

import ast
import contextlib
import inspect
import io
import json
import os
import shutil
import tempfile
import unittest

from urllib.parse import urlsplit

import capture
import capture_logic as cl

AGENTS = [("001", "agent-4x-ubuntu", "v4.14.3"), ("002", "agent-5x-ubuntu", "v5.0.0")]

DASHBOARD = "https://localhost:443"

# The three URLs the live run of 2026-09-20 really landed on (verifier log, lines 17-20).
LIVE_AGENTS_URL = "https://localhost/app/endpoints-summary#/agents-preview/"
LIVE_DISCOVER_URL = (
    "https://localhost/app/data-explorer/discover#?_a=(discover:(columns:!(_source),"
    "isDirty:!f,sort:!()),metadata:(indexPattern:'wazuh-events-v5*',view:discover))"
    "&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-24h,to:now))"
    "&_q=(filters:!(),query:(language:kuery,query:'user.name:%22e2e-capture-6120a743%22'))"
)
LIVE_INVENTORY_URL = (
    "https://localhost/app/it-hygiene#/overview/?tab=it-hygiene&tabView=software"
    "&tabSubView=packages&_a=(filters:!(),query:(language:kuery,query:'wazuh.agent.id:%22002%22"
    "%20and%20package.name:%22adduser%22'))&_g=(filters:!(),refreshInterval:(pause:!t,value:0),"
    "time:(from:now-24h,to:now))"
)
# The Discover URL of the v7c run (2026-09-21 02:26:21 UTC), verbatim.
LIVE_DISCOVER_URL_V7C = (
    "https://localhost/app/data-explorer/discover#?_a=(discover:(columns:!(user.name,"
    "wazuh.agent.name,wazuh.protocol.location),isDirty:!f,sort:!()),metadata:(indexPattern:"
    "'wazuh-events-v5*',view:discover))&_g=(filters:!(),refreshInterval:(pause:!t,value:0),"
    "time:(from:now-24h,to:now))&_q=(filters:!(),query:(language:kuery,query:"
    "'user.name:%22e2e-capture-212f708f%22'))"
)
# The vd view was never opened live (0 findings, P6): this is its route rendered for the ctx
# of these tests, which is what the capturer asks the browser for.
LIVE_VD_URL = (
    "https://localhost/app/vulnerability-detection#/overview/?tab=vuls&tabView=inventory"
    "&_a=(filters:!(),query:(language:kuery,query:'wazuh.agent.id:%22002%22%20and%20"
    "vulnerability.id:%22CVE-2024-38428%22'))&_g=(filters:!(),refreshInterval:(pause:!t,"
    "value:0),time:(from:now-24h,to:now))"
)

VIEWS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "views.json")


def probe(status="ready", enabled=True, available=True, offset=991021, lsu=1789793031):
    return {
        "available": available,
        "enabled": enabled,
        "status": status,
        "offset": offset,
        "last_successful_update": lsu,
    }


def ctx_of(**kwargs):
    ctx = {
        "nonce": "e2e-capture-1a2b3c4d",
        "agent_ids": ["001", "002"],
        "agent_names": ["agent-4x-ubuntu", "agent-5x-ubuntu"],
        "agent_id_5x": "002",
        "agent_name_5x": "agent-5x-ubuntu",
        "package_5x": {"name": "wget", "version": "1.21.4-1ubuntu4"},
        "cve_5x": "CVE-2024-38428",
    }
    ctx.update(kwargs)
    return ctx


def row(columns, top=100, bottom=132, left=0, right=200, truncated=False):
    """One extracted row, with the per-cell geometry the browser reports: the frame check is
    horizontal as well as vertical, and a truncated cell is not evidence (D-8b)."""
    return {"columns": dict(columns),
            "cells": {str(k): {"left": left, "right": right, "truncated": truncated}
                      for k in columns},
            "top": top, "bottom": bottom}


def views_json():
    with open(VIEWS_FILE) as handle:
        return json.load(handle)


# --------------------------------------------------------------------------- fake page


class RotatedLogs(unittest.TestCase):
    """The scanner evidence of the VD failure must survive the manager's midnight log rotation."""

    def test_the_scanner_line_is_found_in_a_rotated_gz_log(self):
        import gzip, os, tempfile, types
        import capture
        home = tempfile.mkdtemp(prefix="e2e-home-")
        os.makedirs(os.path.join(home, "logs", "wazuh", "2026", "Sep"))
        with open(os.path.join(home, "logs", "wazuh-manager.log"), "w") as fh:
            fh.write("2026/09/21 00:00:01 fresh log\n")
        line = ("2026/09/20 16:11:20 wazuh-modulesd:vulnerability-scanner: INFO: Vulnerability scan completed: "
                "agent='002' type=delta reason=package_delta option=VDSync")
        with gzip.open(os.path.join(home, "logs", "wazuh", "2026", "Sep", "wazuh-20.log.gz"), "wb") as fh:
            fh.write((line + "\n").encode())
        args = types.SimpleNamespace(home=home)
        self.assertIn("scan completed: agent='002'", capture.last_scanner_log(args, ["001", "002"]))
        self.assertEqual("", capture.last_scanner_log(args, ["003"]))


class FakeLocator:
    """A locator that only resolves the exact chain it was built from, so a selector used
    outside its scope resolves to nothing — which is the behaviour under test."""

    def __init__(self, page, chain):
        self.page = page
        self.chain = chain

    def locator(self, selector):
        return FakeLocator(self.page, self.chain + (selector,))

    @property
    def texts(self):
        return self.page.elements.get(self.chain, [])

    @property
    def first(self):
        return self

    def count(self):
        return len(self.texts)

    def inner_text(self):
        return self.texts[0] if self.texts else ""

    def all_inner_texts(self):
        return list(self.texts)

    def click(self, timeout=None):
        self.page.clicked.append(self.chain)

    def fill(self, text):
        self.page.filled.append((self.chain, text))

    def press(self, key):
        self.page.pressed.append((self.chain, key))


class FakePage:
    """Enough of a Playwright page to run the real evaluator and the real run_view.

    `tables` maps a scope selector to what the extraction script would return for it
    ({"kind": "grid", "cells": [...]} or {"rows": [...]}, or {"error": "..."}).
    """

    def __init__(self, elements=None, tables=None, urls=None, drift_url=None,
                 drift_selector=None, png=b"PNG-bytes"):
        self.elements = dict(elements or {})
        self.tables = dict(tables or {})
        self.urls = list(urls or [])
        self.url = self.urls[0] if self.urls else ""
        self.drift_url = drift_url
        self.drift_selector = drift_selector
        self.png = png
        self.gotos = []
        self.clicked = []
        self.filled = []
        self.pressed = []
        self.screenshots = []

    def goto(self, url, wait_until=None, timeout=None):
        self.gotos.append(url)
        if self.urls:
            self.url = self.urls[min(len(self.gotos) - 1, len(self.urls) - 1)]
        else:
            self.url = url

    def wait_for_selector(self, selector, timeout=None):
        # the view navigated itself elsewhere while we waited for its data
        if self.drift_url and selector == self.drift_selector:
            self.url = self.drift_url
        return True

    def wait_for_timeout(self, milliseconds):
        return None

    def locator(self, selector):
        return FakeLocator(self, (selector,))

    def evaluate(self, script, spec=None):
        scope = (spec or {}).get("scope")
        if scope not in self.tables:
            return {"error": "scope missing: {0}".format(scope)}
        return dict(self.tables[scope])

    def screenshot(self, path=None, full_page=False):
        # The kwargs are recorded, not only the path: `full_page` is what V11 changed, and the
        # default here is Playwright's own (False), so a capture that quietly went back to the
        # viewport crop — or that stopped passing the argument — fails a test.
        self.screenshots.append({"path": path, "full_page": full_page})
        with open(path, "wb") as handle:
            handle.write(self.png)
        return path


class FakeSession:
    def __init__(self, page):
        self.page = page
        self.api_calls = {"total": 0, "status_ge_400": []}


class TempRun(unittest.TestCase):
    """A test that needs an --out directory and parsed args."""

    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="capture-test-")
        self.addCleanup(shutil.rmtree, self.out, True)

    def args_for(self, extra=None):
        args = capture.parse_args(["--out", self.out] + list(extra or []))
        return args


# --------------------------------------------------------------------------- 1. shell


class ShellSafety(unittest.TestCase):
    def test_nonce_rejects_shell_metacharacters(self):
        for bad in ("e2e-capture-abcd; rm -rf /", "e2e-capture-$(id)", "e2e-capture-a b",
                    "e2e-capture-`id`", "e2e-capture-abcd\nwhoami", "", "rm -rf /",
                    "e2e-capture-abc"):
            with self.assertRaises(ValueError, msg=bad):
                cl.validate_nonce(bad)

    def test_nonce_accepts_the_minted_shape(self):
        self.assertEqual("e2e-capture-1a2b3c4d", cl.validate_nonce("e2e-capture-1a2b3c4d"))
        self.assertEqual("e2e-capture-a.b_c-d", cl.validate_nonce("e2e-capture-a.b_c-d"))

    def test_container_rejects_shell_metacharacters(self):
        for bad in ("wazuh-agent; id", "wazuh agent", "$(id)", "-rm", "", "a" * 65, "a/b"):
            with self.assertRaises(ValueError, msg=bad):
                cl.validate_container(bad)
        self.assertEqual("wazuh-agent-5x-ubuntu", cl.validate_container("wazuh-agent-5x-ubuntu"))

    def test_docker_exec_is_argv_with_a_constant_program(self):
        argv = cl.docker_exec_argv("wazuh-agent-5x-ubuntu")
        self.assertEqual(
            ["docker", "exec", "-i", "wazuh-agent-5x-ubuntu", "sh", "-c",
             "cat >> /var/log/dpkg.log"], argv)
        self.assertNotIn("echo", " ".join(argv))  # the line travels on stdin, not in the program
        with self.assertRaises(ValueError):
            cl.docker_exec_argv("wazuh-agent; id")

    def test_nonce_line_is_validated_too(self):
        line = cl.syslog_nonce_line("e2e-capture-1a2b3c4d", "host", "Sep 20 10:00:00")
        self.assertIn("invalid user e2e-capture-1a2b3c4d", line)
        with self.assertRaises(ValueError):
            cl.syslog_nonce_line("$(id)", "host", "Sep 20 10:00:00")


# --------------------------------------------------------------------------- 2. secrets


class Secrets(unittest.TestCase):
    def test_redact_replaces_every_secret(self):
        self.assertEqual('fill("***")', cl.redact('fill("S3cret")', ["S3cret"]))
        self.assertNotIn("S3cret", cl.redact("user admin pass S3cret", ["S3cret", "admin"]))

    def test_redact_kills_the_url_form_whole(self):
        secrets = cl.secrets_of("admin", "S3cret", "admin", "S3cret")
        line = cl.redact("https://admin:S3cret@localhost:9200/_cluster/health", secrets)
        self.assertNotIn("S3cret", line)
        self.assertNotIn("admin:", line)
        self.assertIn("***", line)

    def test_redact_a_playwright_timeout(self):
        # Playwright echoes the value it was asked to fill; the report must not.
        text = 'TimeoutError: locator.fill: Timeout 30000ms exceeded.\ncalling fill("S3cret")'
        clean = cl.redact(text, cl.secrets_of("admin", "S3cret", "admin", "S3cret"))
        self.assertNotIn("S3cret", clean)
        self.assertIn("TimeoutError", clean)

    def test_redact_survives_non_strings(self):
        self.assertEqual("", cl.redact(None, ["x"]))
        self.assertEqual("7", cl.redact(7, []))

    def test_a_quoted_password_does_not_survive_serialization(self):
        # json.dumps escapes the quote, so redacting the DUMPED text leaves s\"ecret behind:
        # the object is redacted first (D-10b).
        secrets = cl.secrets_of("admin", 's"ecret', "admin", 's"ecret')
        data = {"reason": 'fill("s"ecret") failed', "urls": ["https://admin:s\"ecret@localhost"],
                "nested": {"body": 's"ecret'}, "count": 7, "ok": False}
        dumped = json.dumps(cl.redact_obj(data, secrets))
        self.assertNotIn('s"ecret', dumped)
        self.assertNotIn('s\\"ecret', dumped)
        self.assertIn("***", dumped)
        self.assertIn('"count": 7', dumped)
        self.assertIn('"ok": false', dumped)
        # the naive order (dump, then redact) is what used to leak
        self.assertIn('s\\"ecret', cl.redact(json.dumps(data), secrets))

    def test_redact_obj_walks_keys_lists_and_tuples(self):
        out = cl.redact_obj({"S3cret": ["a", ("S3cret", 1)]}, ["S3cret"])
        self.assertEqual({"***": ["a", ["***", 1]]}, out)

    def test_credentials_in_a_url_are_refused_not_redacted(self):
        self.assertEqual(
            "credentials in --dashboard-url are not accepted; use DASHBOARD_USER/PASSWORD",
            cl.url_credentials_problem("https://admin:S3cret@localhost:443", "--dashboard-url"))
        self.assertEqual(
            "credentials in --indexer-url are not accepted; use INDEXER_USER/PASSWORD",
            cl.url_credentials_problem("https://admin:S3cret@localhost:9200", "--indexer-url"))
        self.assertEqual("", cl.url_credentials_problem(DASHBOARD, "--dashboard-url"))
        self.assertEqual("", cl.url_credentials_problem("", "--dashboard-url"))

    def test_safe_url_removes_the_userinfo(self):
        self.assertEqual("https://localhost:9200/x",
                         cl.safe_url("https://admin:S3cret@localhost:9200/x"))
        self.assertEqual(DASHBOARD, cl.safe_url(DASHBOARD))

    def test_no_bare_print(self):
        """Every print( of capture.py lives inside class Reporter — nothing else may write to
        stdout, because only the Reporter redacts what it prints (D-10b)."""
        path = inspect.getsourcefile(capture)
        with open(path) as handle:
            source = handle.read()
        tree = ast.parse(source)
        reporter = [node for node in ast.walk(tree)
                    if isinstance(node, ast.ClassDef) and node.name == "Reporter"]
        self.assertEqual(1, len(reporter))
        inside = range(reporter[0].lineno, (reporter[0].end_lineno or reporter[0].lineno) + 1)
        calls = [node.lineno for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == "print"]
        self.assertTrue(calls, "capture.py prints nothing at all?")
        self.assertEqual([], [n for n in calls if n not in inside],
                         "print() outside class Reporter at lines {0}".format(
                             [n for n in calls if n not in inside]))
        self.assertNotIn("sys.stdout", source)  # nor a write() that bypasses the Reporter
        self.assertEqual(0, source.count("row_text"))
        self.assertEqual(0, source.count("url_must_contain"))


# --------------------------------------------------------------------------- 3. landing


class Landing(unittest.TestCase):
    def landing_of(self, view, **values):
        cfg = views_json()[view]
        return cl.render_landing(cfg["landing"], values)

    def test_the_urls_of_the_live_run_land(self):
        self.assertEqual((True, []), cl.landing_ok(
            LIVE_AGENTS_URL, DASHBOARD, self.landing_of("agents")))
        self.assertEqual((True, []), cl.landing_ok(
            LIVE_DISCOVER_URL, DASHBOARD, self.landing_of("discover",
                                                          nonce="e2e-capture-6120a743")))
        self.assertEqual((True, []), cl.landing_ok(
            LIVE_INVENTORY_URL, DASHBOARD,
            self.landing_of("inventory", agent_id_5x="002", package_name="adduser")))

    def test_the_default_port_is_the_same_origin(self):
        # the browser drops :443 from the URL it reports; --dashboard-url carries it
        self.assertEqual("https://localhost:443", cl.origin_of("https://localhost/app/x"))
        self.assertEqual("https://localhost:443", cl.origin_of(DASHBOARD))
        self.assertEqual("http://localhost:80", cl.origin_of("http://localhost/app/x"))

    def test_another_origin_is_never_this_dashboard(self):
        url = LIVE_INVENTORY_URL.replace("https://localhost/", "https://evil.example/")
        ok, problems = cl.landing_ok(
            url, DASHBOARD, self.landing_of("inventory", agent_id_5x="002",
                                            package_name="adduser"))
        self.assertFalse(ok)
        self.assertTrue(any("origin" in p for p in problems), problems)
        # the same path on another port is another origin too
        self.assertFalse(cl.landing_ok(LIVE_AGENTS_URL.replace("localhost", "localhost:5601"),
                                       DASHBOARD, self.landing_of("agents"))[0])

    def test_the_expected_text_inside_note_does_not_fake_a_landing(self):
        # /app/it-hygiene?note=<everything the checker used to look for>#/overview/?tabView=hardware
        url = ("https://localhost/app/it-hygiene?note=tab%3Dit-hygiene%26tabView%3Dsoftware"
               "%26tabSubView%3Dpackages%26_a%3D(query:'wazuh.agent.id:%22002%22%20and%20"
               "package.name:%22adduser%22')#/overview/?tabView=hardware")
        ok, problems = cl.landing_ok(
            url, DASHBOARD,
            self.landing_of("inventory", agent_id_5x="002", package_name="adduser"))
        self.assertFalse(ok)
        self.assertIn("#tabView=software", problems)
        self.assertIn("#tab=it-hygiene", problems)
        self.assertIn("#_a missing", problems)

    def test_a_path_that_merely_starts_with_the_views_path_is_not_the_view(self):
        """The path is compared with EQUALITY, in both directions: `/app/it-hygiene-legacy`
        starts with the view's path and `/app/it` is a prefix of it, and neither is the view
        (a prefix comparison would accept one of them)."""
        wanted = self.landing_of("inventory", agent_id_5x="002", package_name="adduser")
        for path in ("/app/it-hygiene-legacy", "/app/it-hygiene2", "/app/it", "/app/it-hygien",
                     "/app/it-hygiene/nested"):
            url = LIVE_INVENTORY_URL.replace("/app/it-hygiene#", path + "#")
            ok, problems = cl.landing_ok(url, DASHBOARD, wanted)
            self.assertFalse(ok, path)
            self.assertIn("path /app/it-hygiene", problems)
        # the real one still lands, and a trailing slash is the same path
        self.assertEqual((True, []), cl.landing_ok(LIVE_INVENTORY_URL, DASHBOARD, wanted))
        self.assertEqual((True, []), cl.landing_ok(
            LIVE_INVENTORY_URL.replace("/app/it-hygiene#", "/app/it-hygiene/#"), DASHBOARD,
            wanted))

    def test_a_duplicated_state_parameter_is_never_read_as_one(self):
        """Two `_a=` in one fragment are two contradictory states; reading `got[0]` was a coin
        toss. The landing says so and fails, for the asserted parameter and for the others."""
        wanted = self.landing_of("inventory", agent_id_5x="002", package_name="adduser")
        empty = "&_a=(filters:!(),query:(language:kuery,query:''))"
        ok, problems = cl.landing_ok(LIVE_INVENTORY_URL + empty, DASHBOARD, wanted)
        self.assertFalse(ok)
        self.assertEqual(["duplicated state parameter _a"], problems)
        # …in either order: the good one second does not save it
        head, _sep, tail = LIVE_INVENTORY_URL.partition("&_a=")
        swapped = head + empty + "&_a=" + tail
        self.assertEqual(["duplicated state parameter _a"],
                         cl.landing_ok(swapped, DASHBOARD, wanted)[1])
        # a state parameter this view does not assert is checked too: `_g` twice is ambiguous
        ok, problems = cl.landing_ok(
            LIVE_INVENTORY_URL + "&_g=(time:(from:now-7d,to:now))", DASHBOARD, wanted)
        self.assertFalse(ok)
        self.assertEqual(["duplicated state parameter _g"], problems)
        self.assertEqual(("_a", "_q", "_g"), cl.STATE_PARAMS)

    def test_a_login_redirect_is_not_the_view(self):
        url = "https://localhost/app/wz-home?next=/app/it-hygiene&note=tabView=software"
        ok, problems = cl.landing_ok(
            url, DASHBOARD,
            self.landing_of("inventory", agent_id_5x="002", package_name="adduser"))
        self.assertFalse(ok)
        self.assertIn("path /app/it-hygiene", problems)

    def test_the_state_must_carry_this_runs_filter(self):
        other = LIVE_INVENTORY_URL.replace("adduser", "wget")
        ok, problems = cl.landing_ok(
            other, DASHBOARD,
            self.landing_of("inventory", agent_id_5x="002", package_name="adduser"))
        self.assertFalse(ok)
        self.assertEqual(1, len(problems))
        self.assertIn('#_a without query:\'wazuh.agent.id:"002" and package.name:"adduser"\'',
                      problems)
        # another agent's filter is not this run's either
        self.assertFalse(cl.landing_ok(
            LIVE_INVENTORY_URL, DASHBOARD,
            self.landing_of("inventory", agent_id_5x="003", package_name="adduser"))[0])

    def test_the_query_of_the_root_is_the_only_query_of_the_view(self):
        # the probe of the FIFTH review: a perfectly valid rison whose `metadata:` carries the
        # expected clause while the view's own query is EMPTY. The old check searched
        # `query:(language:kuery,query:'…')` at ANY depth and took the first match, so this
        # passed — with a dashboard showing everything.
        wanted = self.landing_of("inventory", agent_id_5x="002", package_name="adduser")
        url = ("https://localhost/app/it-hygiene#/overview/?tab=it-hygiene&tabView=software"
               "&tabSubView=packages&_a=(metadata:(query:(language:kuery,query:'wazuh.agent.id"
               ":%22002%22%20and%20package.name:%22adduser%22')),query:(language:kuery,"
               "query:''))")
        state = cl.split_fragment(urlsplit(url).fragment)[1]["_a"][0]
        # the nested clause really is the exact text a search at any depth would have found…
        self.assertIn("query:(language:kuery,query:'{0}')".format(
            'wazuh.agent.id:"002" and package.name:"adduser"'), state)
        self.assertIsNotNone(cl.parse_rison(state))  # and it is valid rison, not a mangled URL
        # …while the root clause — the one the view renders — is empty
        self.assertEqual("", cl.rison_kuery(state))
        ok, problems = cl.landing_ok(url, DASHBOARD, wanted)
        self.assertFalse(ok, problems)
        self.assertEqual(['#_a without query:\'wazuh.agent.id:"002" and '
                          'package.name:"adduser"\''], problems)
        # the same clause carried by a filter chip (valid rison, three levels down) is not it
        # either, and the parameter is named in the problem
        chip = ("https://localhost/app/it-hygiene#/overview/?tab=it-hygiene&tabView=software"
                "&tabSubView=packages&_a=(filters:!((meta:(alias:'chip',query:(language:kuery,"
                "query:'wazuh.agent.id:%22002%22%20and%20package.name:%22adduser%22')))),"
                "query:(language:kuery,query:''))")
        chip_state = cl.split_fragment(urlsplit(chip).fragment)[1]["_a"][0]
        self.assertIsNotNone(cl.parse_rison(chip_state))
        self.assertEqual("", cl.rison_kuery(chip_state))
        self.assertEqual(['#_a without query:\'wazuh.agent.id:"002" and '
                          'package.name:"adduser"\''],
                         cl.landing_ok(chip, DASHBOARD, wanted)[1])

    def test_a_filter_label_is_not_the_views_query(self):
        # the probe of the fourth review: the rison carries `query:'…'` inside a FILTER's
        # display label (meta.alias) while its own query is EMPTY. A substring search over the
        # decoded rison accepted it; the label's unescaped quotes are not readable rison at
        # all, and an unreadable state is a loud failure, never a pass.
        wanted = self.landing_of("inventory", agent_id_5x="002", package_name="adduser")
        url = ("https://localhost/app/it-hygiene#/overview/?tab=it-hygiene&tabView=software"
               "&tabSubView=packages&_a=(filters:!((meta:(alias:'query:'wazuh.agent.id:%22002"
               "%22%20and%20package.name:%22adduser%22''))),query:(language:kuery,query:''))")
        # the label really does carry the exact text the old substring check looked for…
        state = cl.split_fragment(urlsplit(url).fragment)[1]["_a"][0]
        self.assertIn(wanted["state"]["_a"], state)
        # …and the view's own query is empty, so this is not the view that was asked for
        ok, problems = cl.landing_ok(url, DASHBOARD, wanted)
        self.assertFalse(ok, problems)
        self.assertEqual(["#_a is not readable rison"], problems)
        # the same label with rison's own escape (`!'`) IS readable, and still fails on the
        # root's empty query rather than on the label that quotes it
        escaped = url.replace("alias:'query:'wazuh", "alias:'query:!'wazuh").replace(
            "%22adduser%22''", "%22adduser%22!''")
        self.assertEqual(['#_a without query:\'wazuh.agent.id:"002" and '
                          'package.name:"adduser"\''],
                         cl.landing_ok(escaped, DASHBOARD, wanted)[1])
        # and a state with no query clause at all names what is missing
        no_clause = ("https://localhost/app/it-hygiene#/overview/?tab=it-hygiene"
                     "&tabView=software&tabSubView=packages&_a=(filters:!())")
        self.assertEqual(["#_a without query:(language:kuery,query:…)"],
                         cl.landing_ok(no_clause, DASHBOARD, wanted)[1])

    def test_the_rison_of_the_live_run_is_parsed_as_a_structure(self):
        """The three state values the live run of 2026-09-20 really landed with, as
        `parse_qs` hands them over (percent-decoded)."""
        a = ("(filters:!(),query:(language:kuery,query:'wazuh.agent.id:\"002\" and "
             "package.name:\"adduser\"'))")
        q = "(filters:!(),query:(language:kuery,query:'user.name:\"e2e-capture-33975136\"'))"
        g = "(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-24h,to:now))"
        discover_a = ("(discover:(columns:!(user.name,wazuh.agent.name,"
                      "wazuh.protocol.location),isDirty:!f,sort:!()),"
                      "metadata:(indexPattern:'wazuh-events-v5*',view:discover))")
        self.assertEqual('wazuh.agent.id:"002" and package.name:"adduser"', cl.rison_kuery(a))
        self.assertEqual('user.name:"e2e-capture-33975136"', cl.rison_kuery(q))
        self.assertEqual({"filters": [], "refreshInterval": {"pause": True, "value": "0"},
                          "time": {"from": "now-24h", "to": "now"}}, cl.parse_rison(g))
        self.assertEqual(
            {"discover": {"columns": ["user.name", "wazuh.agent.name",
                                      "wazuh.protocol.location"],
                          "isDirty": False, "sort": []},
             "metadata": {"indexPattern": "wazuh-events-v5*", "view": "discover"}},
            cl.parse_rison(discover_a))
        self.assertIsNone(cl.rison_kuery(discover_a))  # Discover's filter lives in `_q`
        # …and the landing of that very run still holds, parsed
        self.assertEqual((True, []), cl.landing_ok(
            LIVE_INVENTORY_URL, DASHBOARD,
            self.landing_of("inventory", agent_id_5x="002", package_name="adduser")))

    def test_parse_rison_reads_the_subset_and_refuses_the_rest(self):
        self.assertEqual({}, cl.parse_rison("()"))
        self.assertEqual({"a": "1", "b": None, "c": True}, cl.parse_rison("(a:1,b:!n,c:!t)"))
        self.assertEqual({"a": ["x", {"b": []}]}, cl.parse_rison("(a:!(x,(b:!())))"))
        self.assertEqual({"a": "it's"}, cl.parse_rison("(a:'it!'s')"))  # !' is a quote
        self.assertEqual({"a": "!"}, cl.parse_rison("(a:'!!')"))        # !! is a bang
        for bad in ("(a:1", "(a:1))", "(a:)", "(a)", "(a:'unterminated)", "", None,
                    "(a:1),junk", "(a:!x)", "(a:'x'trailing)"):
            self.assertIsNone(cl.parse_rison(bad), repr(bad))
        # a root query clause is only a query clause when it says what language it is
        self.assertIsNone(cl.rison_kuery("(query:(language:lucene,query:'x'))"))
        self.assertIsNone(cl.rison_kuery("(query:'x')"))
        self.assertIsNone(cl.rison_kuery("(query:(language:kuery,query:!(a)))"))
        self.assertEqual("x", cl.rison_kuery("(query:(language:kuery,query:'x'))"))

    def test_the_query_clause_is_compared_whole(self):
        self.assertEqual('wazuh.agent.id:"002"', cl.rison_kuery(
            "(filters:!(),query:(language:kuery,query:'wazuh.agent.id:\"002\"'))"))
        self.assertEqual("", cl.rison_kuery("(filters:!(),query:(language:kuery,query:''))"))
        self.assertIsNone(cl.rison_kuery("(filters:!())"))
        # a query that merely CONTAINS the asserted one is not the asserted one
        self.assertEqual(
            "#_a without query:'package.name:\"wget\"'",
            cl.state_problem("_a", "query:'package.name:\"wget\"'",
                             "(query:(language:kuery,query:'package.name:\"wget2\"'))"))
        self.assertEqual("", cl.state_problem(
            "_a", "query:'package.name:\"wget\"'",
            "(query:(language:kuery,query:'package.name:\"wget\"'))"))
        # non-query entries are a PATH of the parsed rison, compared exactly (v8): no 'contains'
        wanted = "metadata.indexPattern:'wazuh-events-v5*'"
        self.assertEqual("", cl.state_problem("_a", wanted,
                                              "(metadata:(indexPattern:'wazuh-events-v5*'))"))
        self.assertEqual("#_a without {0}".format(wanted), cl.state_problem(
            "_a", wanted, "(metadata:(indexPattern:'other*'))"))
        # the path is walked from the root: the same key one level deeper is not it
        self.assertEqual("#_a without {0}".format(wanted), cl.state_problem(
            "_a", wanted, "(x:(metadata:(indexPattern:'wazuh-events-v5*')))"))
        # an entry that is neither a query nor a path is no rule at all, and fails
        self.assertEqual("#_a has an unsupported state entry wazuh-events-v5*", cl.state_problem(
            "_a", "wazuh-events-v5*", "(metadata:(indexPattern:'wazuh-events-v5*'))"))
        self.assertEqual("#_a is not readable rison", cl.state_problem(
            "_a", wanted, "metadata:(indexPattern:'wazuh-events-v5*'"))
        self.assertIsNone(cl.rison_path({"a": ["b"]}, "a.0"))
        self.assertEqual("v", cl.rison_path({"a": {"b": "v"}}, "a.b"))

    def test_discover_queries_the_declared_index_pattern_and_no_other(self):
        """The probe of the SIXTH review: `metadata:(indexPattern:'wrong-index')` plus a
        `decoy:(indexPattern:'wazuh-events-v5*')` next to it. A substring check found the
        declared text in the decoy and the whole view PASSed on another index."""
        wanted = self.landing_of("discover", nonce="e2e-capture-212f708f")
        self.assertEqual("metadata.indexPattern:'wazuh-events-v5*'", wanted["state"]["_a"])
        # the v7c run's own `_a` (matrix.log:18) lands, parsed
        self.assertEqual((True, []), cl.landing_ok(LIVE_DISCOVER_URL_V7C, DASHBOARD, wanted))
        good = "metadata:(indexPattern:'wazuh-events-v5*',view:discover)"
        self.assertIn(good, LIVE_DISCOVER_URL_V7C)
        problem = ["#_a without metadata.indexPattern:'wazuh-events-v5*'"]
        # Codex's adversary: the real index is another one, the declared text sits in a decoy
        adversary = LIVE_DISCOVER_URL_V7C.replace(
            good, "metadata:(indexPattern:'wrong-index',view:discover),"
                  "decoy:(indexPattern:'wazuh-events-v5*')")
        self.assertIn("indexPattern:'wazuh-events-v5*'", adversary)
        self.assertEqual((False, problem), cl.landing_ok(adversary, DASHBOARD, wanted))
        # a prefix of the declared pattern is another pattern…
        prefix = LIVE_DISCOVER_URL_V7C.replace(
            good, "metadata:(indexPattern:'wazuh-events-v5',view:discover)")
        self.assertEqual((False, problem), cl.landing_ok(prefix, DASHBOARD, wanted))
        # …and so is a pattern the declared one is merely a prefix of
        longer = LIVE_DISCOVER_URL_V7C.replace(
            good, "metadata:(indexPattern:'wazuh-events-v5*-archive',view:discover)")
        self.assertEqual((False, problem), cl.landing_ok(longer, DASHBOARD, wanted))
        # and without `metadata` at all the view says what is missing
        bare = LIVE_DISCOVER_URL_V7C.replace(",metadata:(indexPattern:'wazuh-events-v5*',"
                                             "view:discover)", "")
        self.assertEqual((False, problem), cl.landing_ok(bare, DASHBOARD, wanted))

    def test_the_hash_route_is_exact(self):
        url = LIVE_INVENTORY_URL.replace("#/overview/?", "#/inventory/?")
        ok, problems = cl.landing_ok(
            url, DASHBOARD,
            self.landing_of("inventory", agent_id_5x="002", package_name="adduser"))
        self.assertFalse(ok)
        self.assertIn("#route /overview/", problems)

    def test_discover_needs_both_its_state_parameters(self):
        without_q = LIVE_DISCOVER_URL.split("&_q=")[0]
        ok, problems = cl.landing_ok(without_q, DASHBOARD,
                                     self.landing_of("discover", nonce="e2e-capture-6120a743"))
        self.assertFalse(ok)
        self.assertIn("#_q missing", problems)

    def test_view_verdict_reports_the_landing_and_then_the_assertions(self):
        landing = cl.landing_ok(LIVE_AGENTS_URL, DASHBOARD, self.landing_of("agents"))
        ok, reason = cl.view_verdict("endpoints-summary", LIVE_AGENTS_URL, landing,
                                     [{"ok": True}])
        self.assertTrue(ok)
        self.assertIn("app=endpoints-summary", reason)
        ok, reason = cl.view_verdict("endpoints-summary", LIVE_AGENTS_URL, landing,
                                     [{"ok": False, "reason": "2 rows match"}])
        self.assertFalse(ok)
        self.assertEqual("2 rows match", reason)
        ok, reason = cl.view_verdict("it-hygiene", "https://localhost/app/wz-home",
                                     (False, ["path /app/it-hygiene"]), [])
        self.assertFalse(ok)
        self.assertEqual("landed on https://localhost/app/wz-home (missing path /app/it-hygiene)",
                         reason)
        self.assertEqual("landed on x (missing a) after wait",
                         cl.landing_reason("x", ["a"], " after wait"))


# --------------------------------------------------------------------------- 4/5. data


class Agents(unittest.TestCase):
    def test_requested_id_must_be_active(self):
        ids, names, problem = cl.resolve_agents(["003"], AGENTS)
        self.assertEqual(([], []), (ids, names))
        self.assertEqual("not active in global.db: 003", problem)

    def test_requested_ids_keep_their_names(self):
        self.assertEqual((["002"], ["agent-5x-ubuntu"], ""), cl.resolve_agents(["002"], AGENTS))

    def test_no_agent_at_all(self):
        self.assertEqual(([], [], "no active agent"), cl.resolve_agents([], []))

    def test_the_5x_agent_must_really_be_5x(self):
        # the override used to relabel a 4.x agent as "the 5.x agent" of the run
        self.assertEqual(("002", "agent-5x-ubuntu", ""), cl.pick_agent_5x(AGENTS))
        self.assertEqual(
            ("", "", "--agent-5x-id 001 is not an active 5.x agent (v4.14.3)"),
            cl.pick_agent_5x(AGENTS, "001"))
        self.assertEqual(("", "", "--agent-5x-id 009 is not an active agent"),
                         cl.pick_agent_5x(AGENTS, "009"))
        self.assertEqual(("", "", "no active 5.x agent"), cl.pick_agent_5x([AGENTS[0]]))
        self.assertEqual(("002", "agent-5x-ubuntu", ""), cl.pick_agent_5x(AGENTS, "002"))
        self.assertEqual(("", "", "--agent-5x-id 001 is not an active 5.x agent (no version)"),
                         cl.pick_agent_5x([("001", "agent-4x-ubuntu", "")], "001"))

    def test_the_5x_agent_is_picked_among_the_requested_ids(self):
        # --agent-ids 001 used to report `agents=001` and `5x=002` in the same run: an agent
        # nobody asked about driving the inventory and vd views and the manifest
        agent_id, name, problem = cl.pick_agent_5x(AGENTS, "", ["001"])
        self.assertEqual(("", ""), (agent_id, name))
        self.assertEqual("no active 5.x agent among --agent-ids 001", problem)
        self.assertEqual(("002", "agent-5x-ubuntu", ""), cl.pick_agent_5x(AGENTS, "", ["002"]))
        self.assertEqual(("002", "agent-5x-ubuntu", ""),
                         cl.pick_agent_5x(AGENTS, "", ["001", "002"]))
        # the override must belong to the same set
        self.assertEqual(
            ("", "", "--agent-5x-id 002 is not an active agent among --agent-ids 001"),
            cl.pick_agent_5x(AGENTS, "002", ["001"]))
        # no --agent-ids: every active agent is in scope, as before
        self.assertEqual(("002", "agent-5x-ubuntu", ""), cl.pick_agent_5x(AGENTS, "", []))

    def test_is_5x(self):
        self.assertTrue(cl.is_5x("v5.0.0"))
        self.assertFalse(cl.is_5x("v4.14.3"))
        self.assertFalse(cl.is_5x(""))
        self.assertFalse(cl.is_5x(None))


class Placeholders(unittest.TestCase):
    def test_render(self):
        values = {"agent_id_5x": "002", "package_name": "wget", "agent_names": ["a", "b"]}
        self.assertEqual('wazuh.agent.id:"002" and package.name:"wget"', cl.render_query(
            'wazuh.agent.id:"{{agent_id_5x}}" and package.name:"{{package_name}}"', values))
        self.assertEqual("a,b", cl.render_query("{{agent_names}}", values))
        self.assertEqual("", cl.render_query("", values))

    def test_empty_placeholder_raises(self):
        for values in ({"agent_id_5x": ""}, {}, {"agent_id_5x": None}):
            with self.assertRaises(ValueError) as caught:
                cl.render_query('wazuh.agent.id:"{{agent_id_5x}}"', values)
            self.assertEqual("unresolved placeholder {{agent_id_5x}}", str(caught.exception))

    def test_agent_count_is_the_number_of_active_agents(self):
        values = capture.placeholder_values(ctx_of())
        self.assertEqual(2, values["agent_count"])
        self.assertEqual("2", cl.render_query("{{agent_count}}", values))
        self.assertIsNone(capture.placeholder_values(ctx_of(agent_names=[]))["agent_count"])

    def test_expand_row_without_names_requires_nothing_and_that_is_a_failure(self):
        self.assertEqual([], cl.expand_row({"name": "{{agent_names}}", "status": "active"},
                                           {"agent_names": []}))
        self.assertEqual(
            [{"name": "agent-4x-ubuntu", "status": "active"},
             {"name": "agent-5x-ubuntu", "status": "active"}],
            cl.expand_row({"name": "{{agent_names}}", "status": "active"},
                          {"agent_names": ["agent-4x-ubuntu", "agent-5x-ubuntu"]}))

    def test_expand_row_renders_the_sampled_document(self):
        self.assertEqual(
            [{"wazuh.agent.name": "agent-5x-ubuntu", "package.name": "wget",
              "package.version": "1.21.4-1ubuntu4"}],
            cl.expand_row({"wazuh.agent.name": "{{agent_name_5x}}",
                           "package.name": "{{package_name}}",
                           "package.version": "{{package_version}}"},
                          capture.placeholder_values(ctx_of())))

    def test_a_value_rendered_into_a_route_is_percent_encoded(self):
        # `parse_qs` reads '+' as a space, so a package called g++ rendered raw comes back as
        # 'g  ' and the landing check rejects the very URL the capturer asked for
        values = capture.placeholder_values(ctx_of(package_5x={"name": "g++", "version": "13"}))
        route = cl.render_query(views_json()["inventory"]["route"], values, encode=True)
        self.assertIn("package.name:%22g%2B%2B%22", route)
        self.assertNotIn("g++", route)
        landing = cl.render_landing(views_json()["inventory"]["landing"], values)
        self.assertEqual((True, []), cl.landing_ok("https://localhost" + route, DASHBOARD,
                                                   landing))
        # raw rendering is what the query bar and the landing get, and it stays raw
        self.assertIn("package.name:%22g++%22",
                      cl.render_query(views_json()["inventory"]["route"], values))
        self.assertEqual('query:\'wazuh.agent.id:"002" and package.name:"g++"\'',
                         landing["state"]["_a"])
        # the template's own encoding is left alone, and a space still becomes %20
        self.assertEqual("a%20b", cl.render_query("{{nonce}}", {"nonce": "a b"}, encode=True))

    def test_render_landing_resolves_params_and_state(self):
        landing = cl.render_landing(views_json()["inventory"]["landing"],
                                    capture.placeholder_values(ctx_of()))
        self.assertEqual("/app/it-hygiene", landing["path"])
        self.assertEqual("packages", landing["hash_params"]["tabSubView"])
        self.assertEqual('query:\'wazuh.agent.id:"002" and package.name:"wget"\'',
                         landing["state"]["_a"])
        with self.assertRaises(ValueError):
            cl.render_landing(views_json()["inventory"]["landing"],
                              capture.placeholder_values(ctx_of(agent_id_5x="")))

    def test_sampled_document_extraction(self):
        response = {"hits": {"hits": [{"_source": {
            "wazuh": {"agent": {"id": "002", "name": "agent-5x-ubuntu"}},
            "package": {"name": "wget", "version": "1.21.4-1ubuntu4", "type": "deb"}}}]}}
        self.assertEqual([("wget", "1.21.4-1ubuntu4")], cl.inventory_candidates(response))
        self.assertEqual([], cl.inventory_candidates({"hits": {"hits": []}}))
        self.assertEqual([], cl.inventory_candidates({}))
        vulns = {"hits": {"hits": [{"_source": {"vulnerability": {"id": "CVE-2024-38428"}}}]}}
        self.assertEqual("CVE-2024-38428", cl.vulnerability_sample(vulns))
        self.assertEqual("", cl.vulnerability_sample({"hits": {"hits": []}}))
        # flattened keys answer the same, the order the indexer sorted them in is kept, and a
        # document without a package.name is not a candidate
        self.assertEqual([("curl", "8.5.0"), ("wget", "1.21.4")], cl.inventory_candidates(
            {"hits": {"hits": [{"_source": {"package.name": "curl", "package.version": "8.5.0"}},
                               {"_source": {"package": {"version": "9"}}},
                               {"_source": {"package.name": "wget",
                                            "package.version": "1.21.4"}}]}}))


class InventorySample(TempRun):
    """Check 4b with doubles: the sampled package must have ONE document for this agent."""

    def sample_with(self, candidates, counts):
        args = self.args_for()
        rep = capture.Reporter([])
        ctx = ctx_of(package_5x={})
        hits = [{"_source": {"package": {"name": n, "version": v}}} for n, v in candidates]
        original_search, original_count = capture.indexer_search, capture.indexer_count
        capture.indexer_search = lambda a, index, body: {"hits": {"hits": hits}}
        capture.indexer_count = lambda a, index, query: counts[
            query["bool"]["filter"][1]["term"]["package.name"]]
        self.addCleanup(setattr, capture, "indexer_search", original_search)
        self.addCleanup(setattr, capture, "indexer_count", original_count)
        with contextlib.redirect_stdout(io.StringIO()) as buffer:
            status, got = capture.check_inventory_sample(args, ctx, rep)
        return status, got, ctx, buffer.getvalue()

    def test_a_multi_arch_package_is_skipped_for_the_next_name(self):
        status, got, ctx, out = self.sample_with(
            [("adduser", "3.118ubuntu5"), ("libc6", "2.35-0ubuntu3.8")],
            {"adduser": 2, "libc6": 1})
        self.assertEqual("PASS", status)
        self.assertIn("package libc6 2.35-0ubuntu3.8 (1 document)", got)
        self.assertEqual({"name": "libc6", "version": "2.35-0ubuntu3.8"}, ctx["package_5x"])
        self.assertIn("# inventory sample: adduser has 2 documents for agent 002, next", out)

    def test_the_first_unique_name_wins(self):
        status, got, ctx, _out = self.sample_with(
            [("adduser", "3.118ubuntu5"), ("libc6", "2.35")], {"adduser": 1, "libc6": 1})
        self.assertEqual("PASS", status)
        self.assertEqual("adduser", ctx["package_5x"]["name"])

    def test_no_unique_package_is_a_failure_not_a_guess(self):
        status, got, ctx, _out = self.sample_with(
            [("adduser", "3.118ubuntu5"), ("libc6", "2.35")], {"adduser": 2, "libc6": 3})
        self.assertEqual("FAIL", status)
        self.assertEqual("no package with exactly one document for agent 002 among the first "
                         "2 of wazuh-states-inventory-packages*", got)
        self.assertEqual({}, ctx["package_5x"])


class Blocking(unittest.TestCase):
    def test_check_3_fails_the_views_instead_of_hiding_them(self):
        self.assertEqual(("FAIL", "blocked: check 3 failed"), cl.view_block([3]))
        self.assertEqual(("FAIL", "blocked: check 3 failed"), cl.view_block([2, 3]))

    def test_dead_stack_skips(self):
        self.assertEqual(("SKIP", "blocked by 2"), cl.view_block([2, 4]))
        self.assertEqual(("SKIP", "blocked by 5"), cl.view_block([], session_ready=False))
        self.assertIsNone(cl.view_block([4]))


# --------------------------------------------------------------------------- 6. rows


class Rows(unittest.TestCase):
    INVENTORY = [
        row({"wazuh.agent.name": "agent-5x-ubuntu", "package.name": "wget",
             "package.version": "1.21.4-1ubuntu4"}, top=100, bottom=132),
        row({"wazuh.agent.name": "agent-5x-ubuntu", "package.name": "wget.old",
             "package.version": "1.21.4-1ubuntu4"}, top=132, bottom=164),
    ]

    def test_a_similar_value_is_not_the_value(self):
        self.assertEqual(1, len(cl.rows_matching(self.INVENTORY, {"package.name": "wget"})))
        self.assertEqual(1, len(cl.rows_matching(self.INVENTORY, {"package.name": "wget.old"})))
        self.assertEqual([], cl.rows_matching(self.INVENTORY, {"package.name": "wge"}))
        rows = [row({"package.version": "3.118ubuntu5.1"})]
        self.assertEqual([], cl.rows_matching(rows, {"package.version": "3.118ubuntu5"}))
        self.assertEqual(1, len(cl.rows_matching(rows, {"package.version": "3.118ubuntu5.1"})))

    def test_inactive_is_not_active(self):
        rows = [row({"name": "agent-5x-ubuntu", "status": "inactive"})]
        self.assertEqual([], cl.rows_matching(rows, {"name": "agent-5x-ubuntu",
                                                     "status": "active"}))
        rows = [row({"name": "agent-5x-ubuntu", "status": "active"})]
        self.assertEqual(1, len(cl.rows_matching(rows, {"name": "agent-5x-ubuntu",
                                                        "status": "active"})))

    def test_every_value_must_be_on_the_same_row_and_in_its_own_column(self):
        rows = [row({"name": "agent-4x-ubuntu", "status": "active"}),
                row({"name": "agent-5x-ubuntu", "status": "disconnected"}, top=132, bottom=164)]
        self.assertEqual(1, len(cl.rows_matching(rows, {"name": "agent-4x-ubuntu",
                                                        "status": "active"})))
        self.assertEqual([], cl.rows_matching(rows, {"name": "agent-5x-ubuntu",
                                                     "status": "active"}))
        # a value in the WRONG column does not count
        self.assertEqual([], cl.rows_matching(rows, {"name": "active"}))

    def test_a_column_the_row_does_not_have_is_a_mismatch(self):
        self.assertEqual([], cl.rows_matching(self.INVENTORY, {"package.type": "deb"}))
        self.assertEqual([], cl.rows_matching(self.INVENTORY, {}))
        self.assertEqual([], cl.rows_matching([], {"package.name": "wget"}))

    def test_values_are_compared_stripped(self):
        rows = [row({"package.name": "  wget \n"})]
        self.assertEqual(1, len(cl.rows_matching(rows, {"package.name": "wget"})))

    def test_two_matching_rows_are_never_one_row(self):
        rows = self.INVENTORY + [row({"wazuh.agent.name": "agent-5x-ubuntu",
                                      "package.name": "wget",
                                      "package.version": "1.21.4-1ubuntu4"}, top=164, bottom=196)]
        self.assertEqual(2, len(cl.rows_matching(rows, {"package.name": "wget"})))

    def test_the_grid_groups_cells_by_their_exact_top(self):
        # 100 and 101 are two rows: a tolerance wide enough to merge them would let a value
        # of the row below satisfy this row (the whole point of D-8b).
        cells = [["package.name", 100, 132, "wget"], ["package.version", 100, 132, "1.21.4"],
                 ["package.name", 101, 133, "curl"], ["package.version", 101, 133, "8.5.0"]]
        rows = cl.grid_rows(cells)
        self.assertEqual(2, len(rows))
        self.assertEqual({"package.name": "wget", "package.version": "1.21.4"},
                         rows[0]["columns"])
        self.assertEqual([], cl.rows_matching(rows, {"package.name": "wget",
                                                     "package.version": "8.5.0"}))
        self.assertEqual(1, len(cl.rows_matching(rows, {"package.name": "curl",
                                                        "package.version": "8.5.0"})))

    def test_the_grid_keeps_the_rows_in_screen_order_and_their_extent(self):
        rows = cl.grid_rows([["a", 132, 164, "second"], ["a", 100, 132, "first"],
                             ["b", 100, 140, "wide"]])
        self.assertEqual(["first", "second"], [r["columns"]["a"] for r in rows])
        self.assertEqual(140, rows[0]["bottom"])  # the tallest cell of the row
        self.assertEqual([], cl.grid_rows([]))

    def test_a_row_outside_the_frame_is_not_in_the_screenshot(self):
        self.assertTrue(cl.row_in_frame(row({}, top=100, bottom=132), 800))
        self.assertTrue(cl.row_in_frame(row({}, top=0, bottom=800), 800))
        self.assertFalse(cl.row_in_frame(row({}, top=780, bottom=812), 800))
        self.assertFalse(cl.row_in_frame(row({}, top=-10, bottom=22), 800))
        self.assertFalse(cl.row_in_frame(row({}, top=100, bottom=132), None))
        self.assertFalse(cl.row_in_frame({"columns": {}}, 800))
        self.assertIn("viewport=800", cl.row_frame_reason(row({}, top=780, bottom=812), 800))

    def test_a_column_drawn_past_the_right_edge_is_not_in_the_screenshot(self):
        # the row is perfectly placed vertically; the column that carries the proof is not in
        # the frame at all (a grid wider than the viewport still returns every cell's text)
        inside = row({"package.name": "adduser"}, left=538, right=782)
        outside = row({"package.name": "adduser"}, left=1300, right=1544)
        self.assertTrue(cl.row_in_frame(inside, 800, 1280, ["package.name"]))
        self.assertFalse(cl.row_in_frame(outside, 800, 1280, ["package.name"]))
        self.assertFalse(cl.row_in_frame(row({"package.name": "x"}, left=-40, right=100),
                                         800, 1280, ["package.name"]))
        # a column nobody measured is not a column anybody saw
        self.assertFalse(cl.row_in_frame({"columns": {"package.name": "x"}, "cells": {},
                                          "top": 100, "bottom": 132}, 800, 1280,
                                         ["package.name"]))
        # …and without a known width the vertical answer is unchanged
        self.assertTrue(cl.row_in_frame(outside, 800, None, ["package.name"]))
        reason = cl.row_frame_reason(outside, 800, 1280, ["package.name"])
        self.assertEqual("column package.name outside the frame (left=1300 right=1544 "
                         "viewport width=1280)", reason)
        self.assertIn("not measured", cl.row_frame_reason(
            {"columns": {}, "cells": {}, "top": 1, "bottom": 2}, 800, 1280, ["package.name"]))
        # a vertical problem is still reported as the vertical one
        self.assertIn("viewport=800", cl.row_frame_reason(
            row({"package.name": "x"}, top=780, bottom=812), 800, 1280, ["package.name"]))

    def test_a_truncated_column_is_not_the_value_the_png_shows(self):
        cut = row({"package.name": "adduser", "package.vendor": "Ubuntu Developers"},
                  truncated=True)
        whole = row({"package.name": "adduser"})
        self.assertEqual(["package.name"], cl.truncated_columns(cut, ["package.name"]))
        self.assertEqual([], cl.truncated_columns(whole, ["package.name"]))
        self.assertEqual([], cl.truncated_columns(cut, []))
        # truncation is per cell: only the asserted columns are ever consulted
        mixed = row({"a": "1", "b": "2"})
        mixed["cells"]["b"]["truncated"] = True
        self.assertEqual([], cl.truncated_columns(mixed, ["a"]))
        self.assertEqual(["b"], cl.truncated_columns(mixed, ["a", "b"]))

    def test_the_grid_keeps_the_geometry_of_every_cell(self):
        rows = cl.grid_rows([["package.name", 100, 132, "adduser", 538, 782, False],
                             ["package.vendor", 100, 132, "Ubuntu Developers", 293, 538, True]])
        self.assertEqual({"left": 538, "right": 782, "truncated": False},
                         rows[0]["cells"]["package.name"])
        self.assertTrue(rows[0]["cells"]["package.vendor"]["truncated"])
        # a cell the extractor reported without geometry keeps the row usable, and unproven
        bare = cl.grid_rows([["package.name", 100, 132, "adduser"]])
        self.assertEqual({"left": None, "right": None, "truncated": False},
                         bare[0]["cells"]["package.name"])
        self.assertFalse(cl.row_in_frame(bare[0], 800, 1280, ["package.name"]))


# --------------------------------------------------------------------------- assertions


class Assertions(unittest.TestCase):
    GRID_CFG = {
        "scope_selector": ".euiDataGrid",
        "table": {"kind": "grid", "selector": ".euiDataGrid"},
        "count_selector": '[data-test-subj="discoverQueryHits"]',
    }

    def grid_page(self, cells, viewport=800, hits="Result (1/1)", viewport_width=1280):
        return FakePage(
            elements={(".euiDataGrid",): ["grid"],
                      (".euiDataGrid", '[data-test-subj="discoverQueryHits"]'): [hits]},
            tables={".euiDataGrid": {"kind": "grid", "cells": cells, "viewport": viewport,
                                     "viewport_width": viewport_width}},
        )

    def cells_of(self, name="wget", version="1.21.4-1ubuntu4", top=100, left=48, width=200,
                 truncated=False):
        """The three cells of one grid row, as the browser hands them over:
        [column, top, bottom, text, left, right, truncated]."""
        return [[column, top, top + 32, text, left + i * width, left + (i + 1) * width,
                 truncated]
                for i, (column, text) in enumerate(
                    (("wazuh.agent.name", "agent-5x-ubuntu"), ("package.name", name),
                     ("package.version", version)))]

    def inventory_cfg(self, assertions):
        cfg = dict(self.GRID_CFG)
        cfg["assertions"] = assertions
        return cfg

    def test_one_row_of_this_runs_document_passes(self):
        cfg = self.inventory_cfg(views_json()["inventory"]["assertions"])
        page = self.grid_page(self.cells_of())
        results = capture.eval_assertions(page, cfg, ctx_of())
        self.assertEqual([True, True, True], [r["ok"] for r in results],
                         [r.get("reason") for r in results])
        self.assertEqual(["row", "rows_eq", "hits_eq"], [r["kind"] for r in results])

    def test_the_wrong_version_never_passes(self):
        cfg = self.inventory_cfg(views_json()["inventory"]["assertions"])
        page = self.grid_page(self.cells_of(version="1.21.4-1ubuntu4.1"))
        result = capture.eval_assertions(page, cfg, ctx_of())[0]
        self.assertFalse(result["ok"])
        self.assertIn("0 rows match", result["reason"])

    def test_two_matching_rows_fail_the_view(self):
        cfg = self.inventory_cfg([views_json()["inventory"]["assertions"][0]])
        page = self.grid_page(self.cells_of(top=100) + self.cells_of(top=132))
        result = capture.eval_assertions(page, cfg, ctx_of())[0]
        self.assertFalse(result["ok"])
        self.assertIn("2 rows match", result["reason"])
        self.assertEqual(2, result["matched"])

    def test_a_row_below_the_fold_is_noted_not_failed(self):
        # V11: the capture is full-page, so the fold does not keep the row out of the PNG.
        # The measurement is kept and reported; the row is still the exact one or nothing.
        cfg = self.inventory_cfg([views_json()["inventory"]["assertions"][0]])
        page = self.grid_page(self.cells_of(top=790), viewport=800)
        result = capture.eval_assertions(page, cfg, ctx_of())[0]
        self.assertTrue(result["ok"], result.get("reason"))
        self.assertEqual({"in_viewport": False, "truncated_columns": []}, result["frame_note"])
        self.assertEqual("frame: in_viewport=false, truncated=[]",
                         capture.frame_note_line([result]))
        # and it is still one row of this run's document, not any row
        wrong = capture.eval_assertions(
            self.grid_page(self.cells_of(top=790, version="1.21.4-1ubuntu4.1"), viewport=800),
            cfg, ctx_of())[0]
        self.assertFalse(wrong["ok"])
        self.assertIn("0 rows match", wrong["reason"])

    def test_an_asserted_column_outside_the_viewport_is_noted_not_failed(self):
        cfg = self.inventory_cfg([views_json()["inventory"]["assertions"][0]])
        # the row is at the top of the screen, but its columns start at x=1200
        page = self.grid_page(self.cells_of(left=1200, width=200))
        result = capture.eval_assertions(page, cfg, ctx_of())[0]
        self.assertTrue(result["ok"], result.get("reason"))
        self.assertFalse(result["frame_note"]["in_viewport"])
        self.assertEqual([], result["frame_note"]["truncated_columns"])

    def test_a_truncated_asserted_column_is_noted_not_failed(self):
        cfg = self.inventory_cfg([views_json()["inventory"]["assertions"][0]])
        page = self.grid_page(self.cells_of(truncated=True))
        result = capture.eval_assertions(page, cfg, ctx_of())[0]
        self.assertTrue(result["ok"], result.get("reason"))
        self.assertTrue(result["frame_note"]["in_viewport"])
        self.assertEqual(["wazuh.agent.name", "package.name", "package.version"],
                         result["frame_note"]["truncated_columns"])
        self.assertEqual(
            "frame: in_viewport=true, truncated=[package.name, package.version, "
            "wazuh.agent.name]", capture.frame_note_line([result]))

    def test_the_frame_note_aggregates_every_row_and_is_absent_without_one(self):
        # one note per matched row, summarized once for the report line
        cfg = self.inventory_cfg([views_json()["inventory"]["assertions"][0]])
        clean = capture.eval_assertions(self.grid_page(self.cells_of()), cfg, ctx_of())
        self.assertEqual("frame: in_viewport=true, truncated=[]",
                         capture.frame_note_line(clean))
        self.assertIn("frame: in_viewport=true, truncated=[]", capture.describe(clean))
        # one row outside the viewport makes the aggregate false, and the columns are the
        # deduplicated union of what each row measured
        mixed = [{"kind": "row", "frame_note": {"in_viewport": True,
                                                "truncated_columns": ["package.name"]}},
                 {"kind": "row", "frame_note": {"in_viewport": False,
                                                "truncated_columns": ["package.version",
                                                                      "package.name"]}}]
        self.assertEqual("frame: in_viewport=false, truncated=[package.name, package.version]",
                         capture.frame_note_line(mixed))
        # nothing matched, nothing measured: no note at all
        missed = capture.eval_assertions(
            self.grid_page(self.cells_of(version="1.21.4-1ubuntu4.1")), cfg, ctx_of())
        self.assertEqual("", capture.frame_note_line(missed))
        self.assertNotIn("frame:", capture.describe(missed))
        self.assertEqual("", capture.frame_note_line([]))

    def test_rows_eq_counts_the_data_rows(self):
        cfg = self.inventory_cfg([{"rows_eq": 1}])
        page = self.grid_page(self.cells_of(top=100) + self.cells_of(top=132))
        result = capture.eval_assertions(page, cfg, ctx_of())[0]
        self.assertFalse(result["ok"])
        self.assertEqual(2, result["value"])
        self.assertIn("expected exactly 1", result["reason"])
        result = capture.eval_assertions(self.grid_page(self.cells_of()), cfg, ctx_of())[0]
        self.assertTrue(result["ok"])

    def test_rows_eq_takes_the_agent_count(self):
        cfg = {"scope_selector": "table.euiTable",
               "table": {"kind": "table", "selector": "table.euiTable"},
               "assertions": [{"rows_eq": "{{agent_count}}"}]}
        rows = [row({"name": "agent-4x-ubuntu", "status": "active"}),
                row({"name": "agent-5x-ubuntu", "status": "active"}, top=132, bottom=164)]
        page = FakePage(elements={("table.euiTable",): ["table"]},
                        tables={"table.euiTable": {"kind": "table", "rows": rows,
                                                   "viewport": 800, "viewport_width": 1280}})
        self.assertTrue(capture.eval_assertions(page, cfg, ctx_of())[0]["ok"])
        result = capture.eval_assertions(page, cfg, ctx_of(agent_names=["only-one"]))[0]
        self.assertFalse(result["ok"])
        self.assertIn("expected exactly 1", result["reason"])

    def test_one_row_per_agent_and_none_at_all_is_a_failure(self):
        cfg = {"scope_selector": "table.euiTable",
               "table": {"kind": "table", "selector": "table.euiTable"},
               "assertions": views_json()["agents"]["assertions"]}
        rows = [row({"name": "agent-4x-ubuntu", "status": "active"}),
                row({"name": "agent-5x-ubuntu", "status": "active"}, top=132, bottom=164)]
        page = FakePage(elements={("table.euiTable",): ["table"]},
                        tables={"table.euiTable": {"kind": "table", "rows": rows,
                                                   "viewport": 800, "viewport_width": 1280}})
        results = capture.eval_assertions(page, cfg, ctx_of())
        self.assertEqual([True, True, True], [r["ok"] for r in results],
                         [r.get("reason") for r in results])
        empty = capture.eval_assertions(page, cfg, ctx_of(agent_names=[]))
        self.assertFalse(empty[0]["ok"])
        self.assertIn("0 rows required", empty[0]["reason"])
        self.assertFalse(empty[1]["ok"])  # rows_eq cannot render {{agent_count}} either
        self.assertIn("unresolved placeholder", empty[1]["reason"])

    def test_a_missing_scope_or_table_is_never_a_pass(self):
        cfg = self.inventory_cfg(views_json()["inventory"]["assertions"])
        results = capture.eval_assertions(FakePage(), cfg, ctx_of())
        self.assertEqual(3, len(results))
        for entry in results:
            self.assertFalse(entry["ok"])
            self.assertIn("scope missing", entry["reason"])
        page = FakePage(elements={(".euiDataGrid",): ["grid"]},
                        tables={".euiDataGrid": {"error": "table missing: .euiDataGrid"}})
        entry = capture.eval_assertions(page, cfg, ctx_of())[0]
        self.assertFalse(entry["ok"])
        self.assertEqual("table missing: .euiDataGrid", entry["reason"])

    def test_two_grids_in_the_scope_are_ambiguous(self):
        cfg = self.inventory_cfg([{"rows_eq": 1}])
        page = FakePage(elements={(".euiDataGrid",): ["a", "b"]},
                        tables={".euiDataGrid": {"error": "ambiguous table (2) for .euiDataGrid"}})
        entry = capture.eval_assertions(page, cfg, ctx_of())[0]
        self.assertFalse(entry["ok"])
        self.assertIn("ambiguous table (2)", entry["reason"])

    def test_an_unknown_assertion_is_a_failure(self):
        entry = capture.eval_assertions(FakePage(), self.inventory_cfg([{"row_text": ["x"]}]),
                                        ctx_of())[0]
        self.assertFalse(entry["ok"])
        self.assertIn("unknown assertion", entry["reason"])

    def test_extract_rows_reports_an_unknown_kind(self):
        rows, viewport, viewport_w, problem = capture.extract_rows(
            FakePage(), {"scope_selector": "x", "table": {"kind": "list", "selector": "x"}})
        self.assertEqual(([], None, None), (rows, viewport, viewport_w))
        self.assertIn("unknown table", problem)


# --------------------------------------------------------------------------- 7. counter


class Counter(unittest.TestCase):
    CFG = {"count_selector": '[data-test-subj="discoverQueryHits"]',
           "scope_selector": ".euiDataGrid",
           "table": {"kind": "grid", "selector": ".euiDataGrid"}}

    def page_with(self, scope_texts=None, counter_texts=None, foreign=None):
        elements = {}
        if scope_texts is not None:
            elements[(".euiDataGrid",)] = scope_texts
        if counter_texts is not None:
            elements[(".euiDataGrid", '[data-test-subj="discoverQueryHits"]')] = counter_texts
        if foreign is not None:  # a counter of ANOTHER panel, at the page level
            elements[('[data-test-subj="discoverQueryHits"]',)] = foreign
        return FakePage(elements=elements)

    def test_parse_hits_takes_the_first_integer(self):
        self.assertEqual(0, cl.parse_hits("Result (0/10)"))
        self.assertEqual(1, cl.parse_hits("Result (1/1)"))
        self.assertEqual(116, cl.parse_hits("116 hits"))
        self.assertEqual(1, cl.parse_hits("1"))
        self.assertEqual(1234, cl.parse_hits("1,234 hits"))
        self.assertIsNone(cl.parse_hits("no results"))
        self.assertIsNone(cl.parse_hits(""))

    def test_a_counter_outside_the_scope_is_never_this_views_count(self):
        # the scope does not exist and the page has exactly one (foreign) counter reading 9
        page = self.page_with(foreign=["9 hits"])
        hits, problem = capture.count_hits(page, self.CFG)
        self.assertIsNone(hits)
        self.assertEqual("scope missing: .euiDataGrid", problem)
        entry = capture.eval_assertions(page, dict(self.CFG, assertions=[{"hits_eq": 1}]),
                                        ctx_of())[0]
        self.assertFalse(entry["ok"])
        self.assertEqual("scope missing: .euiDataGrid", entry["reason"])
        # and with the scope present, the counter INSIDE it is the one that is read
        page = self.page_with(scope_texts=["grid"], counter_texts=["1"], foreign=["9 hits"])
        self.assertEqual((1, None), capture.count_hits(page, self.CFG))

    def test_counter_must_be_unique_inside_the_scope(self):
        page = self.page_with(scope_texts=["grid"], counter_texts=["Result (1/1)", "Result (9/9)"])
        hits, problem = capture.count_hits(page, self.CFG)
        self.assertIsNone(hits)
        self.assertIn("ambiguous counter (2)", problem)
        page = self.page_with(scope_texts=["grid"])
        hits, problem = capture.count_hits(page, self.CFG)
        self.assertIsNone(hits)
        self.assertIn("counter missing", problem)
        page = self.page_with(scope_texts=["grid"], counter_texts=["no results"])
        hits, problem = capture.count_hits(page, self.CFG)
        self.assertIsNone(hits)
        self.assertIn("shows no number", problem)
        self.assertEqual((0, None), capture.count_hits(
            self.page_with(scope_texts=["grid"], counter_texts=["Result (0/10)"]), self.CFG))

    def test_hits_eq_is_exact(self):
        cfg = dict(self.CFG, assertions=[{"hits_eq": 1}])
        entry = capture.eval_assertions(
            self.page_with(scope_texts=["grid"], counter_texts=["2"]), cfg, ctx_of())[0]
        self.assertFalse(entry["ok"])
        self.assertEqual(2, entry["value"])
        self.assertIn("expected exactly 1", entry["reason"])
        entry = capture.eval_assertions(
            self.page_with(scope_texts=["grid"], counter_texts=["1"]), cfg, ctx_of())[0]
        self.assertTrue(entry["ok"])

    def test_a_view_without_a_counter_says_so(self):
        hits, problem = capture.count_hits(FakePage(), {"scope_selector": "table.euiTable"})
        self.assertIsNone(hits)
        self.assertIn("no count_selector", problem)


# --------------------------------------------------------------------------- 8. artifacts


def png_header(width=1280, height=3612):
    """The first 24 bytes of a PNG: signature, the IHDR chunk's length and type, width,
    height. A full-page capture at 1280 px wide is as tall as the page (V11)."""
    return (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR"
            + width.to_bytes(4, "big") + height.to_bytes(4, "big"))


class Artifacts(unittest.TestCase):
    def test_a_pass_needs_its_png_and_sidecar(self):
        self.assertEqual((True, ""), cl.artifacts_ok(48000, True))
        self.assertEqual((False, "screenshot missing"), cl.artifacts_ok(None, True))
        self.assertEqual((False, "screenshot empty (0 bytes)"), cl.artifacts_ok(0, True))
        self.assertEqual((False, "sidecar not written"), cl.artifacts_ok(48000, False))

    def test_the_pixel_size_is_read_from_the_png_itself(self):
        # the manifest states the size of the evidence; with a full-page capture the height is
        # the page's, so it cannot be the viewport constant
        self.assertEqual((1280, 3612), cl.png_size(png_header() + b"...the rest of the file"))
        self.assertEqual((1280, 800), cl.png_size(png_header(1280, 800)))
        self.assertNotEqual(800, cl.png_size(png_header())[1])
        for bad in (b"", b"PNG-bytes", None, "not bytes at all", 7, png_header()[:23],
                    b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDX" + b"\x00" * 8,
                    png_header(0, 800), png_header(1280, 0)):
            self.assertIsNone(cl.png_size(bad), repr(bad))


class Screenshot(TempRun):
    """What `shoot()` asks the browser for — decision V11."""

    def test_the_capture_is_the_whole_page(self):
        # full_page=True is the decision: a capture cropped to the viewport is what used to
        # leave a row below the fold (or a column past the right edge) out of the evidence.
        page = FakePage()
        args = self.args_for()
        path = capture.shoot(page, args, "inventory", 8, ok=True)
        self.assertEqual(os.path.join(self.out, "08-inventory.png"), path)
        self.assertEqual([{"path": path, "full_page": True}], page.screenshots)
        failed = capture.shoot(page, args, "inventory", 8, ok=False)
        self.assertEqual(os.path.join(self.out, "08-inventory-FAIL.png"), failed)
        self.assertEqual([True, True], [shot["full_page"] for shot in page.screenshots])


# --------------------------------------------------------------------------- --out


class OutDir(unittest.TestCase):
    """--out is EMPTIED before a run, as root: what it may and may not be."""

    def test_only_our_own_artifacts_make_a_directory_ours(self):
        ours = [(n, "file") for n in ("06-agents.png", "07-discover.json", "09-vd-FAIL.png",
                                      "captures.md")]
        self.assertEqual((True, []), cl.out_dir_exclusive(ours))
        self.assertEqual((True, []), cl.out_dir_exclusive([]))
        ok, offenders = cl.out_dir_exclusive(
            ours + [("precious.txt", "file"), ("subdir", "dir")])
        self.assertFalse(ok)
        self.assertEqual(["precious.txt (file)", "subdir (dir)"], offenders)
        # the reason line is printed: at most three names
        ok, offenders = cl.out_dir_exclusive([(n, "file") for n in ("a", "b", "c", "d")])
        self.assertEqual((False, ["a (file)", "b (file)", "c (file)"]), (ok, offenders))
        # near misses are NOT ours
        for name in ("6-agents.png", "06-agents.txt", "06-Agents.png", "06-agents-fail.png",
                     "06-agents.png.bak", "captures.md.bak", ".git"):
            self.assertFalse(cl.out_dir_artifact(name), name)
        for name in ("06-agents.png", "08-inventory.json", "09-vd-FAIL.json", "captures.md"):
            self.assertTrue(cl.out_dir_artifact(name), name)

    def test_the_name_alone_never_makes_an_entry_ours(self):
        """v7: the kind decides too. A directory called `captures.md` and a symlink called
        `06-agents.png` wear an artifact's name; deleting them is not emptying our own run."""
        for kind in ("dir", "symlink", "other", "unreadable", "missing"):
            for name in ("captures.md", "06-agents.png", "08-inventory.json"):
                self.assertEqual((False, ["{0} ({1})".format(name, kind)]),
                                 cl.out_dir_exclusive([(name, kind)]), (name, kind))
                # …and the name is still, on its own, a name this tool would write
                self.assertTrue(cl.out_dir_artifact(name), name)
        self.assertEqual("dir", cl.out_dir_entry_problem("captures.md", "dir"))
        self.assertEqual("symlink", cl.out_dir_entry_problem("06-agents.png", "symlink"))
        self.assertEqual("", cl.out_dir_entry_problem("captures.md", "file"))
        self.assertEqual("file", cl.out_dir_entry_problem("precious.txt", "file"))
        # a bare name with no kind at all is never accepted either
        self.assertEqual((False, ["captures.md (unknown)"]),
                         cl.out_dir_exclusive(["captures.md"]))

    def test_the_paths_out_refuses_outright(self):
        home = "/root"
        repos = ["/workspaces/x/wazuh"]
        self.assertEqual("the filesystem root", cl.out_dir_refusal("/", home, repos))
        self.assertEqual("the filesystem root", cl.out_dir_refusal("//", home, repos))
        self.assertEqual("the home directory", cl.out_dir_refusal("/root", home, repos))
        self.assertEqual("the home directory", cl.out_dir_refusal("/root/", home, repos))
        self.assertEqual("inside the checkout (/workspaces/x/wazuh)",
                         cl.out_dir_refusal("/workspaces/x/wazuh/src/out", home, repos))
        self.assertEqual("inside the checkout (/workspaces/x/wazuh)",
                         cl.out_dir_refusal("/workspaces/x/wazuh", home, repos))
        self.assertEqual("fewer than 2 path components", cl.out_dir_refusal("/tmp", home, repos))
        self.assertEqual("no directory given", cl.out_dir_refusal("", home, repos))
        # and the ones it accepts
        self.assertEqual("", cl.out_dir_refusal("/tmp/captures", home, repos))
        self.assertEqual("", cl.out_dir_refusal("/root/out", home, repos))
        self.assertEqual("", cl.out_dir_refusal("/workspaces/x/e2e-dashboard-out/run", home,
                                                repos))
        self.assertEqual("", cl.out_dir_refusal("/workspaces/x/wazuh-other/out", home, repos))


class OutDirRun(TempRun):
    """The same guard, wired: run() refuses before anything is removed."""

    def capture_run(self, args):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = capture.run(args, "missing")
        return rc, buffer.getvalue()

    def test_the_kind_of_every_entry_is_read_from_the_filesystem(self):
        os.mkdir(os.path.join(self.out, "captures.md"))  # a DIRECTORY wearing our name
        os.symlink("/etc/hostname", os.path.join(self.out, "06-agents.png"))
        with open(os.path.join(self.out, "08-inventory.json"), "w") as handle:
            handle.write("{}")
        self.assertEqual("dir", capture.entry_kind(os.path.join(self.out, "captures.md")))
        # a symlink is answered as a symlink, never as what it points at
        self.assertEqual("symlink", capture.entry_kind(os.path.join(self.out, "06-agents.png")))
        self.assertEqual("file", capture.entry_kind(os.path.join(self.out, "08-inventory.json")))
        self.assertEqual("missing", capture.entry_kind(os.path.join(self.out, "nope.png")))

    def test_a_directory_named_like_the_manifest_is_not_ours_and_is_not_removed(self):
        # the name is one this tool writes; `shutil.rmtree` on it used to take everything
        # inside with it. There is no recursive delete left in capture.py at all.
        inside = os.path.join(self.out, "captures.md", "somebody-elses-work.txt")
        os.mkdir(os.path.join(self.out, "captures.md"))
        with open(inside, "w") as handle:
            handle.write("not this run's")
        rc, text = self.capture_run(self.args_for())
        self.assertEqual(1, rc)
        self.assertIn("FAIL  0. setup (got: out dir not exclusive: captures.md (dir))", text)
        self.assertNotIn("emptied", text)
        self.assertTrue(os.path.isdir(os.path.join(self.out, "captures.md")))
        self.assertTrue(os.path.exists(inside))
        with open(capture.__file__) as handle:
            self.assertEqual(0, handle.read().count("rmtree"))

    def test_a_symlink_wearing_an_artifact_name_is_not_ours(self):
        target = os.path.join(tempfile.mkdtemp(prefix="capture-target-"), "precious.png")
        self.addCleanup(shutil.rmtree, os.path.dirname(target), True)
        with open(target, "w") as handle:
            handle.write("somebody else's file")
        os.symlink(target, os.path.join(self.out, "06-agents.png"))
        rc, text = self.capture_run(self.args_for())
        self.assertEqual(1, rc)
        self.assertIn("FAIL  0. setup (got: out dir not exclusive: 06-agents.png (symlink))",
                      text)
        self.assertTrue(os.path.islink(os.path.join(self.out, "06-agents.png")))
        self.assertTrue(os.path.exists(target))

    def test_a_symlink_into_the_checkout_is_refused_however_it_is_spelled(self):
        # `--out /tmp/alias` where the alias points inside the checkout: abspath sees a path
        # outside it, realpath sees the truth (v7)
        repo = os.path.realpath(tempfile.mkdtemp(prefix="capture-repo-"))
        self.addCleanup(shutil.rmtree, repo, True)
        real = os.path.join(repo, "src", "captures")
        os.makedirs(real)
        with open(os.path.join(real, "06-agents.png"), "w") as handle:
            handle.write("ours, and still refused")
        alias = os.path.join(tempfile.mkdtemp(prefix="capture-alias-"), "out")
        self.addCleanup(shutil.rmtree, os.path.dirname(alias), True)
        os.symlink(real, alias)
        original = os.environ.get("WAZUH_REPO")
        os.environ["WAZUH_REPO"] = repo
        self.addCleanup(lambda: os.environ.__setitem__("WAZUH_REPO", original)
                        if original is not None else os.environ.pop("WAZUH_REPO", None))
        rc, text = self.capture_run(capture.parse_args(["--out", alias]))
        self.assertEqual(1, rc)
        self.assertIn("FAIL  0. setup (got: --out refuses {0}: inside the checkout ({1}))"
                      .format(real, repo), text)
        self.assertEqual(["06-agents.png"], os.listdir(real))
        self.assertFalse(os.path.exists(os.path.join(real, "captures.md")))

    def test_a_directory_that_is_not_ours_is_never_emptied(self):
        precious = os.path.join(self.out, "precious.txt")
        with open(precious, "w") as handle:
            handle.write("someone else's")
        os.mkdir(os.path.join(self.out, "subdir"))
        with open(os.path.join(self.out, "08-inventory.png"), "w") as handle:
            handle.write("ours")
        rc, text = self.capture_run(self.args_for())
        self.assertEqual(1, rc)
        self.assertIn(
            "FAIL  0. setup (got: out dir not exclusive: precious.txt (file), subdir (dir))",
            text)
        self.assertNotIn("emptied", text)
        self.assertTrue(os.path.exists(precious))
        self.assertTrue(os.path.isdir(os.path.join(self.out, "subdir")))
        self.assertTrue(os.path.exists(os.path.join(self.out, "08-inventory.png")))
        # and nothing was written into it either, not even the manifest
        self.assertFalse(os.path.exists(os.path.join(self.out, "captures.md")))
        self.assertIn("SKIP  6. agents (blocked by 0)", text)

    def test_a_directory_of_our_own_artifacts_is_emptied(self):
        for name in ("06-agents.png", "06-agents.json", "09-vd-FAIL.png", "captures.md"):
            with open(os.path.join(self.out, name), "w") as handle:
                handle.write("previous run")
        rc, text = self.capture_run(self.args_for())
        self.assertEqual(1, rc)  # the venv is still missing: this is about --out only
        self.assertIn("# emptied {0} (4 entries)".format(self.out), text)
        self.assertEqual(["captures.md"], sorted(os.listdir(self.out)))  # rewritten by finish
        self.assertIn("FAIL  0. setup (got: venv missing", text)

    def test_an_out_inside_the_checkout_is_refused_before_it_is_read(self):
        repo = tempfile.mkdtemp(prefix="capture-repo-")
        self.addCleanup(shutil.rmtree, repo, True)
        out = os.path.join(repo, "src", "captures")
        os.makedirs(out)
        with open(os.path.join(out, "06-agents.png"), "w") as handle:
            handle.write("ours, and still refused")
        original = os.environ.get("WAZUH_REPO")
        os.environ["WAZUH_REPO"] = repo
        self.addCleanup(lambda: os.environ.__setitem__("WAZUH_REPO", original)
                        if original is not None else os.environ.pop("WAZUH_REPO", None))
        rc, text = self.capture_run(capture.parse_args(["--out", out]))
        self.assertEqual(1, rc)
        self.assertIn("FAIL  0. setup (got: --out refuses {0}: inside the checkout ({1}))"
                      .format(out, repo), text)
        self.assertEqual(["06-agents.png"], os.listdir(out))
        self.assertFalse(os.path.exists(os.path.join(out, "captures.md")))


# --------------------------------------------------------------------------- view + run


class ViewIntegration(TempRun):
    """run_view/view_check against a fake page: the PASS path really writes its PNG and its
    sidecar, and the failures Codex reproduced end as FAIL."""

    def inventory_page(self, url=LIVE_INVENTORY_URL, drift_url=None, cells=None, hits="1",
                       png=b"PNG-bytes"):
        wait_selector = views_json()["inventory"]["wait_selector"]
        cells = cells if cells is not None else self.cells(
            [("wazuh.agent.name", "agent-5x-ubuntu"), ("package.name", "adduser"),
             ("package.version", "3.118ubuntu5")])
        return FakePage(
            elements={(".euiDataGrid",): ["grid"],
                      (".euiDataGrid", '[data-test-subj="discoverQueryHits"]'): [hits],
                      ('[data-test-subj="querySubmitButton"]',): []},
            tables={".euiDataGrid": {"kind": "grid", "cells": cells, "viewport": 800,
                                     "viewport_width": 1280}},
            urls=[url], drift_url=drift_url, drift_selector=wait_selector, png=png,
        )

    @staticmethod
    def cells(pairs, top=100, left=48, width=200, truncated=False):
        return [[column, top, top + 32, text, left + i * width, left + (i + 1) * width,
                 truncated] for i, (column, text) in enumerate(pairs)]

    def ctx(self):
        return ctx_of(run_id="20260920T000000Z-e2e-capture-1a2b3c4d", agent_id_5x="002",
                      agent_name_5x="agent-5x-ubuntu",
                      package_5x={"name": "adduser", "version": "3.118ubuntu5"},
                      counts_by_agent={}, sha256={})

    def run_inventory(self, page, api_calls=None):
        args = self.args_for()
        session = FakeSession(page)
        if api_calls is not None:
            session.api_calls = api_calls
        return capture.run_view(session, args, self.ctx(), "inventory",
                                views_json()["inventory"], 8)

    def test_a_good_view_passes_with_its_png_and_sidecar(self):
        page = self.inventory_page()
        status, reason = self.run_inventory(page)
        self.assertEqual("PASS", status, reason)
        self.assertIn("app=it-hygiene", reason)
        # the frame is measured and reported on the PASS line itself (V11), never a verdict
        self.assertIn("frame: in_viewport=true, truncated=[]", reason)
        png = os.path.join(self.out, "08-inventory.png")
        sidecar = os.path.join(self.out, "08-inventory.json")
        self.assertTrue(os.path.getsize(png) > 0)
        self.assertEqual([{"path": png, "full_page": True}], page.screenshots)
        with open(sidecar) as handle:
            data = json.load(handle)
        self.assertEqual("inventory", data["view"])
        self.assertEqual(LIVE_INVENTORY_URL, data["final_url"])
        self.assertEqual([True, True, True], [a["ok"] for a in data["assertions"]])
        self.assertEqual({"in_viewport": True, "truncated_columns": []},
                         data["assertions"][0]["frame_note"])
        self.assertEqual("grid", data["table"]["kind"])

    def test_the_sidecar_of_a_row_drawn_off_screen_carries_the_note_and_still_passes(self):
        # the proven row is the 1000th of the grid: below the fold and cut on screen. The PNG
        # is the whole page, so this is evidence — with what was measured written down.
        page = self.inventory_page(cells=self.cells(
            [("wazuh.agent.name", "agent-5x-ubuntu"), ("package.name", "adduser"),
             ("package.version", "3.118ubuntu5")], top=4200, truncated=True))
        status, reason = self.run_inventory(page)
        self.assertEqual("PASS", status, reason)
        self.assertIn("frame: in_viewport=false, truncated=[package.name, package.version, "
                      "wazuh.agent.name]", reason)
        with open(os.path.join(self.out, "08-inventory.json")) as handle:
            note = json.load(handle)["assertions"][0]["frame_note"]
        self.assertFalse(note["in_viewport"])
        self.assertEqual(["wazuh.agent.name", "package.name", "package.version"],
                         note["truncated_columns"])

    def test_a_view_that_drifts_after_the_wait_fails_naming_it(self):
        page = self.inventory_page(drift_url="https://localhost/app/it-hygiene#/overview/"
                                             "?tab=it-hygiene&tabView=hardware")
        status, reason = self.run_inventory(page)
        self.assertEqual("FAIL", status)
        self.assertIn("after wait", reason)
        self.assertIn("#tabView=software", reason)
        self.assertTrue(os.path.exists(os.path.join(self.out, "08-inventory-FAIL.png")))

    def test_a_view_that_never_landed_fails_before_its_assertions(self):
        page = self.inventory_page(url="https://localhost/app/wz-home?next=/app/it-hygiene")
        status, reason = self.run_inventory(page)
        self.assertEqual("FAIL", status)
        self.assertIn("landed on", reason)
        self.assertIn("path /app/it-hygiene", reason)

    def test_a_pass_without_bytes_in_the_png_is_a_failure(self):
        status, reason = self.run_inventory(self.inventory_page(png=b""))
        self.assertEqual("FAIL", status)
        self.assertIn("screenshot empty", reason)

    def test_a_wrong_row_fails_the_view(self):
        page = self.inventory_page(cells=self.cells([
            ("wazuh.agent.name", "agent-5x-ubuntu"), ("package.name", "adduser"),
            ("package.version", "3.118ubuntu5.1")]))
        status, reason = self.run_inventory(page)
        self.assertEqual("FAIL", status)
        self.assertIn("0 rows match", reason)

    def test_the_sidecar_of_a_failure_reports_the_api_calls_it_saw(self):
        # a FAILing view is the one whose /api/request calls are worth reading, and they used
        # to be a hardcoded {"total": 0} the README described as measured
        calls = {"total": 7, "status_ge_400": [[500, "https://localhost/api/request"]]}
        status, _reason = self.run_inventory(
            self.inventory_page(url="https://localhost/app/wz-home"), api_calls=calls)
        self.assertEqual("FAIL", status)
        with open(os.path.join(self.out, "08-inventory.json")) as handle:
            data = json.load(handle)
        self.assertEqual(calls, data["api_request_calls"])

    def test_an_unresolved_placeholder_fails_the_view_naming_it(self):
        args = self.args_for()
        session = FakeSession(self.inventory_page())
        ctx = self.ctx()
        ctx["package_5x"] = {}
        status, reason = capture.run_view(session, args, ctx, "inventory",
                                          views_json()["inventory"], 8)
        self.assertEqual("FAIL", status)
        self.assertEqual("unresolved placeholder {{package_name}}", reason)

    def test_the_vd_view_refuses_a_table_with_a_second_row(self):
        """v7: the vd view asserts `rows_eq: 1` like the other filtered views. Without it a
        grid holding the right finding AND somebody else's — the filter ignored, or the
        previous result still on screen — passed with a counter that read 1."""
        cells = self.cells([("wazuh.agent.name", "agent-5x-ubuntu"),
                            ("vulnerability.id", "CVE-2024-38428")], top=100)
        cells += self.cells([("wazuh.agent.name", "agent-4x-ubuntu"),
                             ("vulnerability.id", "CVE-2019-9999")], top=132)
        page = FakePage(
            elements={(".euiDataGrid",): ["grid"],
                      (".euiDataGrid", '[data-test-subj="discoverQueryHits"]'): ["1"],
                      ('[data-test-subj="querySubmitButton"]',): []},
            tables={".euiDataGrid": {"kind": "grid", "cells": cells, "viewport": 800,
                                     "viewport_width": 1280}},
            urls=[LIVE_VD_URL],
        )
        status, reason = capture.run_view(FakeSession(page), self.args_for(), self.ctx(), "vd",
                                          views_json()["vd"], 9)
        self.assertEqual("FAIL", status)
        self.assertIn("2 data row(s)", reason)
        self.assertIn("expected exactly 1", reason)
        self.assertTrue(os.path.exists(os.path.join(self.out, "09-vd-FAIL.png")))
        with open(os.path.join(self.out, "09-vd.json")) as handle:
            results = json.load(handle)["assertions"]
        self.assertEqual(["row", "rows_eq", "hits_eq"], [r["kind"] for r in results])
        self.assertEqual([True, False, True], [r["ok"] for r in results])
        # the row assertion alone was happy: one matching row among two is still one match
        self.assertEqual(1, results[0]["matched"])
        self.assertEqual(2, results[1]["value"])
        # with the foreign row gone it is the view that was asked for
        page.tables[".euiDataGrid"]["cells"] = cells[:2]
        status, reason = capture.run_view(FakeSession(page), self.args_for(), self.ctx(), "vd",
                                          views_json()["vd"], 9)
        self.assertEqual("PASS", status, reason)
        self.assertIn("rows_eq=1", reason)

    def test_view_check_reports_the_block_and_the_feed_verdict(self):
        args = self.args_for(["--probe-json", self.probe_file(), "--findings-json",
                              self.findings_file()])
        rep = capture.Reporter([])
        ctx = self.ctx()
        with contextlib.redirect_stdout(io.StringIO()):
            status, reason = capture.view_check(None, args, ctx, rep, "vd",
                                                views_json()["vd"], 9,
                                                ("SKIP", "blocked by 5"))
        self.assertEqual("SKIP", status)
        self.assertIn("feed verdict: feed ready, 3 findings", reason)

    def probe_file(self):
        path = os.path.join(self.out, "probe.json")
        with open(path, "w") as handle:
            json.dump(probe(), handle)
        return path

    def findings_file(self):
        path = os.path.join(self.out, "findings.json")
        with open(path, "w") as handle:
            json.dump({"001": 0, "002": 3}, handle)
        return path


class Orchestration(TempRun):
    """run() end to end with doubles: what is counted, in which order, and the exit status."""

    def capture_run(self, args, venv_state="missing"):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = capture.run(args, venv_state)
        return rc, buffer.getvalue()

    def summary_of(self, text):
        return [line for line in text.splitlines() if line.startswith("# summary:")][0]

    def test_credentials_in_the_url_abort_the_run_before_anything_else(self):
        args = self.args_for(["--dashboard-url", "https://admin:S3cret@localhost:443"])
        rc, text = self.capture_run(args)
        self.assertEqual(1, rc)
        self.assertIn("FAIL  0. setup (got: credentials in --dashboard-url are not accepted; "
                      "use DASHBOARD_USER/PASSWORD)", text)
        self.assertNotIn("S3cret", text)  # not even in the header
        self.assertIn("# summary: executed=1 passed=0 failed=1", text)
        self.assertIn("SKIP  6. agents (blocked by 0)", text)

    def test_an_out_dir_that_cannot_be_listed_is_a_counted_failure(self):
        args = self.args_for()
        original = os.listdir

        def boom(path):
            if os.path.abspath(str(path)) == os.path.abspath(self.out):
                raise PermissionError(13, "Permission denied")
            return original(path)

        os.listdir = boom
        self.addCleanup(setattr, os, "listdir", original)
        rc, text = self.capture_run(args)
        self.assertEqual(1, rc)
        self.assertIn("out dir not cleared", text)
        self.assertIn("PermissionError", text)
        # the manifest's own listing failed too, and that is check 10 — not a silent empty
        # 'Every file' table under a report that only mentions check 0
        self.assertIn("FAIL  10. manifest (got: listing ", text)
        self.assertLess(text.index("FAIL  10. manifest"), text.index("# summary:"))
        self.assertIn("failed=2", self.summary_of(text))
        with open(os.path.join(self.out, "captures.md")) as handle:
            self.assertIn("| (listing failed: PermissionError) |", handle.read())

    def test_a_manifest_that_cannot_be_written_is_counted_before_the_summary(self):
        args = self.args_for()
        original = capture.write_text

        def boom(path, text, secrets):
            if path.endswith("captures.md"):
                raise OSError(28, "No space left on device")
            return original(path, text, secrets)

        capture.write_text = boom
        self.addCleanup(setattr, capture, "write_text", original)
        rc, text = self.capture_run(args)
        self.assertEqual(1, rc)
        lines = text.splitlines()
        manifest = [i for i, line in enumerate(lines) if line.startswith("FAIL  10. manifest")]
        summary = [i for i, line in enumerate(lines) if line.startswith("# summary:")]
        self.assertEqual(1, len(manifest), text)
        self.assertIn("(got: OSError)", lines[manifest[0]])
        self.assertLess(manifest[0], summary[0])  # counted BEFORE the summary, not after it
        self.assertIn("failed=2", self.summary_of(text))  # venv (0) + manifest (10)

    def finish_with(self, captured=(), unreadable=()):
        """capture.finish() over the files already in --out, with `unreadable` the ones whose
        sha256 raises (the double: running as root, no chmod can make a file unreadable)."""
        args = self.args_for()
        targets = {os.path.join(self.out, n) for n in unreadable}
        original = capture.sha256_of

        def boom(path):
            if os.path.abspath(str(path)) in targets:
                raise PermissionError(13, "Permission denied")
            return original(path)

        capture.sha256_of = boom
        rep = capture.Reporter([])
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                rc = capture.finish(rep, args, {"run_id": "20260921T000000Z-x"},
                                    list(captured))
        finally:  # restored HERE, so a second call in the same test starts from the real one
            capture.sha256_of = original
        return rc, buffer.getvalue(), rep

    def test_an_unreadable_artifact_is_a_counted_failure_of_the_manifest(self):
        """v7: a file the manifest could not read, hash or measure used to leave a loud row
        (`(unreadable: PermissionError)`) under a report that said failed=0 and returned 0.
        A manifest that cannot vouch for a file it lists is not an evidence index."""
        with open(os.path.join(self.out, "08-inventory.json"), "w") as handle:
            handle.write("{}\n")
        with open(os.path.join(self.out, "08-inventory.png"), "wb") as handle:
            handle.write(png_header() + b"\x00" * 64)
        rc, text, rep = self.finish_with(unreadable=["08-inventory.json"])
        self.assertEqual(1, rc)
        self.assertEqual(1, rep.failed)
        self.assertIn("FAIL  10. manifest (got: unreadable: 08-inventory.json "
                      "(PermissionError))", text)
        self.assertLess(text.index("FAIL  10. manifest"), text.index("# summary:"))
        self.assertIn("failed=1", self.summary_of(text))
        with open(os.path.join(self.out, "captures.md")) as handle:
            manifest = handle.read()
        self.assertIn("| 08-inventory.json | (unreadable: PermissionError) | — | — |", manifest)
        self.assertIn("| 1280x3612 |", manifest)  # the readable one is still described
        # and a run whose artifacts are all readable is not a failure
        rc, text, rep = self.finish_with()
        self.assertEqual(0, rc)
        self.assertEqual(0, rep.failed)
        self.assertNotIn("FAIL  10.", text)

    def test_a_png_hashed_at_capture_that_cannot_be_opened_is_a_counted_failure(self):
        """v8: run_view caches the PNG's sha256 in ctx; the manifest used to reuse it and only
        `png_dimensions` opened the file again — silencing the OSError into a '—'. A PNG
        nobody can open is not evidence: `FAIL 10`, rc 1, whatever was cached."""
        png = os.path.join(self.out, "08-inventory.png")
        with open(png, "wb") as handle:
            handle.write(png_header() + b"\x00" * 64)
        cached = capture.sha256_of(png)
        ctx = {"run_id": "20260921T000000Z-x", "sha256": {"08-inventory.png": cached}}
        captured = [("inventory", "08-inventory.png", [])]

        def publish(fail_sha256):
            """finish() with every open() of the PNG raising PermissionError — or, with
            `fail_sha256=False`, only the one png_dimensions makes (the hash still answers
            what was cached), so the measurement is the only reader left to fail."""
            real_open, real_sha = open, capture.sha256_of

            def denied(path, *a, **k):
                if os.path.abspath(str(path)) == png:
                    raise PermissionError(13, "Permission denied")
                return real_open(path, *a, **k)

            capture.open = denied
            if not fail_sha256:
                capture.sha256_of = lambda path: cached if os.path.abspath(str(path)) == png \
                    else real_sha(path)
            rep = capture.Reporter([])
            buffer = io.StringIO()
            try:
                with contextlib.redirect_stdout(buffer):
                    rc = capture.finish(rep, self.args_for(), dict(ctx), captured)
            finally:
                del capture.open
                capture.sha256_of = real_sha
            return rc, buffer.getvalue(), rep

        for fail_sha256 in (True, False):
            rc, text, rep = publish(fail_sha256)
            self.assertEqual(1, rc, text)
            self.assertGreaterEqual(rep.failed, 1)
            self.assertIn("FAIL  10. manifest (got: unreadable: 08-inventory.png "
                          "(PermissionError))", text)
            self.assertLess(text.index("FAIL  10. manifest"), text.index("# summary:"))
            with open(os.path.join(self.out, "captures.md")) as handle:
                manifest = handle.read()
            self.assertIn("| 08-inventory.png | (unreadable: PermissionError) | — | — |", manifest)
        # the measurement itself no longer turns an unopenable file into a dash
        capture.open = lambda *a, **k: (_ for _ in ()).throw(PermissionError(13, "denied"))
        try:
            with self.assertRaises(PermissionError):
                capture.png_dimensions(png)
        finally:
            del capture.open
        self.assertEqual("1280x3612", capture.png_dimensions(png))
        # readable again and unchanged: nothing to report
        rep = capture.Reporter([])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, capture.finish(rep, self.args_for(), dict(ctx), captured))
        # readable, but not the bytes hashed when the view passed: counted as well
        with open(png, "ab") as handle:
            handle.write(b"tampered")
        rep = capture.Reporter([])
        with contextlib.redirect_stdout(io.StringIO()) as buffer:
            self.assertEqual(1, capture.finish(rep, self.args_for(), dict(ctx), captured))
        self.assertIn("FAIL  10. manifest (got: changed since capture: 08-inventory.png)",
                      buffer.getvalue())

    def test_every_unreadable_artifact_is_named_in_the_same_reason(self):
        for name in ("08-inventory.json", "09-vd-FAIL.png"):
            with open(os.path.join(self.out, name), "w") as handle:
                handle.write("x")
        # the captured table hashes the PNG too: both paths accumulate into one reason
        rc, text, rep = self.finish_with(
            captured=[("vd", "09-vd-FAIL.png", [])],
            unreadable=["08-inventory.json", "09-vd-FAIL.png"])
        self.assertEqual(1, rc)
        self.assertEqual(1, rep.failed)
        line = [entry for entry in text.splitlines() if entry.startswith("FAIL  10.")][0]
        self.assertIn("unreadable: 09-vd-FAIL.png (PermissionError)", line)
        self.assertIn("unreadable: 08-inventory.json (PermissionError)", line)

    def test_an_out_dir_that_cannot_be_created_is_counted_too(self):
        out = os.path.join(self.out, "nested")
        args = capture.parse_args(["--out", out])
        original = os.makedirs

        def boom(path, exist_ok=False):
            if os.path.abspath(str(path)) == os.path.abspath(out):
                raise PermissionError(13, "Permission denied")
            return original(path, exist_ok=exist_ok)

        os.makedirs = boom
        self.addCleanup(setattr, os, "makedirs", original)
        rc, text = self.capture_run(args)
        self.assertEqual(1, rc)
        self.assertIn("FAIL  0. setup (got: cannot create {0}: PermissionError)".format(out),
                      text)
        # no directory, no evidence, no manifest — and that is check 10, not a '#' note
        self.assertIn("FAIL  10. manifest (got: no out dir: {0})".format(out), text)
        self.assertLess(text.index("FAIL  10. manifest"), text.index("# summary:"))
        self.assertIn("failed=2", self.summary_of(text))
        self.assertFalse(os.path.exists(out))

    def test_a_good_abort_still_writes_its_manifest_and_returns_one(self):
        rc, text = self.capture_run(self.args_for())
        self.assertEqual(1, rc)
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith("# capture.py — "))
        self.assertIn("# manifest: {0}".format(os.path.join(self.out, "captures.md")), text)
        self.assertLess(text.index("# manifest:"), text.index("# summary:"))
        with open(os.path.join(self.out, "captures.md")) as handle:
            manifest = handle.read()
        self.assertIn("| sources | capture.py `", manifest)
        self.assertIn("| git status |", manifest)
        self.assertNotIn("git diff", manifest)
        # the dashboard version was never read (no stack in a unit test): it says so
        self.assertIn("| dashboard | declared 5.0.0-latest |", manifest)
        self.assertIn("| fichero | sha256 | tamaño | WxH |", manifest)

    def test_the_manifest_states_the_pixel_size_of_every_png(self):
        # V11: the capture is full-page, so its height is the page's. The manifest READS it
        # from each PNG's own IHDR header; anything that is not a PNG has no pixel size.
        args = self.args_for()
        with open(os.path.join(self.out, "08-inventory.png"), "wb") as handle:
            handle.write(png_header() + b"\x00" * 64)
        with open(os.path.join(self.out, "08-inventory.json"), "w") as handle:
            handle.write("{}\n")
        path, problem = capture.write_manifest(args, {"run_id": "20260920T000000Z-x"}, [])
        self.assertEqual("", problem)
        with open(path) as handle:
            manifest = handle.read()
        rows = {line.split("|")[1].strip(): line for line in manifest.splitlines()
                if line.startswith("| 08-")}
        self.assertEqual({"08-inventory.png", "08-inventory.json"}, set(rows))
        self.assertIn("| 1280x3612 |", rows["08-inventory.png"])
        self.assertIn("| 88 |", rows["08-inventory.png"])  # the bytes are still there
        self.assertTrue(rows["08-inventory.json"].rstrip().endswith("| — |"),
                        rows["08-inventory.json"])


# --------------------------------------------------------------------------- provenance


class Provenance(unittest.TestCase):
    def test_sources_row_lists_every_file_that_ran(self):
        self.assertEqual(
            "| sources | capture.py `aa` · capture_logic.py `bb` · views.json `cc` |",
            cl.sources_row([("capture.py", "aa"), ("capture_logic.py", "bb"),
                            ("views.json", "cc")]))
        self.assertEqual("| sources | (none) |", cl.sources_row([]))

    def test_git_status_row_keeps_staged_and_untracked_lines(self):
        self.assertEqual("| git status | clean |", cl.git_status_row(""))
        self.assertEqual("| git status | clean |", cl.git_status_row(None))
        self.assertEqual("| git status | `M  capture.py; ?? new.py` |",
                         cl.git_status_row("M  capture.py\n?? new.py\n"))

    def test_the_dashboard_version_is_measured_or_declared_as_declared(self):
        self.assertEqual("| dashboard | `2.19.1` |", cl.dashboard_row("2.19.1", "5.0.0-latest"))
        self.assertEqual("| dashboard | declared 5.0.0-latest |",
                         cl.dashboard_row("", "5.0.0-latest"))
        self.assertEqual("| dashboard | declared 5.0.0-latest |",
                         cl.dashboard_row(None, "5.0.0-latest"))
        self.assertEqual("2.19.1", cl.dashboard_version(
            {"name": "wazuh-dashboard", "version": {"number": "2.19.1", "build_hash": "abc"}}))
        self.assertEqual("2.19.1", cl.dashboard_version({"version": "2.19.1"}))
        self.assertEqual("", cl.dashboard_version({}))
        self.assertEqual("", cl.dashboard_version(None))
        self.assertEqual("", cl.dashboard_version({"version": {"build_hash": "abc"}}))

    def test_the_real_manifest_pins_the_sources_by_hash(self):
        args = capture.parse_args([])
        entries = dict(capture.source_digests(args))
        self.assertEqual({"capture.py", "capture_logic.py", "views.json"}, set(entries))
        for name, digest in entries.items():
            self.assertEqual(64, len(digest), name)


# --------------------------------------------------------------------------- 9/10. vd


class VdVerdict(unittest.TestCase):
    def test_ready_with_findings_for_the_5x_agent(self):
        status, reason = cl.vd_verdict(probe(), {"001": 0, "002": 3}, "002")
        self.assertEqual("PASS", status)
        self.assertIn("3 findings", reason)
        self.assertIn("agent 002", reason)

    def test_another_agents_findings_do_not_count(self):
        status, reason = cl.vd_verdict(probe(), {"001": 7, "002": 0}, "002")
        self.assertEqual("FAIL", status)
        self.assertEqual("feed ready, 0 findings indexed for agent 002", reason)

    def test_failed_feed_does_not_need_findings(self):
        # the order matters: capture.py must not query the indexer for a feed that failed
        status, reason = cl.vd_verdict(probe(status="failed"), None, "002")
        self.assertEqual("FAIL", status)
        self.assertIn("status=failed", reason)
        self.assertEqual(("FAIL", reason), cl.probe_blocks(probe(status="failed")))

    def test_probe_blocks_only_on_settled_probes(self):
        self.assertIsNone(cl.probe_blocks(probe()))
        self.assertIsNone(cl.probe_blocks(probe(status="updating")))
        self.assertEqual("FAIL", cl.probe_blocks(None)[0])
        self.assertEqual("SKIP", cl.probe_blocks(probe(enabled=False))[0])

    def test_disabled(self):
        status, reason = cl.vd_verdict(probe(enabled=False, status="updating"), {"002": 9}, "002")
        self.assertEqual("SKIP", status)
        self.assertEqual("vulnerability-detector disabled in config", reason)

    def test_not_available_is_not_ready(self):
        status, reason = cl.vd_verdict(probe(available=False), {"002": 5}, "002")
        self.assertEqual("FAIL", status)
        self.assertIn("not ready", reason)

    def test_offset_zero_is_not_ready(self):
        status, reason = cl.vd_verdict(probe(offset=0), {"002": 5}, "002")
        self.assertEqual("FAIL", status)
        self.assertIn("not ready", reason)

    def test_last_successful_update_zero_is_not_ready(self):
        status, reason = cl.vd_verdict(probe(lsu=0), {"002": 5}, "002")
        self.assertEqual("FAIL", status)
        self.assertIn("not ready", reason)

    def test_updating_timeout(self):
        status, reason = cl.vd_verdict(probe(status="updating", offset=12345), {"002": 0}, "002")
        self.assertEqual("FAIL", status)
        self.assertIn("offset=12345", reason)
        self.assertIn("last_successful_update=1789793031", reason)

    def test_unreachable(self):
        self.assertEqual("FAIL", cl.vd_verdict(None, {}, "002")[0])
        status, reason = cl.vd_verdict({"error": "No such file or directory"}, {"002": 1}, "002")
        self.assertEqual("FAIL", status)
        self.assertIn("unreachable", reason)

    def test_ready_without_a_5x_agent(self):
        status, reason = cl.vd_verdict(probe(), {"001": 9}, "")
        self.assertEqual("FAIL", status)
        self.assertIn("no 5.x agent", reason)

    def test_probe_source(self):
        self.assertEqual(("file", "/tmp/probe.json"),
                         cl.probe_source("/tmp/probe.json", "/var/wazuh-manager/queue/sockets/x"))
        self.assertEqual(("socket", "/tmp/no-existe.sock"),
                         cl.probe_source("", "/tmp/no-existe.sock"))


# --------------------------------------------------------------------------- 14. browsers


class Browsers(unittest.TestCase):
    def test_variable_is_set_not_defaulted(self):
        self.assertEqual("/w/venv-dashboard/browsers",
                         cl.browsers_env({}, "/w/venv-dashboard")["PLAYWRIGHT_BROWSERS_PATH"])
        self.assertEqual(
            "/w/venv-dashboard/browsers",
            cl.browsers_env({"PLAYWRIGHT_BROWSERS_PATH": "/root/.cache/ms-playwright"},
                            "/w/venv-dashboard")["PLAYWRIGHT_BROWSERS_PATH"])

    def test_playwright_is_pinned(self):
        # "reproducible captures" with whatever pip resolves that day is not reproducible: the
        # run asserts layout, and layout moves with the browser
        self.assertEqual("playwright==1.63.0", capture.PLAYWRIGHT_PIN)
        source = inspect.getsource(capture.do_setup)
        self.assertIn("PLAYWRIGHT_PIN", source)
        self.assertNotIn('"playwright"]', source)

    def test_override_wins_and_the_rest_is_kept(self):
        env = cl.browsers_env({"PATH": "/bin"}, "/w/venv-dashboard", "/opt/browsers")
        self.assertEqual("/opt/browsers", env["PLAYWRIGHT_BROWSERS_PATH"])
        self.assertEqual("/bin", env["PATH"])
        self.assertEqual("/w/venv/browsers", cl.browsers_dir("/w/venv/"))


# --------------------------------------------------------------------------- plan/format


class PlanChecks(unittest.TestCase):
    def test_only_agents_skips_4_4b_and_9(self):
        plan = cl.plan_checks(["agents"], "agents")
        self.assertEqual([0, 1, 2, 3, 4, "4b", 5, 6, 7, 8, 9], [n for n, _n, _r in plan])
        requested = {n: req for n, _name, req in plan}
        self.assertTrue(all(requested[n] for n in (0, 1, 2, 3, 5, 6)))
        self.assertFalse(requested[4])
        self.assertFalse(requested["4b"])
        self.assertFalse(any(requested[n] for n in (7, 8, 9)))

    def test_sample_check_is_requested_by_inventory_or_vd(self):
        for views in (["inventory"], ["vd"], ["inventory", "vd"]):
            requested = {n: req for n, _name, req in cl.plan_checks(views, "none")}
            self.assertTrue(requested["4b"], views)
        requested = {n: req for n, _name, req in cl.plan_checks(["discover"], "agents")}
        self.assertFalse(requested["4b"])

    def test_events_mode(self):
        views = ["agents", "discover", "inventory", "vd"]
        self.assertFalse({n: r for n, _x, r in cl.plan_checks(views, "none")}[4])
        self.assertFalse({n: r for n, _x, r in cl.plan_checks(views, "benchmark")}[4])
        self.assertTrue({n: r for n, _x, r in cl.plan_checks(views, "agents")}[4])


class Format(unittest.TestCase):
    def test_lines(self):
        self.assertEqual("# summary: executed=6 passed=5 failed=1 skipped=4",
                         cl.summary_line(6, 5, 1, 4))
        self.assertEqual("PASS  1. indexer cluster health (got: green)",
                         cl.format_line("PASS", 1, "indexer cluster health", "green"))
        self.assertEqual("SKIP  9. vd (not requested)",
                         cl.format_line("SKIP", 9, "vd", "not requested"))
        self.assertEqual("PASS  4b. inventory sample (got: package wget)",
                         cl.format_line("PASS", "4b", "inventory sample", "package wget"))
        self.assertEqual("FAIL  10. manifest (got: OSError)",
                         cl.format_line("FAIL", cl.MANIFEST_CHECK, cl.CHECK_NAMES[10], "OSError"))
        self.assertEqual(2, cl.blocked_by([2, 5]))
        self.assertIsNone(cl.blocked_by([3, 4]))


# --------------------------------------------------------------------------- views.json


class ViewsFile(unittest.TestCase):
    def test_every_view_declares_its_landing_its_table_and_only_known_assertions(self):
        views = views_json()
        self.assertEqual(set(cl.VIEW_NAMES), set(views))
        for name, cfg in views.items():
            self.assertIn("landing", cfg, name)
            self.assertEqual({"path", "hash_route", "hash_params", "state"},
                             set(cfg["landing"]), name)
            self.assertTrue(cfg["landing"]["path"].startswith("/app/"), name)
            self.assertIn(cfg["table"]["kind"], ("grid", "table", "doctable"), name)
            self.assertTrue(cfg["scope_selector"], name)
            self.assertTrue(cfg["assertions"], name)
            for spec in cfg["assertions"]:
                self.assertEqual(1, len(spec), (name, spec))
                self.assertIn(list(spec)[0], ("row", "rows_eq", "hits_eq"), name)
            if any("hits_eq" in spec for spec in cfg["assertions"]):
                self.assertTrue(cfg.get("count_selector"), name)

    def test_every_filtered_view_demands_exactly_one_row_and_one_hit(self):
        """The three views filtered down to ONE document (D-8b: `rows_eq: 1` + `hits_eq: 1`).
        `vd` carried only `hits_eq`, so a grid with the right finding AND a foreign one passed
        while the counter read 1."""
        views = views_json()
        for name in ("discover", "inventory", "vd"):
            self.assertIn({"rows_eq": 1}, views[name]["assertions"], name)
            self.assertIn({"hits_eq": 1}, views[name]["assertions"], name)
        # the agents view is the one that counts agents, not documents
        self.assertIn({"rows_eq": "{{agent_count}}"}, views["agents"]["assertions"])

    def test_no_view_is_proven_by_a_substring_any_more(self):
        with open(VIEWS_FILE) as handle:
            raw = handle.read()
        self.assertEqual(0, raw.count("row_text"))
        self.assertEqual(0, raw.count("url_must_contain"))
        self.assertEqual(0, raw.count("hits_min"))
        self.assertEqual(0, raw.count("count_min"))

    def test_the_views_filter_by_this_runs_data(self):
        views = views_json()
        self.assertIn("{{nonce}}", views["discover"]["route"])
        self.assertIn("{{agent_id_5x}}", views["inventory"]["route"])
        self.assertIn("{{package_name}}", views["inventory"]["route"])
        self.assertIn("{{cve_5x}}", views["vd"]["route"])
        self.assertEqual({"user.name", "wazuh.agent.name", "wazuh.protocol.location"},
                         set(views["discover"]["assertions"][0]["row"]))
        self.assertEqual({"wazuh.agent.name", "package.name", "package.version"},
                         set(views["inventory"]["assertions"][0]["row"]))


if __name__ == "__main__":
    unittest.main()
