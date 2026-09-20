#!/usr/bin/env python3
"""DOM tests of the three extraction scripts — a real Chromium, no network, no stack.

    $WORKSPACE/venv-dashboard/bin/python -m unittest -v test_capture_dom

`test_capture_logic.py` proves every DECISION with a fake page, which is exactly what the
fake cannot do for the JavaScript those decisions are fed from: `FakePage.evaluate` ignores
the script it is handed, so column identity (`byLeft`, the header's own DOM position), the
visible text of a cell (its `innerText` MINUS the `.euiScreenReaderOnly` span), the horizontal
geometry, the truncation flag and the "exactly one table in the scope" guard were only ever
exercised by a live run against the dashboard — and one of them (`tds[header.index]`) had to
be corrected live, with nothing red to warn first.

These tests load, with `page.set_content()`, HTML fixtures copied from the DOM the probes of
2026-09-20 recorded against dashboard `5.0.0-latest` (`anexos/e5a/probes/resultados.md`,
sections probe-columns and probe-canvas): the IT Hygiene data grid (header cells at `left`
8/48/293/538/782/1027, absolutely positioned row cells sharing those lefts, a
`discoverQueryHits` under `.euiDataGrid__controls`), the agents table (a leading selection
`<th>` without `data-test-subj`, then `tableHeaderCell_<field>_<n>`) and Discover's
`docTable` inside `.dscCanvas`. The selectors come from `views.json`, so a view whose scope or
table moved fails here too.

The browser is launched once per class, headless and with `--no-sandbox` (the capturer runs as
root), and nothing is ever fetched: the only content is the string these fixtures build.
Without the venv — or without `playwright` importable — every test SKIPs, so the system
interpreter running `python3 -m unittest test_capture_dom` is a clean skip, not an error.
"""

import json
import os
import unittest

import capture

WORKSPACE = capture.workspace_root()
VENV = os.environ.get("DASHBOARD_VENV") or os.path.join(WORKSPACE, "venv-dashboard")

# Same policy as capture.py: PLAYWRIGHT_BROWSERS_PATH is SET, never inherited — an ambient
# value would send the driver to ~/.cache/ms-playwright while --setup installed under the venv.
os.environ.update(capture.browsers_env(os.environ, VENV,
                                       os.environ.get("DASHBOARD_BROWSERS_PATH", "")))

try:  # the venv's interpreter has it; the system one does not
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT = os.path.isdir(VENV)
    PLAYWRIGHT_WHY = "" if PLAYWRIGHT else "venv missing: {0}".format(VENV)
except Exception as exc:  # pragma: no cover - depends on the interpreter, not on the code
    sync_playwright = None
    PLAYWRIGHT = False
    PLAYWRIGHT_WHY = "playwright not importable ({0}); run it with {1}/bin/python".format(
        type(exc).__name__, VENV)

VIEWS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "views.json")

# The fields and the `left` the live IT Hygiene grid drew them at (probe-columns, GRID).
GRID_COLUMNS = [
    ("inspectCollapseColumn", 8, 40),
    ("wazuh.agent.name", 48, 245),
    ("package.vendor", 293, 245),
    ("package.name", 538, 244),
    ("package.version", 782, 245),
    ("package.type", 1027, 245),
]
ROW_TOPS = (34, 66)

# EUI's own screen-reader class: the text IS rendered (1px, clipped), so it reaches innerText
# and has to be subtracted — "Row: 1, Column: 2: adduser" is not what the screenshot shows.
CSS = """
  body { margin: 0; padding: 0; font: 12px sans-serif; }
  .euiDataGrid { position: relative; width: 1272px; height: 200px; }
  .euiDataGridHeaderCell, .euiDataGridRowCell { position: absolute; height: 32px;
      line-height: 32px; overflow: hidden; box-sizing: border-box; }
  .truncate { text-overflow: ellipsis; white-space: nowrap; overflow: hidden; }
  .euiScreenReaderOnly { position: absolute; width: 1px; height: 1px; overflow: hidden;
      clip: rect(1px, 1px, 1px, 1px); white-space: nowrap; }
  table { border-collapse: collapse; }
  th, td { padding: 4px; text-align: left; }
"""

# `package.vendor` is the column the live 08-inventory.png showed cut with an ellipsis (the
# fourth review's objection 3): it is the same string here, HTML-escaped as the dashboard
# renders it.
VENDOR = "Ubuntu Developers &lt;ubuntu-devel-discuss@lists.ubuntu.com&gt;"
VENDOR_TEXT = "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"

ROWS = [
    {"wazuh.agent.name": "agent-5x-ubuntu", "package.vendor": VENDOR,
     "package.name": "adduser", "package.version": "3.118ubuntu5", "package.type": "deb"},
    {"wazuh.agent.name": "agent-5x-ubuntu", "package.vendor": VENDOR,
     "package.name": "adduser.old", "package.version": "3.118ubuntu5.1",
     "package.type": "deb"},
]


def page_html(body):
    return "<!doctype html><html><head><meta charset='utf-8'><style>{0}</style></head>" \
           "<body>{1}</body></html>".format(CSS, body)


def grid_html(shift=0, hits="2", unmatched_cell=True, hidden_cell=True, controls=True):
    """The IT Hygiene data grid: two rows, six columns, absolutely positioned cells.

    `shift` moves every column right (a grid wider than the viewport: the cells are still
    readable, they are just not in the screenshot any more). `unmatched_cell` adds a cell at a
    `left` no header has — EUI draws control and footer cells too — which the extractor must
    DROP: a cell whose column cannot be named is not evidence.
    """
    parts = []
    if controls:
        parts.append(
            '<div class="euiDataGrid__controls"><div class="euiDataGrid__leftControls">'
            '<span>Displaying <strong data-test-subj="discoverQueryHits">{0}</strong> hits'
            '</span></div></div>'.format(hits))
    for field, left, width in GRID_COLUMNS:
        parts.append(
            '<div class="euiDataGridHeaderCell" role="columnheader" '
            'data-test-subj="dataGridHeaderCell-{0}" style="left:{1}px;top:0px;width:{2}px">'
            '{0}</div>'.format(field, left + shift, width))
    for index, (top, values) in enumerate(zip(ROW_TOPS, ROWS), start=1):
        for column, (field, left, width) in enumerate(GRID_COLUMNS, start=1):
            text = "" if field == "inspectCollapseColumn" else values.get(field, "")
            klass = "euiDataGridRowCell truncate" if field == "package.vendor" \
                else "euiDataGridRowCell"
            parts.append(
                '<div class="{0}" role="gridcell" data-test-subj="dataGridRowCell" '
                'style="left:{1}px;top:{2}px;width:{3}px"><span class="euiScreenReaderOnly">'
                'Row: {4}, Column: {5}:</span>{6}</div>'.format(
                    klass, left + shift, top, width, index, column, text))
    if unmatched_cell:
        parts.append(
            '<div class="euiDataGridRowCell" role="gridcell" data-test-subj="dataGridRowCell" '
            'style="left:{0}px;top:{1}px;width:8px">footer</div>'.format(
                1272 + shift, ROW_TOPS[0]))
    if hidden_cell:
        parts.append(
            '<div class="euiDataGridRowCell" role="gridcell" data-test-subj="dataGridRowCell" '
            'style="display:none;left:{0}px;top:{1}px;width:244px">never-rendered</div>'.format(
                538 + shift, ROW_TOPS[0]))
    return page_html('<div class="euiDataGrid">{0}</div>'.format("".join(parts)))


AGENTS_HEADERS = [("", ""), ("id_0", "ID"), ("name_1", "Name"), ("ip_2", "IP address"),
                  ("group_3", "Group(s)"), ("os.name,os.version_4", "Operating system"),
                  ("version_5", "Version"), ("status_6", "Status"), ("", "Actions")]
AGENTS_ROWS = [
    ["", "001", "agent-4x-ubuntu", "172.20.0.2", "default", "Ubuntu 22.04.5 LTS", "4.14.3",
     "active", "View agent details"],
    ["", "002", "agent-5x-ubuntu", "172.20.0.3", "default", "Ubuntu 22.04.5 LTS", "v5.0.0",
     "active", "View agent details"],
]


def agents_html(hidden_row=True):
    """The endpoints table: EUI numbers `tableHeaderCell_<field>_<n>` over its DATA columns
    only, so the leading selection `<th>` (no data-test-subj) shifts every `<td>` by one —
    `name_1` is the 3rd `<th>`/`<td>`, `status_6` the 8th (probe-columns, AGENTS)."""
    head = "".join(
        '<th{0}>{1}</th>'.format(
            ' data-test-subj="tableHeaderCell_{0}"'.format(subj) if subj else "", label)
        for subj, label in AGENTS_HEADERS)
    body = ""
    for values in AGENTS_ROWS:
        body += "<tr>{0}</tr>".format("".join("<td>{0}</td>".format(v) for v in values))
    if hidden_row:
        body += '<tr style="display:none">{0}</tr>'.format(
            "".join("<td>{0}</td>".format(v) for v in
                    ["", "003", "agent-never-rendered", "-", "-", "-", "-", "active", "-"]))
    return page_html(
        '<div data-test-subj="table-with-search-bar" class="euiBasicTable">'
        '<table class="euiTable"><thead><tr>{0}</tr></thead><tbody>{1}</tbody></table>'
        "</div>".format(head, body))


DOC_COLUMNS = [("", ""), ("", "Time"), ("user.name", "user.name"),
               ("wazuh.agent.name", "wazuh.agent.name"),
               ("wazuh.protocol.location", "wazuh.protocol.location")]
DOC_ROW = ["", "Sep 20, 2026 @ 21:17:28.256", "e2e-capture-6120a743", "agent-5x-ubuntu",
           "/var/log/dpkg.log"]


def doctable_html(with_table=True, hits="1"):
    """Discover inside `.dscCanvas`: the counter and the document table under the same
    `dscCanvasResults` (probe-canvas). Two headers carry `docTableHeader-<field>`, one does
    not — both paths of the extractor are live here."""
    head = "".join(
        '<th data-test-subj="docTableHeaderField">{0}</th>'.format(
            '<span data-test-subj="docTableHeader-{0}">{0}</span>'.format(field)
            if field else label)
        for field, label in DOC_COLUMNS)
    cells = "".join(
        '<td data-test-subj="docTableField">{0}</td>'.format(
            '<button data-test-subj="docTableExpandToggleColumn"></button>' if not value
            else value)
        for value in DOC_ROW)
    table = ('<div data-test-subj="discoverTable"><table data-test-subj="docTable" '
             'class="osd-table table"><thead><tr>{0}</tr></thead><tbody><tr>{1}</tr>'
             "</tbody></table></div>".format(head, cells)) if with_table else ""
    return page_html(
        '<div class="dscCanvas"><div data-test-subj="dscCanvasResults">'
        '<div data-test-subj="dscResultsActionBar"><div data-test-subj="dscResultCount">'
        '<span data-test-subj="discoverQueryHits">{0}</span></div></div>{1}</div></div>'
        .format(hits, table))


def views():
    with open(VIEWS) as handle:
        return json.load(handle)


@unittest.skipUnless(PLAYWRIGHT, PLAYWRIGHT_WHY or "playwright/venv not available")
class DomExtraction(unittest.TestCase):
    """The real scripts, the real selectors of views.json, a real Chromium."""

    @classmethod
    def setUpClass(cls):
        cls._play = sync_playwright().start()
        cls.browser = cls._play.chromium.launch(args=["--no-sandbox"])
        cls.context = cls.browser.new_context(viewport=capture.VIEWPORT)
        cls.page = cls.context.new_page()

    @classmethod
    def tearDownClass(cls):
        for closer in (cls.context.close, cls.browser.close, cls._play.stop):
            try:
                closer()
            except Exception:
                pass

    def extract(self, html, view):
        self.page.set_content(html)
        return capture.extract_rows(self.page, views()[view])

    # ------------------------------------------------------------------ grid

    def test_the_grid_is_read_row_by_row_and_column_by_column(self):
        rows, height, width, problem = self.extract(grid_html(), "inventory")
        self.assertIsNone(problem)
        self.assertEqual((800, 1280), (height, width))
        self.assertEqual(2, len(rows))
        self.assertEqual([34, 66], [r["top"] for r in rows])
        self.assertEqual([66, 98], [r["bottom"] for r in rows])
        # exactly the six columns of the header row: the cell at a left no header has (and
        # the one that is not rendered at all) are dropped, not attributed to a neighbour
        self.assertEqual({f for f, _l, _w in GRID_COLUMNS}, set(rows[0]["columns"]))
        self.assertEqual("adduser", rows[0]["columns"]["package.name"])
        self.assertEqual("3.118ubuntu5", rows[0]["columns"]["package.version"])
        self.assertEqual("agent-5x-ubuntu", rows[0]["columns"]["wazuh.agent.name"])
        self.assertEqual("", rows[0]["columns"]["inspectCollapseColumn"])
        # the second row is the SIMILAR one: it must stay a second row
        self.assertEqual("adduser.old", rows[1]["columns"]["package.name"])
        self.assertEqual("3.118ubuntu5.1", rows[1]["columns"]["package.version"])
        # dropping those two cells is all they did: without them the reading is identical
        clean, _h, _w, _p = self.extract(
            grid_html(unmatched_cell=False, hidden_cell=False), "inventory")
        self.assertEqual([r["columns"] for r in rows], [r["columns"] for r in clean])

    def test_the_visible_text_is_not_the_screen_reader_text(self):
        self.page.set_content(grid_html())
        raw = self.page.evaluate(
            "() => document.querySelectorAll('[data-test-subj=dataGridRowCell]')[3].innerText")
        self.assertIn("Row: 1, Column: 4:", raw)  # the browser really renders it
        rows, _h, _w, problem = capture.extract_rows(self.page, views()["inventory"])
        self.assertIsNone(problem)
        for row in rows:
            for column, value in row["columns"].items():
                self.assertNotIn("Row:", value, column)
                self.assertNotIn("Column:", value, column)
        self.assertEqual("adduser", rows[0]["columns"]["package.name"])

    def test_every_cell_carries_its_own_geometry_and_truncation(self):
        rows, _h, _w, problem = self.extract(grid_html(), "inventory")
        self.assertIsNone(problem)
        cells = rows[0]["cells"]
        self.assertEqual({"left": 538, "right": 782, "truncated": False},
                         cells["package.name"])
        self.assertEqual(1027, cells["package.type"]["left"])
        self.assertEqual(48, cells["wazuh.agent.name"]["left"])
        # the vendor column is the one the live 08-inventory.png showed cut with an ellipsis:
        # innerText still hands back the WHOLE value, which is exactly the trap
        self.assertTrue(cells["package.vendor"]["truncated"])
        self.assertEqual(VENDOR_TEXT, rows[0]["columns"]["package.vendor"])
        self.assertFalse(cells["package.version"]["truncated"])
        self.assertFalse(cells["wazuh.agent.name"]["truncated"])

    def test_a_grid_wider_than_the_viewport_is_not_in_the_screenshot(self):
        rows, height, width, problem = self.extract(grid_html(shift=800), "inventory")
        self.assertIsNone(problem)
        self.assertEqual(1280, width)
        self.assertEqual(1338, rows[0]["cells"]["package.name"]["left"])
        self.assertFalse(capture.row_in_frame(rows[0], height, width, ["package.name"]))
        self.assertTrue(capture.row_in_frame(rows[0], height, width, []))

    def test_the_whole_assertion_path_runs_against_the_real_dom(self):
        cfg = dict(views()["inventory"])
        cfg["assertions"] = [cfg["assertions"][0], {"rows_eq": 2}, {"hits_eq": 2}]
        self.page.set_content(grid_html(hits="2"))
        ctx = {"agent_names": ["agent-5x-ubuntu"], "agent_id_5x": "002",
               "agent_name_5x": "agent-5x-ubuntu",
               "package_5x": {"name": "adduser", "version": "3.118ubuntu5"}}
        results = capture.eval_assertions(self.page, cfg, ctx)
        self.assertEqual([True, True, True], [r["ok"] for r in results],
                         [r.get("reason") for r in results])
        self.assertEqual(1, results[0]["matched"])
        # the similar row is not this row, in a real browser either
        ctx["package_5x"] = {"name": "adduser", "version": "3.118ubuntu5.1"}
        failed = capture.eval_assertions(self.page, cfg, ctx)[0]
        self.assertFalse(failed["ok"])
        self.assertIn("0 rows match", failed["reason"])

    def test_an_assertion_on_a_truncated_column_passes_with_its_note(self):
        cfg = dict(views()["inventory"])
        # the vendor really is on screen and really is cut with an ellipsis. V11: the PNG is
        # the whole page and the row is proven column by column, so this is a PASS — with the
        # truncation measured in a real browser and written down as a note
        cfg["assertions"] = [{"row": {"package.name": "adduser", "package.vendor": VENDOR_TEXT}}]
        self.page.set_content(grid_html())
        result = capture.eval_assertions(self.page, cfg, {})[0]
        self.assertEqual(1, result["matched"])
        self.assertTrue(result["ok"], result.get("reason"))
        self.assertEqual({"in_viewport": True, "truncated_columns": ["package.vendor"]},
                         result["frame_note"])
        self.assertEqual("frame: in_viewport=true, truncated=[package.vendor]",
                         capture.frame_note_line([result]))

    def test_a_row_drawn_past_the_right_edge_is_noted_and_still_proves_the_view(self):
        # the same grid shifted 800 px right: every asserted column is outside the viewport,
        # which the full-page capture makes a note (V11) rather than a verdict
        cfg = dict(views()["inventory"])
        cfg["assertions"] = [cfg["assertions"][0]]
        self.page.set_content(grid_html(shift=800))
        ctx = {"agent_names": ["agent-5x-ubuntu"], "agent_id_5x": "002",
               "agent_name_5x": "agent-5x-ubuntu",
               "package_5x": {"name": "adduser", "version": "3.118ubuntu5"}}
        result = capture.eval_assertions(self.page, cfg, ctx)[0]
        self.assertTrue(result["ok"], result.get("reason"))
        self.assertFalse(result["frame_note"]["in_viewport"])
        # …and a row that is NOT this run's document still fails, wherever it was drawn
        ctx["package_5x"] = {"name": "adduser", "version": "3.118ubuntu5.1"}
        failed = capture.eval_assertions(self.page, cfg, ctx)[0]
        self.assertFalse(failed["ok"])
        self.assertIn("0 rows match", failed["reason"])

    def test_the_counter_is_read_inside_the_scope(self):
        self.page.set_content(grid_html(hits="2"))
        self.assertEqual((2, None), capture.count_hits(self.page, views()["inventory"]))
        self.page.set_content(grid_html(hits="2", controls=False))
        hits, problem = capture.count_hits(self.page, views()["inventory"])
        self.assertIsNone(hits)
        self.assertIn("counter missing", problem)

    # ------------------------------------------------------------------ table

    def test_the_selection_column_does_not_shift_the_agents_columns(self):
        rows, height, width, problem = self.extract(agents_html(), "agents")
        self.assertIsNone(problem)
        self.assertEqual((800, 1280), (height, width))
        self.assertEqual(2, len(rows), "the display:none row is not a row")
        self.assertEqual("agent-4x-ubuntu", rows[0]["columns"]["name"])
        self.assertEqual("001", rows[0]["columns"]["id"])
        self.assertEqual("active", rows[0]["columns"]["status"])
        self.assertEqual("4.14.3", rows[0]["columns"]["version"])
        self.assertEqual("172.20.0.2", rows[0]["columns"]["ip"])
        self.assertEqual("Ubuntu 22.04.5 LTS", rows[0]["columns"]["os.name,os.version"])
        self.assertEqual("agent-5x-ubuntu", rows[1]["columns"]["name"])
        self.assertEqual("v5.0.0", rows[1]["columns"]["version"])
        # the two headers without a data-test-subj (selection, actions) are not columns
        self.assertEqual({"id", "name", "ip", "group", "os.name,os.version", "version",
                          "status"}, set(rows[0]["columns"]))
        self.assertTrue(rows[0]["cells"]["status"]["right"] <= 1280)

    def test_the_agents_rows_are_matched_column_by_column(self):
        self.page.set_content(agents_html())
        cfg = views()["agents"]
        ctx = {"agent_names": ["agent-4x-ubuntu", "agent-5x-ubuntu"], "agent_count": 2}
        results = capture.eval_assertions(self.page, cfg, ctx)
        self.assertEqual([True, True, True], [r["ok"] for r in results],
                         [r.get("reason") for r in results])

    # ------------------------------------------------------------------ doctable

    def test_discover_maps_its_headers_onto_its_cells(self):
        rows, _h, _w, problem = self.extract(doctable_html(), "discover")
        self.assertIsNone(problem)
        self.assertEqual(1, len(rows))
        columns = rows[0]["columns"]
        self.assertEqual("e2e-capture-6120a743", columns["user.name"])
        self.assertEqual("agent-5x-ubuntu", columns["wazuh.agent.name"])
        self.assertEqual("/var/log/dpkg.log", columns["wazuh.protocol.location"])
        self.assertEqual("Sep 20, 2026 @ 21:17:28.256", columns["Time"])
        self.assertFalse(rows[0]["cells"]["user.name"]["truncated"])

    # ------------------------------------------------------------------ the guards

    def test_two_grids_in_the_scope_are_ambiguous_not_merged(self):
        html = grid_html().replace(
            "</body>", '<div class="euiDataGrid"></div></body>')
        rows, _h, _w, problem = self.extract(html, "inventory")
        self.assertEqual([], rows)
        self.assertEqual("ambiguous table (2) for .euiDataGrid", problem)

    def test_a_scope_without_its_table_says_so(self):
        rows, _h, _w, problem = self.extract(doctable_html(with_table=False), "discover")
        self.assertEqual([], rows)
        self.assertEqual('table missing: table[data-test-subj="docTable"]', problem)

    def test_a_scope_that_is_not_there_is_never_an_empty_table(self):
        rows, _h, _w, problem = self.extract(page_html("<div>nothing here</div>"), "inventory")
        self.assertEqual([], rows)
        self.assertEqual("scope missing: .euiDataGrid", problem)


if __name__ == "__main__":
    unittest.main()
