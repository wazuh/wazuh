#!/usr/bin/env python3
"""Mechanical documentation checks: links, anchors, page publication, example syntax, diagrams.

Covers the mdBook (every .md under docs/) and the developer documentation (tracked .md files
under src/, framework/, api/ and tools/). It needs a built book, whose heading ids it uses as the
anchor truth: run it from docs/build.sh after `mdbook build`, or pass --book.

Each finding prints as `path:line: [check] message`; the exit status is 1 when there is any.
`--list-checks` prints every check. A block that is deliberately not valid in its language (an
excerpt, a template with placeholders) is fenced with a `fragment` attribute: ```json,fragment.
A path that is only an illustration uses a placeholder (`src/<module>/`), which is not checked.
"""

import argparse
import csv
import glob
import html
import json
import os
import posixpath
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

import yaml

DOCS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(DOCS)
INVENTORY = os.path.join(REPO, '.github/actions/check_files/manager_base.csv')
MERMAID_CHECKER = os.path.join(DOCS, 'tools', 'check-mermaid.js')
# jsdom (pinned in docs/tools/package-lock.json) is installed outside docs/, because mdBook copies
# every file under docs/ into the site.
NODE_DIR = os.environ.get('WAZUH_DOCS_NODE_DIR', os.path.expanduser('~/.cache/wazuh-docs-tools'))
DEV_TREES = ('src', 'framework', 'api', 'tools')
# Trees that are not ours to keep correct (vendored or downloaded).
DEV_EXCLUDE = re.compile(r'^src/(external|shared_modules/http-request)/')

CHECKS = {
    'unpublished': 'a page under docs/ that SUMMARY.md does not list is never published',
    'link-target': 'a relative link to a file that does not exist',
    'link-anchor': 'a link to a heading id that does not exist on the target page',
    'link-outside-book': 'a book page linking outside docs/, which the rendered site does not serve',
    'link-html': 'a book page linking a built .html name instead of its .md source',
    'link-unpublished': 'a book page linking a page SUMMARY.md does not list',
    'link-absolute': 'a site-absolute link, which breaks wherever the book is hosted',
    'block-json': 'a ```json block that does not parse',
    'block-yaml': 'a ```yaml block that does not parse',
    'block-xml': 'an ```xml block that is not well-formed',
    'block-mermaid': 'a ```mermaid diagram that the bundled mermaid cannot parse',
    'installed-bin': 'a /var/wazuh-manager/bin/ path that the package does not install',
    'repo-path': 'a `path` in inline code naming a repository file or directory that does not exist',
}

FENCE_OPEN = re.compile(r'^( {0,3})(`{3,}|~{3,})\s*([^\s`]*)(.*)$')
INLINE_CODE = re.compile(r'(`+)(.+?)\1')
INLINE_LINK = re.compile(r'!?\[(?:[^\[\]\\]|\\.|\[[^\[\]]*\])*\]\(\s*<?([^)\s>]*)>?(?:\s+(?:"[^"]*"|\'[^\']*\'))?\s*\)')
REF_DEF = re.compile(r'^ {0,3}\[[^\]]+\]:\s+<?(\S+?)>?(?:\s+.*)?$')
HTML_ATTR = re.compile(r'<(?:a|img)\b[^>]*?\b(?:href|src)="([^"]+)"', re.IGNORECASE)
HEADING = re.compile(r'^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$')
EXPLICIT_ID = re.compile(r'\{#([^}\s]+)[^}]*\}\s*$')
HTML_ID = re.compile(r'<[^>]+\b(?:id|name)="([^"]+)"')
SCHEME = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*:')
# Prefixes that only name repository paths: `etc/`, `api/configuration/` and friends also name
# paths under the installed prefix, so they are not checked.
REPO_PATH = re.compile(r'^(?:src|docs|tools|packages|\.github|framework/(?:wazuh|scripts)|api/(?:api|scripts|test))/'
                       r'[A-Za-z0-9_./@+-]*$')
INSTALLED_BIN = re.compile(r'/var/wazuh-manager/bin/([A-Za-z0-9_.-]+)')


class Doc:
    """One markdown file split into prose lines and fenced blocks."""

    def __init__(self, rel):
        self.rel = rel
        with open(os.path.join(REPO, rel), encoding='utf-8') as f:
            self.lines = f.read().split('\n')
        self.blocks = []  # (first body line number, info string words, body)
        self.prose = []  # (line number, text) outside fenced blocks
        fence = None
        for no, line in enumerate(self.lines, 1):
            if fence:
                char, length, start, info, body = fence
                stripped = line.strip()
                if stripped and set(stripped) == {char} and len(stripped) >= length and len(line) - len(line.lstrip()) < 4:
                    self.blocks.append((start, info, '\n'.join(body)))
                    fence = None
                else:
                    body.append(line)
                continue
            m = FENCE_OPEN.match(line)
            if m and not (m.group(2)[0] == '`' and '`' in m.group(4)):
                info = [w for w in re.split(r'[,\s]+', (m.group(3) + m.group(4)).strip().lower()) if w]
                fence = (m.group(2)[0], len(m.group(2)), no + 1, info, [])
                continue
            self.prose.append((no, line))
        if fence:
            self.blocks.append((fence[2], fence[3], '\n'.join(fence[4])))

    def links(self):
        for no, line in self.prose:
            text = INLINE_CODE.sub(lambda m: ' ' * len(m.group(0)), line)
            for m in INLINE_LINK.finditer(text):
                yield no, m.group(1)
            m = REF_DEF.match(text)
            if m:
                yield no, m.group(1)
            for m in HTML_ATTR.finditer(text):
                yield no, html.unescape(m.group(1))

    def code_spans(self):
        for no, line in self.prose:
            for m in INLINE_CODE.finditer(line):
                yield no, m.group(2).strip()


def github_ids(doc):
    """Heading ids as GitHub renders them (developer READMEs are read there)."""
    ids, seen = set(), {}
    for no, line in doc.prose:
        ids.update(HTML_ID.findall(line))
        m = HEADING.match(line)
        if not m:
            continue
        text = m.group(2)
        text = re.sub(r'!?\[([^\]]*)\]\([^)]*\)', r'\1', text)
        text = re.sub(r'<[^>]+>', '', text)
        slug = re.sub(r'[^\w\- ]', '', text.replace('`', '').lower()).replace(' ', '-')
        n = seen.get(slug, 0)
        seen[slug] = n + 1
        ids.add(slug if n == 0 else f'{slug}-{n}')
    return ids


class Checker:
    def __init__(self, book_dir, only):
        self.book_dir = book_dir
        self.only = only
        self.findings = []
        self.docs = {}
        self.book_ids = {}
        self.published = self._summary()
        self.installed_bin = self._installed_bin()
        self.tracked = set(subprocess.run(['git', '-C', REPO, 'ls-files'], capture_output=True, text=True,
                                          check=True).stdout.split('\n'))
        self.tracked_dirs = {posixpath.dirname(p) for p in self.tracked}
        for p in list(self.tracked_dirs):
            while p:
                p = posixpath.dirname(p)
                self.tracked_dirs.add(p)

    # ---- inputs -----------------------------------------------------------------------------

    def _summary(self):
        with open(os.path.join(DOCS, 'SUMMARY.md'), encoding='utf-8') as f:
            targets = re.findall(r'\]\(([^)]+\.md)\)', f.read())
        return {posixpath.normpath('docs/' + t) for t in targets}

    def _installed_bin(self):
        with open(INVENTORY, encoding='utf-8') as f:
            return {row['full_filename'].rsplit('/', 1)[1] for row in csv.DictReader(f)
                    if row['full_filename'].startswith('/var/wazuh-manager/bin/')}

    def doc(self, rel):
        if rel not in self.docs:
            self.docs[rel] = Doc(rel)
        return self.docs[rel]

    def page_ids(self, rel):
        """Heading ids of a published page, read from the built book."""
        if rel not in self.book_ids:
            out = posixpath.relpath(rel, 'docs')[:-3] + '.html'
            out = re.sub(r'(^|/)README\.html$', r'\1index.html', out)
            path = os.path.join(self.book_dir, out)
            if not os.path.isfile(path):
                sys.exit(f'check-docs: {path} missing; build the book first (docs/build.sh)')
            with open(path, encoding='utf-8') as f:
                content = f.read()
            main = content.split('<main>', 1)[-1].split('</main>', 1)[0]
            self.book_ids[rel] = set(re.findall(r'\bid="([^"]+)"', main))
        return self.book_ids[rel]

    def ids(self, rel, in_book):
        """Heading ids of `rel` as the reader of the linking page sees them."""
        return self.page_ids(rel) if in_book and rel in self.published else github_ids(self.doc(rel))

    def report(self, rel, no, check, message):
        self.findings.append((rel, no, check, message))

    # ---- checks -----------------------------------------------------------------------------

    def files(self):
        docs = sorted(p for p in self.tracked if p.startswith('docs/') and p.endswith('.md'))
        dev = sorted(p for p in self.tracked if p.endswith('.md') and p.split('/', 1)[0] in DEV_TREES
                     and not DEV_EXCLUDE.match(p))
        chosen = docs + dev
        if self.only:
            chosen = [p for p in chosen if any(p == o or p.startswith(o.rstrip('/') + '/') for o in self.only)]
        return [p for p in chosen if os.path.isfile(os.path.join(REPO, p))]

    def run(self):
        blocks = []
        for rel in self.files():
            in_book = rel.startswith('docs/')
            if in_book and rel != 'docs/SUMMARY.md' and rel not in self.published:
                self.report(rel, 1, 'unpublished', 'not listed in docs/SUMMARY.md, so never published')
            doc = self.doc(rel)
            if rel != 'docs/SUMMARY.md':
                for no, target in doc.links():
                    self.check_link(rel, in_book, no, target)
            for no, span in doc.code_spans():
                self.check_span(rel, no, span)
            for start, info, body in doc.blocks:
                blocks.extend(self.check_block(rel, start, info, body))
                for m in INSTALLED_BIN.finditer(body):
                    self.check_bin(rel, start, m.group(1))
        self.check_mermaid(blocks)
        return self.findings

    def check_link(self, rel, in_book, no, target):
        if not target or SCHEME.match(target):
            return
        if target.startswith('/'):
            self.report(rel, no, 'link-absolute', f'`{target}`: use a relative link')
            return
        path, _, anchor = target.partition('#')
        path = html.unescape(path)
        if not path:
            if anchor and anchor not in self.ids(rel, in_book):
                self.report(rel, no, 'link-anchor', f'`#{anchor}`: no such heading on this page')
            return
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(rel), path))
        if resolved.startswith('../'):
            self.report(rel, no, 'link-target', f'`{target}` leaves the repository')
            return
        if in_book and not resolved.startswith('docs/'):
            self.report(rel, no, 'link-outside-book',
                        f'`{target}`: the rendered book has no `{resolved}`; name it in backticks or link GitHub')
            return
        if in_book and path.endswith('.html'):
            source = resolved[:-5] + '.md'
            source = re.sub(r'(^|/)index\.md$', r'\1README.md', source)
            hint = f'link `{posixpath.relpath(source, posixpath.dirname(rel))}`' if os.path.isfile(
                os.path.join(REPO, source)) else 'no source page has that name either'
            self.report(rel, no, 'link-html', f'`{target}`: {hint}')
            return
        full = os.path.join(REPO, resolved)
        if not os.path.exists(full):
            self.report(rel, no, 'link-target', f'`{target}`: `{resolved}` does not exist')
            return
        if not resolved.endswith('.md'):
            return
        if in_book and resolved not in self.published:
            self.report(rel, no, 'link-unpublished', f'`{target}`: `{resolved}` is not in SUMMARY.md')
            return
        if anchor and anchor not in self.ids(resolved, in_book):
            self.report(rel, no, 'link-anchor', f'`{target}`: `{resolved}` has no heading `#{anchor}`')

    def check_span(self, rel, no, span):
        for m in INSTALLED_BIN.finditer(span):
            self.check_bin(rel, no, m.group(1))
        path = span.rstrip('/')
        if not REPO_PATH.match(span) or '*' in span or path.endswith('.') or '/.' in path:
            return
        # A developer README may name paths relative to its own module (`src/foo.cpp`).
        bases = [''] if rel.startswith('docs/') else [''] + self.ancestors(rel)
        if not any(posixpath.join(b, path) in self.tracked or posixpath.join(b, path) in self.tracked_dirs
                   for b in bases) and not self.ignored(path):
            self.report(rel, no, 'repo-path', f'`{span}` is not in the repository')

    @staticmethod
    def ignored(path):
        """Build outputs and downloads (src/build/, src/external/...) are named legitimately."""
        return subprocess.run(['git', '-C', REPO, 'check-ignore', '-q', '--no-index', path]).returncode == 0

    @staticmethod
    def ancestors(rel):
        out, d = [], posixpath.dirname(rel)
        while d:
            out.append(d)
            d = posixpath.dirname(d)
        return out

    def check_bin(self, rel, no, name):
        name = name.rstrip('.')
        if name and name not in self.installed_bin:
            self.report(rel, no, 'installed-bin',
                        f'`/var/wazuh-manager/bin/{name}` is not installed (manager_base.csv)')

    def check_block(self, rel, start, info, body):
        lang = info[0] if info else ''
        if 'fragment' in info or not body.strip():
            return []
        try:
            if lang == 'json':
                json.loads(body)
            elif lang in ('yaml', 'yml'):
                list(yaml.safe_load_all(body))
            elif lang == 'xml':
                ET.fromstring(f'<fragment-root>{re.sub(r"<[?]xml[^>]*[?]>", "", body)}</fragment-root>')
            elif lang == 'mermaid':
                return [(rel, start, body)]
        except (ValueError, yaml.YAMLError, ET.ParseError) as e:
            message = str(e).split('\n')[0]
            self.report(rel, start, f'block-{"yaml" if lang == "yml" else lang}',
                        f'{message} (mark an intentional fragment with ```{lang},fragment)')
        return []

    @staticmethod
    def node_modules():
        lock = os.path.join(DOCS, 'tools', 'package-lock.json')
        stamp = os.path.join(NODE_DIR, 'package-lock.json')
        with open(lock, encoding='utf-8') as f:
            wanted = f.read()
        if not os.path.isfile(stamp) or open(stamp, encoding='utf-8').read() != wanted:
            os.makedirs(NODE_DIR, exist_ok=True)
            for name in ('package.json', 'package-lock.json'):
                with open(os.path.join(DOCS, 'tools', name), encoding='utf-8') as src, \
                        open(os.path.join(NODE_DIR, name), 'w', encoding='utf-8') as dst:
                    dst.write(src.read())
            proc = subprocess.run(['npm', 'ci', '--silent', '--no-audit', '--no-fund', '--prefix', NODE_DIR],
                                  capture_output=True, text=True)
            if proc.returncode != 0:
                os.remove(stamp)
                sys.exit(f'check-docs: npm ci into {NODE_DIR} failed:\n{proc.stderr}')
        return os.path.join(NODE_DIR, 'node_modules')

    def check_mermaid(self, blocks):
        if not blocks:
            return
        env = dict(os.environ, NODE_PATH=self.node_modules())
        proc = subprocess.run(['node', MERMAID_CHECKER, os.path.join(DOCS, 'mermaid.min.js')],
                              input=json.dumps([b[2] for b in blocks]), capture_output=True, text=True, env=env)
        if proc.returncode != 0:
            sys.exit(f'check-docs: {MERMAID_CHECKER} failed:\n{proc.stderr}')
        for (rel, start, _), error in zip(blocks, json.loads(proc.stdout)):
            if error:
                self.report(rel, start, 'block-mermaid', error)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('paths', nargs='*', help='limit to these files or directories (repository-relative)')
    parser.add_argument('--book', default=os.path.join(DOCS, 'book'), help='built book directory')
    parser.add_argument('--list-checks', action='store_true', help='print the checks and exit')
    args = parser.parse_args()
    if args.list_checks:
        for name, what in CHECKS.items():
            print(f'{name:18} {what}')
        return 0
    only = [posixpath.normpath(os.path.relpath(os.path.abspath(p), REPO)) if os.path.exists(p) else p
            for p in args.paths]
    findings = Checker(args.book, only).run()
    for rel, no, check, message in sorted(findings):
        print(f'{rel}:{no}: [{check}] {message}')
    if findings:
        counts = {}
        for f in findings:
            counts[f[2]] = counts.get(f[2], 0) + 1
        print(f'check-docs: {len(findings)} finding(s): ' +
              ', '.join(f'{k} {v}' for k, v in sorted(counts.items())), file=sys.stderr)
        return 1
    print('check-docs: OK', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
