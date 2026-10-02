#!/usr/bin/env python3
"""mdBook preprocessor: make links to README.md chapters resolve in the rendered book.

mdBook renders a chapter named README.md as index.html but rewrites a link to it as README.html,
which does not exist. Sources link to README.md so they also work when browsed on GitHub; this
rewrites every such link whose target is an in-book file to index.md, which mdBook then renders
as index.html. Links outside the book, absolute URLs and fenced code blocks are left untouched.
"""

import json
import os
import posixpath
import re
import sys

BOOK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Inline links `](target)` and reference definitions `[id]: target`.
INLINE = re.compile(r'(\]\()([^)\s#]*README\.md)((?:#[^)\s]*)?(?:\s+"[^"]*")?\))')
REFDEF = re.compile(r'^(\s{0,3}\[[^\]]+\]:\s+)([^\s#]*README\.md)(#\S*)?', re.MULTILINE)
FENCE = re.compile(r'^\s*(```|~~~)')


def rewrite_target(chapter_dir, target):
    if re.match(r'^[a-z][a-z0-9+.-]*:', target, re.IGNORECASE) or target.startswith('/'):
        return target
    resolved = posixpath.normpath(posixpath.join(chapter_dir, target))
    if resolved.startswith('../') or not os.path.isfile(os.path.join(BOOK_ROOT, resolved)):
        return target
    return target[: -len('README.md')] + 'index.md'


def rewrite(content, chapter_path):
    chapter_dir = posixpath.dirname(chapter_path)
    out, block, fenced = [], [], False

    def flush():
        text = ''.join(block)
        text = INLINE.sub(lambda m: m.group(1) + rewrite_target(chapter_dir, m.group(2)) + m.group(3), text)
        text = REFDEF.sub(lambda m: m.group(1) + rewrite_target(chapter_dir, m.group(2)) + (m.group(3) or ''), text)
        out.append(text)
        block.clear()

    for line in content.splitlines(keepends=True):
        if FENCE.match(line):
            if not fenced:
                flush()
            fenced = not fenced
            out.append(line)
        elif fenced:
            out.append(line)
        else:
            block.append(line)
    flush()
    return ''.join(out)


def walk(items):
    for item in items:
        chapter = item.get('Chapter') if isinstance(item, dict) else None
        if not chapter:
            continue
        if chapter.get('path'):
            chapter['content'] = rewrite(chapter['content'], chapter['path'].replace(os.sep, '/'))
        walk(chapter.get('sub_items', []))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'supports':
        sys.exit(0)
    _, book = json.load(sys.stdin)
    walk(book.get('sections', book.get('items', [])))
    json.dump(book, sys.stdout)


if __name__ == '__main__':
    main()
