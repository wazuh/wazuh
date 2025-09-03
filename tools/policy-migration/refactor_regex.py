#!/usr/bin/env python3
import sys
import re
from typing import List, Tuple, Set, Optional


def left_to_right_swap_dots(pattern: str, quote_char: Optional[str]) -> str:
    """Swap '.' and escaped dot inside a regex pattern, quote-aware.

    - Single-quoted or unquoted lines: swap '.' <-> '\\.'
    - Double-quoted lines: swap '.' <-> '\\\\.' (two backslashes before dot)

    osregex: '.' means literal dot; escaped dot means any char.
    PCRE2: '.' means any char; escaped dot means literal dot.
    """
    out: List[str] = []
    i = 0
    n = len(pattern)
    is_double = (quote_char == '"')
    while i < n:
        if not is_double and i + 1 < n and pattern[i] == '\\' and pattern[i + 1] == '.':
            out.append('.')
            i += 2
            continue
        if is_double and i + 2 < n and pattern[i] == '\\' and pattern[i + 1] == '\\' and pattern[i + 2] == '.':
            out.append('.')
            i += 3
            continue
        if pattern[i] == '.':
            out.append('\\\\.' if is_double else '\\.')
            i += 1
            continue
        out.append(pattern[i])
        i += 1
    return ''.join(out)


def swap_in_rn_tokens_dots(text: str, quote_char: Optional[str]) -> Tuple[str, bool]:
    """Apply dot-swap only within r:/n:/!r:/!n: tokens left-to-right (quote-aware).
    Token ends at ' && ' or ' compare '. Returns (updated_text, changed_flag).
    """
    i = 0
    s = text
    out: List[str] = []
    n = len(s)

    def read_until_boundary(k: int) -> Tuple[str, int]:
        j = k
        while j < n and not (s.startswith(' && ', j) or s.startswith(' compare ', j)):
            j += 1
        return s[k:j], j

    while i < n:
        # Handle !r: / !n:
        if i + 2 < n and s[i] == '!' and s[i + 1] in ('r', 'n') and s[i + 2] == ':':
            out.append(s[i:i+3])
            i += 3
            payload, next_i = read_until_boundary(i)
            out.append(left_to_right_swap_dots(payload, quote_char))
            i = next_i
            continue
        # Handle r: / n:
        if i + 1 < n and s[i] in ('r', 'n') and s[i + 1] == ':':
            out.append(s[i:i+2])
            i += 2
            payload, next_i = read_until_boundary(i)
            out.append(left_to_right_swap_dots(payload, quote_char))
            i = next_i
            continue
        out.append(s[i])
        i += 1

    updated = ''.join(out)
    return updated, (updated != text)


def update_yaml_rules_dots(yml_lines: List[str], ids: Set[str]) -> Tuple[List[str], int]:
    """Under matching IDs, swap '.' and '\\.' inside r:/n:/!r:/!n: tokens.
    Returns (updated_lines, edited_rule_count).
    """
    new_lines: List[str] = []
    edited_count: int = 0

    in_target_check = False
    check_indent_len = None
    in_rules = False
    rules_indent_len = None

    id_line_re = re.compile(r'^(\s*)-\s+id:\s+(\d+)\s*$')
    rules_key_re = re.compile(r'^(\s*)rules:\s*$')
    list_item_re = re.compile(r'^(\s*)-\s')

    for line in yml_lines:
        # Detect start of a new check by id
        m_id = id_line_re.match(line)
        if m_id:
            check_indent_len = len(m_id.group(1))
            in_target_check = m_id.group(2) in ids
            in_rules = False
            rules_indent_len = None
            new_lines.append(line)
            continue

        # Detect rules: key within a target check
        if in_target_check:
            m_rules = rules_key_re.match(line)
            if m_rules:
                in_rules = True
                rules_indent_len = len(m_rules.group(1))
                new_lines.append(line)
                continue

            if in_rules:
                # End of rules block if dedent to rules indent or less, or new id starts
                leading_spaces = len(line) - len(line.lstrip(' '))
                if leading_spaces <= (rules_indent_len or 0) or id_line_re.match(line):
                    in_rules = False
                    rules_indent_len = None
                    # fall-through to append line normally
                else:
                    # Process only YAML list items under rules
                    if list_item_re.match(line):
                        quote_char = _detect_line_quote_char(line)
                        transformed, changed = swap_in_rn_tokens_dots(line, quote_char)
                        if changed:
                            edited_count += 1
                        new_lines.append(transformed)
                        continue

        new_lines.append(line)

    return new_lines, edited_count


def _has_dot_in_rn_tokens(text: str) -> bool:
    """Return True if there is any '.' or '\\.' inside r:/n:/!r:/!n: token payloads.
    Token payload ends at ' && ' or ' compare '.
    """
    i = 0
    s = text
    n = len(s)

    def read_until_boundary(k: int) -> Tuple[str, int]:
        j = k
        while j < n and not (s.startswith(' && ', j) or s.startswith(' compare ', j)):
            j += 1
        return s[k:j], j

    while i < n:
        # !r: / !n:
        if i + 2 < n and s[i] == '!' and s[i + 1] in ('r', 'n') and s[i + 2] == ':':
            i += 3
            payload, i = read_until_boundary(i)
            if '.' in payload:
                return True
            continue
        # r: / n:
        if i + 1 < n and s[i] in ('r', 'n') and s[i + 1] == ':':
            i += 2
            payload, i = read_until_boundary(i)
            if '.' in payload:
                return True
            continue
        i += 1
    return False


def find_ids_with_dot_patterns(yml_lines: List[str]) -> Set[str]:
    """Scan YAML and return IDs whose rules contain r:/n:/!r:/!n: with '.' or '\\.'."""
    ids_with_dots: Set[str] = set()

    current_id: str = ''
    in_rules = False
    rules_indent_len = None

    id_line_re = re.compile(r'^(\s*)-\s+id:\s+(\d+)\s*$')
    rules_key_re = re.compile(r'^(\s*)rules:\s*$')
    list_item_re = re.compile(r'^(\s*)-\s')

    for line in yml_lines:
        m_id = id_line_re.match(line)
        if m_id:
            current_id = m_id.group(2)
            in_rules = False
            rules_indent_len = None
            continue

        m_rules = rules_key_re.match(line)
        if m_rules:
            in_rules = True
            rules_indent_len = len(m_rules.group(1))
            continue

        if in_rules:
            leading_spaces = len(line) - len(line.lstrip(' '))
            if leading_spaces <= (rules_indent_len or 0) or id_line_re.match(line):
                in_rules = False
                rules_indent_len = None
                continue
            if list_item_re.match(line) and _has_dot_in_rn_tokens(line):
                if current_id:
                    ids_with_dots.add(current_id)

    return ids_with_dots


def left_to_right_escape_unescaped_brackets(pattern: str, quote_char: Optional[str]) -> str:
    """Escape unescaped '[' and ']' according to line quote style.
    - Double-quoted line (quote_char == '"'): add two backslashes before bracket
    - Single-quoted or unquoted: add one backslash before bracket
    Leaves already escaped brackets as-is.
    """
    out: List[str] = []
    i = 0
    n = len(pattern)

    def count_backslashes_before(index: int) -> int:
        cnt = 0
        k = index - 1
        while k >= 0 and pattern[k] == '\\':
            cnt += 1
            k -= 1
        return cnt

    while i < n:
        ch = pattern[i]
        if ch in ('[', ']'):
            cnt = count_backslashes_before(i)
            if quote_char == '"':
                # Consider escaped only if there are at least two preceding backslashes and the count is even (2, 4, ...)
                escaped = (cnt >= 2 and (cnt % 2 == 0))
                if not escaped:
                    out.append('\\\\')
                    out.append(ch)
                    i += 1
                    continue
            else:
                # Single-quoted or unquoted: escaped if odd number of preceding backslashes
                escaped = (cnt % 2 == 1)
                if not escaped:
                    out.append('\\')
                    out.append(ch)
                    i += 1
                    continue
        out.append(ch)
        i += 1
    return ''.join(out)


def _has_unescaped_brackets(payload: str, quote_char: Optional[str]) -> bool:
    """Return True if payload contains an unescaped '[' or ']' based on quote style.
    - Double-quoted: needs escaping unless at least two consecutive backslashes (even count >= 2)
    - Single/unquoted: needs escaping if preceding backslashes count is even
    """
    n = len(payload)
    i = 0
    while i < n:
        ch = payload[i]
        if ch in ('[', ']'):
            # Count preceding backslashes
            cnt = 0
            k = i - 1
            while k >= 0 and payload[k] == '\\':
                cnt += 1
                k -= 1
            if quote_char == '"':
                if not (cnt >= 2 and (cnt % 2 == 0)):
                    return True
            else:
                if cnt % 2 == 0:
                    return True
        i += 1
    return False


def _has_unescaped_brackets_in_rn_tokens(text: str, quote_char: Optional[str]) -> bool:
    """Return True if any r:/n:/!r:/!n: token payload contains unescaped '[' or ']' (quote-aware)."""
    i = 0
    s = text
    n = len(s)

    def read_until_boundary(k: int) -> Tuple[str, int]:
        j = k
        while j < n and not (s.startswith(' && ', j) or s.startswith(' compare ', j)):
            j += 1
        return s[k:j], j

    while i < n:
        if i + 2 < n and s[i] == '!' and s[i + 1] in ('r', 'n') and s[i + 2] == ':':
            i += 3
            payload, i = read_until_boundary(i)
            if _has_unescaped_brackets(payload, quote_char):
                return True
            continue
        if i + 1 < n and s[i] in ('r', 'n') and s[i + 1] == ':':
            i += 2
            payload, i = read_until_boundary(i)
            if _has_unescaped_brackets(payload, quote_char):
                return True
            continue
        i += 1
    return False


def swap_in_rn_tokens_brackets(text: str, quote_char: Optional[str]) -> Tuple[str, bool]:
    """Escape unescaped '[' and ']' only within r:/n:/!r:/!n: tokens.
    Token ends at ' && ' or ' compare '. Returns (updated_text, changed_flag).
    """
    i = 0
    s = text
    out: List[str] = []
    n = len(s)

    def read_until_boundary(k: int) -> Tuple[str, int]:
        j = k
        while j < n and not (s.startswith(' && ', j) or s.startswith(' compare ', j)):
            j += 1
        return s[k:j], j

    while i < n:
        if i + 2 < n and s[i] == '!' and s[i + 1] in ('r', 'n') and s[i + 2] == ':':
            out.append(s[i:i+3])
            i += 3
            payload, next_i = read_until_boundary(i)
            new_payload = left_to_right_escape_unescaped_brackets(payload, quote_char)
            out.append(new_payload)
            i = next_i
            continue
        if i + 1 < n and s[i] in ('r', 'n') and s[i + 1] == ':':
            out.append(s[i:i+2])
            i += 2
            payload, next_i = read_until_boundary(i)
            new_payload = left_to_right_escape_unescaped_brackets(payload, quote_char)
            out.append(new_payload)
            i = next_i
            continue
        out.append(s[i])
        i += 1

    updated = ''.join(out)
    return updated, (updated != text)


def find_ids_with_unescaped_brackets(yml_lines: List[str]) -> Set[str]:
    """Scan YAML and return IDs whose rules contain unescaped '[' or ']' inside r:/n:/!r:/!n: tokens."""
    ids_with_issue: Set[str] = set()

    current_id: str = ''
    in_rules = False
    rules_indent_len = None

    id_line_re = re.compile(r'^(\s*)-\s+id:\s+(\d+)\s*$')
    rules_key_re = re.compile(r'^(\s*)rules:\s*$')
    list_item_re = re.compile(r'^(\s*)-\s')

    for line in yml_lines:
        m_id = id_line_re.match(line)
        if m_id:
            current_id = m_id.group(2)
            in_rules = False
            rules_indent_len = None
            continue

        m_rules = rules_key_re.match(line)
        if m_rules:
            in_rules = True
            rules_indent_len = len(m_rules.group(1))
            continue

        if in_rules:
            leading_spaces = len(line) - len(line.lstrip(' '))
            if leading_spaces <= (rules_indent_len or 0) or id_line_re.match(line):
                in_rules = False
                rules_indent_len = None
                continue
            if list_item_re.match(line):
                quote_char = _detect_line_quote_char(line)
                if _has_unescaped_brackets_in_rn_tokens(line, quote_char):
                    if current_id:
                        ids_with_issue.add(current_id)

    return ids_with_issue


def update_yaml_rules_brackets(yml_lines: List[str], ids: Set[str]) -> Tuple[List[str], int]:
    """Under matching IDs, escape unescaped '[' and ']' inside r:/n:/!r:/!n: tokens.
    Returns (updated_lines, edited_rule_count).
    """
    new_lines: List[str] = []
    edited_count: int = 0

    in_target_check = False
    in_rules = False
    rules_indent_len = None

    id_line_re = re.compile(r'^(\s*)-\s+id:\s+(\d+)\s*$')
    rules_key_re = re.compile(r'^(\s*)rules:\s*$')
    list_item_re = re.compile(r'^(\s*)-\s')

    for line in yml_lines:
        m_id = id_line_re.match(line)
        if m_id:
            in_target_check = m_id.group(2) in ids
            in_rules = False
            rules_indent_len = None
            new_lines.append(line)
            continue

        if in_target_check:
            m_rules = rules_key_re.match(line)
            if m_rules:
                in_rules = True
                rules_indent_len = len(m_rules.group(1))
                new_lines.append(line)
                continue

            if in_rules:
                leading_spaces = len(line) - len(line.lstrip(' '))
                if leading_spaces <= (rules_indent_len or 0) or id_line_re.match(line):
                    in_rules = False
                    rules_indent_len = None
                else:
                    if list_item_re.match(line):
                        quote_char = _detect_line_quote_char(line)
                        transformed, changed = swap_in_rn_tokens_brackets(line, quote_char)
                        if changed:
                            edited_count += 1
                        new_lines.append(transformed)
                        continue

        new_lines.append(line)

    return new_lines, edited_count


def _detect_line_quote_char(line: str) -> Optional[str]:
    """Detect if the YAML list item value is single-quoted or double-quoted.
    Returns '"', "'", or None if not quoted.
    """
    m = re.match(r'^\s*-\s*([\'\"])', line)
    if m:
        return m.group(1)
    return None


def _has_w(payload: str, quote_char: Optional[str]) -> bool:
    """Return True if payload contains a \w (or \\w in double-quoted lines) token anywhere."""
    i = 0
    n = len(payload)
    is_double = (quote_char == '"')
    while i < n:
        if not is_double and payload[i] == '\\' and i + 1 < n and payload[i + 1] == 'w':
            return True
        if is_double and payload[i] == '\\' and i + 2 < n and payload[i + 1] == '\\' and payload[i + 2] == 'w':
            return True
        i += 1
    return False


def _has_w_in_rn_tokens(text: str, quote_char: Optional[str]) -> bool:
    """Return True if any r:/n:/!r:/!n: payload contains a \w token needing expansion,
    considering the line's quote style.
    """
    i = 0
    s = text
    n = len(s)

    def read_until_boundary(k: int) -> Tuple[str, int]:
        j = k
        while j < n and not (s.startswith(' && ', j) or s.startswith(' compare ', j)):
            j += 1
        return s[k:j], j

    while i < n:
        if i + 2 < n and s[i] == '!' and s[i + 1] in ('r', 'n') and s[i + 2] == ':':
            i += 3
            payload, i = read_until_boundary(i)
            if _has_w(payload, quote_char):
                return True
            continue
        if i + 1 < n and s[i] in ('r', 'n') and s[i + 1] == ':':
            i += 2
            payload, i = read_until_boundary(i)
            if _has_w(payload, quote_char):
                return True
            continue
        i += 1
    return False


def left_to_right_expand_word_chars(pattern: str, quote_char: Optional[str]) -> str:
    """Replace all \w with [\w@-] (quote-aware).
    - Double-quoted lines: replace \\w with [\\w@-]
    - Single/unquoted lines: replace \w with [\w@-]
    """
    out: List[str] = []
    i = 0
    n = len(pattern)
    is_double = (quote_char == '"')
    while i < n:
        if not is_double and pattern[i] == '\\' and i + 1 < n and pattern[i + 1] == 'w':
            out.append('[\\w@-]')
            i += 2
            continue
        if is_double and pattern[i] == '\\' and i + 2 < n and pattern[i + 1] == '\\' and pattern[i + 2] == 'w':
            out.append('[\\\\w@-]')
            i += 3
            continue
        out.append(pattern[i])
        i += 1
    return ''.join(out)


def swap_in_rn_tokens_words(text: str, quote_char: Optional[str]) -> Tuple[str, bool]:
    """Expand \\w tokens only within r:/n:/!r:/!n: payloads.
    Token ends at ' && ' or ' compare '. Returns (updated_text, changed_flag).
    """
    i = 0
    s = text
    out: List[str] = []
    n = len(s)

    def read_until_boundary(k: int) -> Tuple[str, int]:
        j = k
        while j < n and not (s.startswith(' && ', j) or s.startswith(' compare ', j)):
            j += 1
        return s[k:j], j

    while i < n:
        if i + 2 < n and s[i] == '!' and s[i + 1] in ('r', 'n') and s[i + 2] == ':':
            out.append(s[i:i+3])
            i += 3
            payload, next_i = read_until_boundary(i)
            new_payload = left_to_right_expand_word_chars(payload, quote_char)
            out.append(new_payload)
            i = next_i
            continue
        if i + 1 < n and s[i] in ('r', 'n') and s[i + 1] == ':':
            out.append(s[i:i+2])
            i += 2
            payload, next_i = read_until_boundary(i)
            new_payload = left_to_right_expand_word_chars(payload, quote_char)
            out.append(new_payload)
            i = next_i
            continue
        out.append(s[i])
        i += 1

    updated = ''.join(out)
    return updated, (updated != text)


def find_ids_with_w_tokens(yml_lines: List[str]) -> Set[str]:
    """Scan YAML and return IDs whose rules contain \\w tokens needing expansion inside r:/n:/!r:/!n:."""
    ids_with_issue: Set[str] = set()

    current_id: str = ''
    in_rules = False
    rules_indent_len = None

    id_line_re = re.compile(r'^(\s*)-\s+id:\s+(\d+)\s*$')
    rules_key_re = re.compile(r'^(\s*)rules:\s*$')
    list_item_re = re.compile(r'^(\s*)-\s')

    for line in yml_lines:
        m_id = id_line_re.match(line)
        if m_id:
            current_id = m_id.group(2)
            in_rules = False
            rules_indent_len = None
            continue

        m_rules = rules_key_re.match(line)
        if m_rules:
            in_rules = True
            rules_indent_len = len(m_rules.group(1))
            continue

        if in_rules:
            leading_spaces = len(line) - len(line.lstrip(' '))
            if leading_spaces <= (rules_indent_len or 0) or id_line_re.match(line):
                in_rules = False
                rules_indent_len = None
                continue
            if list_item_re.match(line):
                quote_char = _detect_line_quote_char(line)
                # Extract tokens and check payloads
                if _has_w_in_rn_tokens(line, quote_char):
                    if current_id:
                        ids_with_issue.add(current_id)

    return ids_with_issue


def update_yaml_rules_words(yml_lines: List[str], ids: Set[str]) -> Tuple[List[str], int]:
    """Under matching IDs, expand \\w to [\\w@-] (or \\w@- inside classes) within r:/n:/!r:/!n: tokens.
    Returns (updated_lines, edited_rule_count).
    """
    new_lines: List[str] = []
    edited_count: int = 0

    in_target_check = False
    in_rules = False
    rules_indent_len = None

    id_line_re = re.compile(r'^(\s*)-\s+id:\s+(\d+)\s*$')
    rules_key_re = re.compile(r'^(\s*)rules:\s*$')
    list_item_re = re.compile(r'^(\s*)-\s')

    for line in yml_lines:
        m_id = id_line_re.match(line)
        if m_id:
            in_target_check = m_id.group(2) in ids
            in_rules = False
            rules_indent_len = None
            new_lines.append(line)
            continue

        if in_target_check:
            m_rules = rules_key_re.match(line)
            if m_rules:
                in_rules = True
                rules_indent_len = len(m_rules.group(1))
                new_lines.append(line)
                continue

            if in_rules:
                leading_spaces = len(line) - len(line.lstrip(' '))
                if leading_spaces <= (rules_indent_len or 0) or re.match(r'^(\s*)-\s+id:\s+(\d+)\s*$', line):
                    in_rules = False
                    rules_indent_len = None
                else:
                    if list_item_re.match(line):
                        quote_char = _detect_line_quote_char(line)
                        transformed, changed = swap_in_rn_tokens_words(line, quote_char)
                        if changed:
                            edited_count += 1
                        new_lines.append(transformed)
                        continue

        new_lines.append(line)

    return new_lines, edited_count


# ========= QUANTIFIERS (literal * and + handling) =========

_QUANTIFIER_PREV_ALLOWED = set(['w', 'd', 's', 't', 'p', 'W', 'D', 'S', '.'])


def _escape_literal_quantifiers(payload: str, quote_char: Optional[str]) -> str:
    """Escape literal '*' and '+' that old engine treated as literals.
    Old engine: '*' or '+' is a quantifier only if preceded by one of: \\w, \\d, \\s, \\t, \\p, \\W, \\D, \\S, or \\. .
    Otherwise it's literal and must be escaped for PCRE2.
    Quote-aware escaping: double-quoted -> prefix with '\\', single/unquoted -> prefix with '\'.
    """
    out: List[str] = []
    i = 0
    n = len(payload)
    is_double = (quote_char == '"')

    def prev_token_allows_quantifier(idx: int) -> bool:
        # Check immediate previous escaped token: \\x (single/unquoted) or \\\\x (double-quoted), where x in allowed set.
        if idx <= 0:
            return False
        if quote_char == '"':
            # Expect two backslashes before token char
            if idx - 3 >= 0 and payload[idx - 3] == '\\' and payload[idx - 2] == '\\' and payload[idx - 1] in _QUANTIFIER_PREV_ALLOWED:
                return True
        else:
            if idx - 2 >= 0 and payload[idx - 2] == '\\' and payload[idx - 1] in _QUANTIFIER_PREV_ALLOWED:
                return True
        return False

    while i < n:
        ch = payload[i]
        if ch in ('*', '+'):
            if prev_token_allows_quantifier(i):
                out.append(ch)
            else:
                out.append('\\\\' + ch if is_double else '\\' + ch)
            i += 1
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def _has_literal_quants_in_payload(payload: str, quote_char: Optional[str]) -> bool:
    i = 0
    n = len(payload)
    def prev_token_allows_quantifier(idx: int) -> bool:
        if idx <= 0:
            return False
        if quote_char == '"':
            if idx - 3 >= 0 and payload[idx - 3] == '\\' and payload[idx - 2] == '\\' and payload[idx - 1] in _QUANTIFIER_PREV_ALLOWED:
                return True
        else:
            if idx - 2 >= 0 and payload[idx - 2] == '\\' and payload[idx - 1] in _QUANTIFIER_PREV_ALLOWED:
                return True
        return False
    while i < n:
        if payload[i] in ('*', '+') and not prev_token_allows_quantifier(i):
            return True
        i += 1
    return False


def _has_literal_quants_in_rn_tokens(text: str, quote_char: Optional[str]) -> bool:
    i = 0
    s = text
    n = len(s)
    def read_until_boundary(k: int) -> Tuple[str, int]:
        j = k
        while j < n and not (s.startswith(' && ', j) or s.startswith(' compare ', j)):
            j += 1
        return s[k:j], j
    while i < n:
        if i + 2 < n and s[i] == '!' and s[i + 1] in ('r', 'n') and s[i + 2] == ':':
            i += 3
            payload, i = read_until_boundary(i)
            if _has_literal_quants_in_payload(payload, quote_char):
                return True
            continue
        if i + 1 < n and s[i] in ('r', 'n') and s[i + 1] == ':':
            i += 2
            payload, i = read_until_boundary(i)
            if _has_literal_quants_in_payload(payload, quote_char):
                return True
            continue
        i += 1
    return False


def swap_in_rn_tokens_quants(text: str, quote_char: Optional[str]) -> Tuple[str, bool]:
    i = 0
    s = text
    out: List[str] = []
    n = len(s)
    def read_until_boundary(k: int) -> Tuple[str, int]:
        j = k
        while j < n and not (s.startswith(' && ', j) or s.startswith(' compare ', j)):
            j += 1
        return s[k:j], j
    while i < n:
        if i + 2 < n and s[i] == '!' and s[i + 1] in ('r', 'n') and s[i + 2] == ':':
            out.append(s[i:i+3])
            i += 3
            payload, next_i = read_until_boundary(i)
            out.append(_escape_literal_quantifiers(payload, quote_char))
            i = next_i
            continue
        if i + 1 < n and s[i] in ('r', 'n') and s[i + 1] == ':':
            out.append(s[i:i+2])
            i += 2
            payload, next_i = read_until_boundary(i)
            out.append(_escape_literal_quantifiers(payload, quote_char))
            i = next_i
            continue
        out.append(s[i])
        i += 1
    updated = ''.join(out)
    return updated, (updated != text)


def find_ids_with_literal_quants(yml_lines: List[str]) -> Set[str]:
    ids_with_issue: Set[str] = set()
    current_id: str = ''
    in_rules = False
    rules_indent_len = None
    id_line_re = re.compile(r'^(\s*)-\s+id:\s+(\d+)\s*$')
    rules_key_re = re.compile(r'^(\s*)rules:\s*$')
    list_item_re = re.compile(r'^(\s*)-\s')
    for line in yml_lines:
        m_id = id_line_re.match(line)
        if m_id:
            current_id = m_id.group(2)
            in_rules = False
            rules_indent_len = None
            continue
        m_rules = rules_key_re.match(line)
        if m_rules:
            in_rules = True
            rules_indent_len = len(m_rules.group(1))
            continue
        if in_rules:
            leading_spaces = len(line) - len(line.lstrip(' '))
            if leading_spaces <= (rules_indent_len or 0) or id_line_re.match(line):
                in_rules = False
                rules_indent_len = None
                continue
            if list_item_re.match(line):
                quote_char = _detect_line_quote_char(line)
                if _has_literal_quants_in_rn_tokens(line, quote_char):
                    if current_id:
                        ids_with_issue.add(current_id)
    return ids_with_issue


def update_yaml_rules_quants(yml_lines: List[str], ids: Set[str]) -> Tuple[List[str], int]:
    new_lines: List[str] = []
    edited_count: int = 0
    in_target_check = False
    in_rules = False
    rules_indent_len = None
    id_line_re = re.compile(r'^(\s*)-\s+id:\s+(\d+)\s*$')
    rules_key_re = re.compile(r'^(\s*)rules:\s*$')
    list_item_re = re.compile(r'^(\s*)-\s')
    for line in yml_lines:
        m_id = id_line_re.match(line)
        if m_id:
            in_target_check = m_id.group(2) in ids
            in_rules = False
            rules_indent_len = None
            new_lines.append(line)
            continue
        if in_target_check:
            m_rules = rules_key_re.match(line)
            if m_rules:
                in_rules = True
                rules_indent_len = len(m_rules.group(1))
                new_lines.append(line)
                continue
            if in_rules:
                leading_spaces = len(line) - len(line.lstrip(' '))
                if leading_spaces <= (rules_indent_len or 0) or id_line_re.match(line):
                    in_rules = False
                    rules_indent_len = None
                else:
                    if list_item_re.match(line):
                        quote_char = _detect_line_quote_char(line)
                        transformed, changed = swap_in_rn_tokens_quants(line, quote_char)
                        if changed:
                            edited_count += 1
                        new_lines.append(transformed)
                        continue
        new_lines.append(line)
    return new_lines, edited_count

def main() -> None:
    # CLI: python refactor_regex.py <policy.yml> (--dots | --brackets | --words | --quants | --help)
    # Help can be requested with --help or -h at any time
    if any(arg in ('--help', '-h') for arg in sys.argv[1:]):
        print('Usage: python refactor_regex.py <policy.yml> (--dots | --brackets | --words | --quants)')
        print('')
        print('Modes:')
        print('  --quants   Escape literal * and + in r:/n:/!r:/!n: payloads unless they follow an escaped primitive')
        print('             (\\w, \\d, \\s, \\t, \\p, \\W, \\D, \\S, \\.) respecting quote style.')
        print('  --brackets Escape unescaped [ and ] inside r:/n:/!r:/!n: payloads (quote-aware).')
        print('  --words    Expand \\w to [\\w@-] outside classes and \\w@- inside classes (quote-aware).')
        print("  --dots     Swap '.' and escaped dot inside r:/n:/!r:/!n: payloads (quote-aware).")
        print('')
        print('Suggested order to minimize interference: --quants -> --brackets -> --words -> --dots')
        sys.exit(0)

    if len(sys.argv) < 3:
        print('Usage: python refactor_regex.py <policy.yml> (--dots | --brackets | --words | --quants)')
        sys.exit(1)

    dots_mode = any(arg == '--dots' for arg in sys.argv[1:])
    brackets_mode = any(arg == '--brackets' for arg in sys.argv[1:])
    words_mode = any(arg == '--words' for arg in sys.argv[1:])
    quants_mode = any(arg == '--quants' for arg in sys.argv[1:])
    non_flag_args = [a for a in sys.argv[1:] if not a.startswith('-')]

    modes_selected = int(dots_mode) + int(brackets_mode) + int(words_mode) + int(quants_mode)
    if not non_flag_args or modes_selected != 1:
        # Either no file provided, or not exactly one mode provided
        print('Usage: python refactor_regex.py <policy.yml> (--dots | --brackets | --words | --quants)')
        sys.exit(1)

    policy_yml = non_flag_args[0]

    try:
        with open(policy_yml, 'r', encoding='utf-8', newline='') as f:
            yml_lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: File '{policy_yml}' not found.")
        sys.exit(1)

    if words_mode:
        # Stage 1: Detect IDs with \\w tokens needing expansion
        ids = find_ids_with_w_tokens(yml_lines)
        if not ids:
            print('No IDs found with \\w tokens needing expansion in r:/n:/!r:/!n:. Nothing to change.')
            return

        print(f"Detected IDs with \\w tokens: {', '.join(sorted(ids))}")

        # Confirm before applying changes
        try:
            answer = input('Proceed to expand \\w to [\\w@-]? [y/N]: ').strip().lower()
        except EOFError:
            answer = ''
        if answer not in ('y', 'yes'):
            print('Aborted. No changes applied.')
            return

        # Stage 2: Apply changes
        updated_lines, edited_count = update_yaml_rules_words(yml_lines, ids)

        if updated_lines == yml_lines:
            print('No changes made. Matching IDs may have no expandable \\w tokens.')
            return

        with open(policy_yml, 'w', encoding='utf-8', newline='') as f:
            f.writelines(updated_lines)

        print(f"Updated '{policy_yml}' for IDs: {', '.join(sorted(ids))}. Edited rules: {edited_count}.")
        return

    if brackets_mode:
        # Stage 1: Detect IDs with unescaped '[' or ']' inside r:/n:/!r:/!n: token payloads
        ids = find_ids_with_unescaped_brackets(yml_lines)
        if not ids:
            print("No IDs found with unescaped '[' or ']' in r:/n:/!r:/!n: tokens. Nothing to change.")
            return

        print(f"Detected IDs with unescaped brackets: {', '.join(sorted(ids))}")

        # Confirm before applying changes
        try:
            answer = input('Proceed to escape brackets in these IDs? [y/N]: ').strip().lower()
        except EOFError:
            answer = ''
        if answer not in ('y', 'yes'):
            print('Aborted. No changes applied.')
            return

        # Stage 2: Apply changes
        updated_lines, edited_count = update_yaml_rules_brackets(yml_lines, ids)

        if updated_lines == yml_lines:
            print('No changes made. Matching IDs may have no escapable brackets.')
            return

        with open(policy_yml, 'w', encoding='utf-8', newline='') as f:
            f.writelines(updated_lines)

        print(f"Updated '{policy_yml}' for IDs: {', '.join(sorted(ids))}. Edited rules: {edited_count}.")
        return

    if quants_mode:
        # Stage 1: Detect IDs with literal '*' or '+' that need escaping
        ids = find_ids_with_literal_quants(yml_lines)
        if not ids:
            print("No IDs found with literal '*' or '+' needing escape in r:/n:/!r:/!n:. Nothing to change.")
            return

        print(f"Detected IDs with literal quantifiers: {', '.join(sorted(ids))}")

        # Confirm before applying changes
        try:
            answer = input("Proceed to escape literal '*' and '+'? [y/N]: ").strip().lower()
        except EOFError:
            answer = ''
        if answer not in ('y', 'yes'):
            print('Aborted. No changes applied.')
            return

        # Stage 2: Apply changes
        updated_lines, edited_count = update_yaml_rules_quants(yml_lines, ids)

        if updated_lines == yml_lines:
            print('No changes made. Matching IDs may have no escapable literal quantifiers.')
            return

        with open(policy_yml, 'w', encoding='utf-8', newline='') as f:
            f.writelines(updated_lines)

        print(f"Updated '{policy_yml}' for IDs: {', '.join(sorted(ids))}. Edited rules: {edited_count}.")
        return

    # --dots mode: dot-swap inside r:/n:/!r:/!n: tokens
    ids = find_ids_with_dot_patterns(yml_lines)
    if not ids:
        print('No IDs found with r:/n:/!r:/!n: tokens containing dot patterns. Nothing to change.')
        return

    print(f"Detected IDs with dot patterns: {', '.join(sorted(ids))}")

    # Confirm before applying changes
    try:
        answer = input('Proceed to apply swap to these IDs? [y/N]: ').strip().lower()
    except EOFError:
        answer = ''
    if answer not in ('y', 'yes'):
        print('Aborted. No changes applied.')
        return

    updated_lines, edited_count = update_yaml_rules_dots(yml_lines, ids)

    if updated_lines == yml_lines:
        print('No changes made. Matching IDs may have no r:/n:/!r:/!n: tokens to update.')
        return

    with open(policy_yml, 'w', encoding='utf-8', newline='') as f:
        f.writelines(updated_lines)

    print(f"Updated '{policy_yml}' for IDs: {', '.join(sorted(ids))}. Edited rules: {edited_count}.")

if __name__ == '__main__':
    main()