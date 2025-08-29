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


def _detect_line_quote_char(line: str) -> Optional[str]:
    """Detect if the YAML list item value is single-quoted or double-quoted.
    Returns '"', "'", or None if not quoted.
    """
    m = re.match(r'^\s*-\s*([\'\"])', line)
    if m:
        return m.group(1)
    return None


def main() -> None:
    # CLI: python refactor_regex.py <policy.yml> (--dots)
    if len(sys.argv) < 3:
        print('Usage: python refactor_regex.py <policy.yml> (--dots)')
        sys.exit(1)

    dots_mode = any(arg == '--dots' for arg in sys.argv[1:])
    non_flag_args = [a for a in sys.argv[1:] if not a.startswith('-')]

    modes_selected = int(dots_mode)
    if not non_flag_args or modes_selected != 1:
        # Either no file provided, or not exactly one mode provided
        print('Usage: python refactor_regex.py <policy.yml> (--dots)')
        sys.exit(1)

    policy_yml = non_flag_args[0]

    try:
        with open(policy_yml, 'r', encoding='utf-8', newline='') as f:
            yml_lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: File '{policy_yml}' not found.")
        sys.exit(1)

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