#!/usr/bin/env python3
import sys
import re
from typing import List, Tuple, Set, Optional
import os

# ========= DOTS (invert '.' and '\\.' handling) =========

def _swap_dots(payload: str, quote_char: Optional[str]) -> str:
    """Swap '.' and escaped dot inside a regex pattern, quote-aware.

    - Double-quote: swap '.' with '\\\\.' and '\\\\.' with '.'
    - Single-quote: swap '.' with '\\.' and '\\.' with '.'

    osregex: '.' means literal dot, escaped dot means any char.
    PCRE2: '.' means any char, escaped dot means literal dot.
    """
    out: List[str] = []
    i = 0
    n = len(payload)
    is_double = (quote_char == '"')
    while i < n:
        if not is_double and i + 1 < n and payload[i] == '\\' and payload[i + 1] == '.':
            out.append('.')
            i += 2
            continue
        if is_double and i + 2 < n and payload[i] == '\\' and payload[i + 1] == '\\' and payload[i + 2] == '.':
            out.append('.')
            i += 3
            continue
        if payload[i] == '.':
            out.append('\\\\.' if is_double else '\\.')
            i += 1
            continue
        out.append(payload[i])
        i += 1
    return ''.join(out)


# ========= BRACKETS (unescaped '[' and ']' handling) =========

def _escape_literal_brackets(payload: str, quote_char: Optional[str]) -> str:
    """Escape '[' and ']' according to line quote style, quote-aware.

    - Double-quote: add two backslashes before bracket
    - Single-quote: add one backslash before bracket

    osregex: No character class functionality.
    PCRE2: Character class functionality, previous bracket needs to be escaped.
    """
    out: List[str] = []
    i = 0
    n = len(payload)
    is_double = (quote_char == '"')

    while i < n:
        ch = payload[i]
        if ch in ('[', ']'):
            if is_double:
                out.append('\\\\')
                out.append(ch)
                i += 1
                continue
            else:
                out.append('\\')
                out.append(ch)
                i += 1
                continue
        out.append(ch)
        i += 1
    return ''.join(out)


def _detect_line_quote_char(line: str) -> Optional[str]:
    """Detect if the YAML list item value is single-quoted or double-quoted.
    Returns '"', "'", or None if not quoted.
    """
    m = re.match(r'^\s*-\s*([\'\"])', line)
    if m:
        return m.group(1)
    return None


# ========= WORDS (\\w handling) =========


def _expand_word_chars(payload: str, quote_char: Optional[str]) -> str:
    """Replace all \\w with [\\w@-], quote-aware.

    - Double-quote: replace '\\\\w' with '[\\\\w@-]'
    - Single-quote: replace '\\w' with '[\\w@-]'

    osregex: \\w includes letters plus '@-_'
    PCRE2: \\w includes letters plus '_', needs to be expanded to [\\w@-]
    """
    out: List[str] = []
    i = 0
    n = len(payload)
    is_double = (quote_char == '"')
    while i < n:
        if not is_double and payload[i] == '\\' and i + 1 < n and payload[i + 1] == 'w':
            out.append('[\\w@-]')
            i += 2
            continue
        if is_double and payload[i] == '\\' and i + 2 < n and payload[i + 1] == '\\' and payload[i + 2] == 'w':
            out.append('[\\\\w@-]')
            i += 3
            continue
        out.append(payload[i])
        i += 1
    return ''.join(out)


# ========= QUANTIFIERS (literal * and + handling) =========

_QUANTIFIER_PREV_ALLOWED = set(['w', 'd', 's', 't', 'p', 'W', 'D', 'S', '.'])

def _escape_literal_quantifiers(payload: str, quote_char: Optional[str]) -> str:
    """Escape literal '*' and '+'.

    - Double-quote: add two backslashes before literal.
    - Single-quote: add one backslash before literal.

    osregex: '*' or '+' is a quantifier only if preceded by one of: \\w, \\d, \\s, \\t, \\p, \\W, \\D, \\S, or \\. else it's literal.
    PCRE2: '*' or '+' is always a quantifier.
    """
    out: List[str] = []
    i = 0
    n = len(payload)
    is_double = (quote_char == '"')

    def prev_token_allows_quantifier(idx: int) -> bool:
        # Check immediate previous escaped token: \\x (single/unquoted) or \\\\x (double-quoted), where x in allowed set.
        if idx <= 0:
            return False
        if is_double:
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


# ========= LOGGING =========

_MODES_ORDER = ['quants', 'brackets', 'punct', 'words', 'dots', 'win']


def _get_logs_dir() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    logs_dir = os.path.join(script_dir, 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    return logs_dir


def _load_fix_log(policy_yml: str) -> dict:
    logs_dir = _get_logs_dir()
    policy_name = os.path.basename(policy_yml)
    policy_root, _ = os.path.splitext(policy_name)
    log_path = os.path.join(logs_dir, f"{policy_root}_fixlog.txt")
    data = {
        'policy_name': policy_root,
        'checked': 'no',
        'modes': {m: {'run': False, 'affected': 0, 'edited': 0, 'ids': [], 'warnings': []} for m in _MODES_ORDER}
    }
    if not os.path.exists(log_path):
        return data
    try:
        with open(log_path, 'r', encoding='utf-8', newline='') as f:
            lines = [ln.rstrip('\n') for ln in f.readlines()]
    except Exception:
        return data

    # Very lightweight parser: look for lines starting with mode headers
    if lines:
        data['policy_name'] = lines[0].strip() or policy_root
    for idx, ln in enumerate(lines):
        ln_stripped = ln.strip()
        for mode in _MODES_ORDER:
            hdr = f"--{mode} |"
            if ln_stripped.startswith(hdr):
                # Format: --mode | affected | edited | yes/no
                parts = [p.strip() for p in ln_stripped.split('|')]
                if len(parts) >= 4:
                    try:
                        affected = int(parts[1])
                    except ValueError:
                        affected = 0
                    try:
                        edited = int(parts[2])
                    except ValueError:
                        edited = 0
                    run_flag = parts[3].lower() in ('yes', 'true', 'y')
                    data['modes'][mode]['affected'] = affected
                    data['modes'][mode]['edited'] = edited
                    data['modes'][mode]['run'] = run_flag
                # Next lines: policy_list and optionally warnings
                # policy_list
                if idx + 1 < len(lines) and lines[idx + 1].strip().startswith('policy_list'):
                    ids_line = lines[idx + 1]
                    ids_part = ids_line.split(':', 1)
                    if len(ids_part) == 2:
                        ids_str = ids_part[1].strip()
                        ids = [s.strip() for s in ids_str.split(',') if s.strip()]
                        data['modes'][mode]['ids'] = ids
                # policy_list_warnings (only for punct)
                if mode == 'punct' and idx + 2 < len(lines) and lines[idx + 2].strip().startswith('policy_list_warnings'):
                    w_line = lines[idx + 2]
                    w_part = w_line.split(':', 1)
                    if len(w_part) == 2:
                        w_str = w_part[1].strip()
                        warns = [s.strip() for s in w_str.split(',') if s.strip()]
                        data['modes'][mode]['warnings'] = warns
    return data


def _write_fix_log(policy_yml: str, mode: str, ids: Set[str], edited_count: int, warned_ids: Optional[Set[str]] = None) -> None:
    logs_dir = _get_logs_dir()
    policy_name = os.path.basename(policy_yml)
    policy_root, _ = os.path.splitext(policy_name)
    log_path = os.path.join(logs_dir, f"{policy_root}_fixlog.txt")

    data = _load_fix_log(policy_yml)
    # Update current mode
    ids_list = sorted(ids)
    data['modes'][mode]['run'] = True
    data['modes'][mode]['affected'] = len(ids_list)
    data['modes'][mode]['edited'] = int(edited_count)
    data['modes'][mode]['ids'] = ids_list
    if warned_ids is not None:
        data['modes'][mode]['warnings'] = sorted(warned_ids)

    # Compute totals
    total_ids: Set[str] = set()
    total_edited = 0
    for m in _MODES_ORDER:
        total_ids.update(data['modes'][m]['ids'])
        total_edited += int(data['modes'][m]['edited'])

    # Write file
    with open(log_path, 'w', encoding='utf-8', newline='') as f:
        f.write(f"{data['policy_name']}\n")
        f.write(f"fix | {len(total_ids)} | {total_edited} | {data['checked']}\n")
        for m in _MODES_ORDER:
            entry = data['modes'][m]
            f.write(f"--{m} | {entry['affected']} | {entry['edited']} | {'yes' if entry['run'] else 'no'}\n")
            f.write("policy_list: " + (', '.join(entry['ids'])) + "\n")
            if m == 'punct':
                warns = entry.get('warnings') or []
                f.write("policy_list_warnings: " + (', '.join(warns)) + "\n")

# ========= PUNCT (custom \p handling) =========


def _replace_p(payload: str, quote_char: Optional[str]) -> Tuple[str, bool]:
    """Replace \p with [*!+-] in r:/!r: payloads.

    - Double-quote: replace '\\\\p' with '[*!+-]'
    - Single-quote: replace '\\p' with '[*!+-]'

    osregex: \\p means non-letters characters.
    PCRE2: \\p is not a valid wildcard, needs to be replaced with [*!+-].
    """
    out: List[str] = []
    i = 0
    n = len(payload)
    is_double = (quote_char == '"')
    warned_flag = False
    while i < n:
        if not is_double and payload[i] == '\\' and i + 1 < n and payload[i + 1] == 'p':
            # consume \p
            i += 2
            out.append('[*!+-]')
            warned_flag = True
            continue
        if is_double and payload[i] == '\\' and i + 2 < n and payload[i + 1] == '\\' and payload[i + 2] == 'p':
            i += 3
            out.append('[*!+-]')
            warned_flag = True
            continue
        # Regular character
        out.append(payload[i])
        i += 1
    return ''.join(out), warned_flag


def _remove_p(payload: str, quote_char: Optional[str]) -> str:
    """Remove \p from n:/!n: payloads.

    - Double-quote: replace '\\\\p' with ''
    - Single-quote: replace '\\p' with ''

    osregex: \\p means non-letters characters.
    PCRE2: \\p is not a valid wildcard, needs to be removed.
    """
    out: List[str] = []
    i = 0
    n = len(payload)
    is_double = (quote_char == '"')
    while i < n:
        if not is_double and payload[i] == '\\' and i + 1 < n and payload[i + 1] == 'p':
            i += 2
            if i < n and payload[i] in ('*', '+'):
                i += 1
            continue
        if is_double and payload[i] == '\\' and i + 2 < n and payload[i + 1] == '\\' and payload[i + 2] == 'p':
            i += 3
            if i < n and payload[i] in ('*', '+'):
                i += 1
            continue
        # Regular character
        out.append(payload[i])
        i += 1
    return ''.join(out)


# ========= WINDOWS (HKLM -> HKEY_LOCAL_MACHINE) =========

def _replace_win(pattern: str) -> str:
    """Replace HKLM with HKEY_LOCAL_MACHINE in the pattern.
    """
    return pattern.replace('HKLM', 'HKEY_LOCAL_MACHINE')

# ========= UPDATE YAML =========

_REGEX_MODES = ['quants', 'brackets','punct', 'words', 'dots']
_PATTERN_MODES = ['win']

def update_rules_based_on_mode(yml_lines: List[str], mode: str) -> Tuple[List[str], int, Set[str], Optional[Set[str]]]:
    """Update YAML rules based on the given mode."""
    new_lines: List[str] = []
    edited_count: int = 0
    warned_ids: Set[str] = set()
    ids: Set[str] = set()
    in_target_check = False
    in_rules = False
    rules_indent_len = None
    current_id: Optional[str] = None
    id_line_re = re.compile(r'^(\s*)-\s+id:\s+(\d+)\s*$')
    rules_key_re = re.compile(r'^(\s*)rules:\s*$')
    list_item_re = re.compile(r'^(\s*)-\s')
    for line in yml_lines:
        m_id = id_line_re.match(line)
        if m_id:
            current_id = m_id.group(2)
            in_target_check = True
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
                        if mode in _REGEX_MODES:
                            new_line, changed, warned_flag = fix_regex_in_line(mode, line, quote_char)
                        else:
                            new_line, changed, warned_flag = fix_pattern_in_line(mode, line)
                        if changed:
                            edited_count += 1
                            ids.add(current_id)
                        new_lines.append(new_line)
                        if warned_flag:
                            warned_ids.add(current_id)
                        continue
        new_lines.append(line)
    if not warned_ids:
        warned_ids = None
    return new_lines, edited_count, ids, warned_ids


def read_until_boundary(line: str, lenght: int, index: int) -> Tuple[str, int]:
    j = index
    while j < lenght and not (line.startswith(' && ', j) or line.startswith(' compare ', j) or line.startswith(' -> ', j)):
        j += 1
    return line[index:j], j


def fix_regex_in_line(mode: str, line: str, quote_char: Optional[str]) -> Tuple[str, bool, bool]:
    index = 0
    out: List[str] = []
    length = len(line)
    warned_flag: bool = False
    is_r_cmd: bool = False

    # Skip everything before the first command
    first_command, index = read_until_boundary(line, length, index)
    out.append(first_command)

    # If there is no command after skipping, return the original line
    if index == length:
        return line, False, False

    while index < length:
        # Handle !r: / !n:
        if index + 2 < length and line[index] == '!' and line[index + 1] in ('r', 'n') and line[index + 2] == ':':
            out.append(line[index:index+3])
            if line[index + 1] == 'r':
                is_r_cmd = True
            else:
                is_r_cmd = False
            index += 3
            payload, next_i = read_until_boundary(line, length, index)
            match mode:
                case 'quants':
                    out.append(_escape_literal_quantifiers(payload, quote_char))
                case 'brackets':
                    out.append(_escape_literal_brackets(payload, quote_char))
                case 'punct':
                    if is_r_cmd:
                        tmp, warned_flag = _replace_p(payload, quote_char)
                        out.append(tmp)
                    else:
                        out.append(_remove_p(payload, quote_char))
                case 'words':
                    out.append(_expand_word_chars(payload, quote_char))
                case 'dots':
                    out.append(_swap_dots(payload, quote_char))
                case _:
                    raise ValueError(f"Invalid mode: {mode}")
            index = next_i
            continue
        # Handle r: / n:
        if index + 1 < length and line[index] in ('r', 'n') and line[index + 1] == ':':
            out.append(line[index:index+2])
            if line[index] == 'r':
                is_r_cmd = True
            else:
                is_r_cmd = False
            index += 2
            payload, next_i = read_until_boundary(line, length, index)
            match mode:
                case 'quants':
                    out.append(_escape_literal_quantifiers(payload, quote_char))
                case 'brackets':
                    out.append(_escape_literal_brackets(payload, quote_char))
                case 'punct':
                    if is_r_cmd:
                        tmp, warned_flag = _replace_p(payload, quote_char)
                        out.append(tmp)
                    else:
                        out.append(_remove_p(payload, quote_char))
                case 'words':
                    out.append(_expand_word_chars(payload, quote_char))
                case 'dots':
                    out.append(_swap_dots(payload, quote_char))
                case _:
                    raise ValueError(f"Invalid mode: {mode}")
            index = next_i
            continue
        # Regular character
        out.append(line[index])
        index += 1
    updated = ''.join(out)
    return updated, (updated != line), warned_flag


def fix_pattern_in_line(mode: str, line: str) -> Tuple[str, bool, bool]:
    """ Fix the pattern in the line based on the mode.
    """
    match mode:
        case 'win':
            new_line = _replace_win(line)
        case _:
            raise ValueError(f"Invalid mode: {mode}")

    if new_line == line:
        return line, False, False

    return new_line, True, False


def main() -> None:
    # CLI: python refactor_regex.py <policy.yml> (--dots | --brackets | --words | --quants | --punct | --win | --help)
    # Help can be requested with --help or -h at any time
    if any(arg in ('--help', '-h') for arg in sys.argv[1:]):
        print('Usage: python refactor_regex.py <policy.yml> (--dots | --brackets | --words | --quants | --punct | --win)')
        print('')
        print('Modes:')
        print('  --quants   Escape literal * and + in r:/n:/!r:/!n: payloads unless they follow an escaped primitive')
        print('             (\\w, \\d, \\s, \\t, \\p, \\W, \\D, \\S, \\.) respecting quote style.')
        print('  --brackets Escape unescaped [ and ] inside r:/n:/!r:/!n: payloads (quote-aware).')
        print('  --words    Expand \\w to [\\w@-] outside classes and \\w@- inside classes (quote-aware).')
        print("  --dots     Swap '.' and escaped dot inside r:/n:/!r:/!n: payloads (quote-aware).")
        print("  --punct    Replace custom \\p: in n/!n remove (including trailing * or +); in r/!r replace with [*!+-].")
        print('  --win      [Windows only] Replace HKLM with HKEY_LOCAL_MACHINE anywhere in rule items.')
        print('')
        print('Suggested order for Linux to minimize interference: --quants -> --brackets -> --punct -> --words -> --dots')
        print('Suggested order for Windows to minimize interference: --win')
        print('')
        print('Log output:')
        print('  Location: logs/ directory next to this script.')
        print('  File name: <policy_name>_fixlog.txt')
        print('  Format:')
        print('    policy_name')
        print('    fix | <total policies> | <total lines fixed> | <checked>')
        print('    --<mode> | <affected> | <edited> | <yes|no>')
        print('    policy_list: <comma-separated IDs>')
        print('    (punct only) policy_list_warnings: <comma-separated IDs>')
        print('')
        print('Warning: Total policies reflects unique (non-repeatable) policy IDs across modes;')
        print('         summing per-mode affected counts may not equal the total.')
        sys.exit(0)

    if len(sys.argv) < 3:
        print('Usage: python refactor_regex.py <policy.yml> (--dots | --brackets | --words | --quants | --punct | --win)')
        sys.exit(1)

    dots_mode = any(arg == '--dots' for arg in sys.argv[1:])
    brackets_mode = any(arg == '--brackets' for arg in sys.argv[1:])
    words_mode = any(arg == '--words' for arg in sys.argv[1:])
    quants_mode = any(arg == '--quants' for arg in sys.argv[1:])
    punct_mode = any(arg == '--punct' for arg in sys.argv[1:])
    win_mode = any(arg == '--win' for arg in sys.argv[1:])
    non_flag_args = [a for a in sys.argv[1:] if not a.startswith('-')]

    modes_selected = int(dots_mode) + int(brackets_mode) + int(words_mode) + int(quants_mode) + int(punct_mode) + int(win_mode)
    if not non_flag_args or modes_selected != 1:
        # Either no file provided, or not exactly one mode provided
        print('Usage: python refactor_regex.py <policy.yml> (--dots | --brackets | --words | --quants | --punct | --win)')
        sys.exit(1)

    policy_yml = non_flag_args[0]

    try:
        with open(policy_yml, 'r', encoding='utf-8', newline='') as f:
            yml_lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: File '{policy_yml}' not found.")
        sys.exit(1)

    # --words mode: expand \\w to [\\w@-]
    if words_mode:
        updated_lines, edited_count, ids, _ = update_rules_based_on_mode(yml_lines, 'words')

        if updated_lines == yml_lines:
            print('No changes made. No expandable \\w tokens.')
            return

        with open(policy_yml, 'w', encoding='utf-8', newline='') as f:
            f.writelines(updated_lines)

        print(f"Updated '{policy_yml}' for IDs: {', '.join(sorted(ids))}. Edited rules: {edited_count}.")
        _write_fix_log(policy_yml, 'words', ids, edited_count)
        return

    # --brackets mode: escape unescaped [ and ]
    if brackets_mode:
        updated_lines, edited_count, ids, _ = update_rules_based_on_mode(yml_lines, 'brackets')

        if updated_lines == yml_lines:
            print('No changes made. No escapable brackets.')
            return

        with open(policy_yml, 'w', encoding='utf-8', newline='') as f:
            f.writelines(updated_lines)

        print(f"Updated '{policy_yml}' for IDs: {', '.join(sorted(ids))}. Edited rules: {edited_count}.")
        _write_fix_log(policy_yml, 'brackets', ids, edited_count)
        return

    # --quants mode: escape literal * and +
    if quants_mode:
        updated_lines, edited_count, ids, _ = update_rules_based_on_mode(yml_lines, 'quants')

        if updated_lines == yml_lines:
            print('No changes made. No escapable literal quantifiers.')
            return

        with open(policy_yml, 'w', encoding='utf-8', newline='') as f:
            f.writelines(updated_lines)

        print(f"Updated '{policy_yml}' for IDs: {', '.join(sorted(ids))}. Edited rules: {edited_count}.")
        _write_fix_log(policy_yml, 'quants', ids, edited_count)
        return

    # --punct mode: replace \\p with [*!+-]
    if punct_mode:
        updated_lines, edited_count, ids, warned_ids = update_rules_based_on_mode(yml_lines, 'punct')

        if updated_lines == yml_lines:
            print('No changes made. No \\p to update.')
            return

        with open(policy_yml, 'w', encoding='utf-8', newline='') as f:
            f.writelines(updated_lines)

        print(f"Updated '{policy_yml}' for IDs: {', '.join(sorted(ids))}. Edited rules: {edited_count}.")
        if warned_ids:
            print(f"Warning: replaced \\p with [*!+-] under r/!r for IDs: {', '.join(sorted(warned_ids))}. Please review those rules manually.")
        _write_fix_log(policy_yml, 'punct', ids, edited_count, warned_ids)
        return

    # --win mode: replace HKLM with HKEY_LOCAL_MACHINE
    if win_mode:
        updated_lines, edited_count, ids, _ = update_rules_based_on_mode(yml_lines, 'win')

        if updated_lines == yml_lines:
            print('No changes made. No HKLM to update.')
            return

        with open(policy_yml, 'w', encoding='utf-8', newline='') as f:
            f.writelines(updated_lines)

        print(f"Updated '{policy_yml}' for IDs: {', '.join(sorted(ids))}. Edited rules: {edited_count}.")
        _write_fix_log(policy_yml, 'win', ids, edited_count)
        return

    # --dots mode: dot-swap inside r:/n:/!r:/!n: tokens
    updated_lines, edited_count, ids, _ = update_rules_based_on_mode(yml_lines, 'dots')

    if updated_lines == yml_lines:
        print('No changes made. No dots to update.')
        return

    with open(policy_yml, 'w', encoding='utf-8', newline='') as f:
        f.writelines(updated_lines)

    print(f"Updated '{policy_yml}' for IDs: {', '.join(sorted(ids))}. Edited rules: {edited_count}.")
    _write_fix_log(policy_yml, 'dots', ids, edited_count)

if __name__ == '__main__':
    main()