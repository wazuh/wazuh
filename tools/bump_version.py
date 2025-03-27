import argparse
import difflib
import json
import re
import sys
from datetime import datetime
from pathlib import Path

# Define directories and files
DIR_ROOT = Path(__file__).resolve().parent.parent
FILE_VERSION = DIR_ROOT / 'VERSION.json'
DIR_SRC = DIR_ROOT / 'src'
DIR_FRAMEWORK = DIR_ROOT / 'framework'
DIR_APIS = DIR_ROOT / 'apis'
DIR_MANAGEMENT_API = DIR_APIS / 'server_management'
DIR_COMMUNICATIONS_API = DIR_APIS / 'communications'
DIR_PACKAGE = DIR_ROOT / 'packages'

# Version regex patterns
PATTERN_STAGES = ['alpha', 'beta', 'rc']
PATTERN_VERSION = r'\d+\.\d+\.\d+'
PATTERN_STAGE = r'({})\d{{1,2}}'.format('|'.join(PATTERN_STAGES))

# Control variables
DRY_RUN = False
VERBOSE = False


def debug_globals() -> str:
    """Get global variables for debugging."""
    dg = f'DIR_ROOT: {DIR_ROOT}\nFILE_VERSION: {FILE_VERSION}\n\n'
    dg += f'DIR_SRC: {DIR_SRC}\n'
    dg += f'DIR_FRAMEWORK: {DIR_FRAMEWORK}\n'
    dg += f'DIR_MANAGEMENT_API: {DIR_MANAGEMENT_API}\n'
    dg += f'DIR_COMMUNICATIONS_API: {DIR_COMMUNICATIONS_API}\n'
    dg += f'DIR_PACKAGE: {DIR_PACKAGE}\n'
    dg += f'PATTERN_STAGES: {PATTERN_STAGES}\nPATTERN_VERSION: {PATTERN_VERSION}\nPATTERN_STAGE: {PATTERN_STAGE}\n\n'
    dg += f'DRY_RUN: {DRY_RUN}\nVERBOSE: {VERBOSE}\n'

    return dg


def print_v(text: str) -> None:
    """Print vervose output.

    Parameters
    ----------
    text : str
        Text to print.
    """
    if VERBOSE:
        print(text)


class Command:
    """Represent a command over a file."""

    def __init__(self, file: Path, backup_text: str, new_text: str):
        self._file = file
        self._backup_text = backup_text
        self._new_text = new_text

    def do(self) -> str | None:
        """Apply changes in a file."""
        try:
            self._file.write_text(self._new_text)
            print_v(f'Updated {self._file}')
        except Exception as e:
            print_v(f'Failed to update {self._file}: {e}')
            return str(e)

    def undo(self) -> str | None:
        """Revert changes in a file."""
        try:
            self._file.write_text(self._backup_text)
            print_v(f'Reverted {self._file}')
        except Exception as e:
            print_v(f'Failed to revert {self._file}: {e}')
            return str(e)

        return None

    def diff(self) -> str:
        """Show differences from old and new files."""
        diff = difflib.unified_diff(self._backup_text.splitlines(), self._new_text.splitlines(), lineterm='', n=1)

        return f'{self._file}: \n {"\n".join(diff)} \n'


class Executor:
    """Represent a command executor."""

    def __init__(self):
        self._commands = []
        self._do_errors = []
        self._undo_errors = []
        self._current_index = 0

    def add_command(self, command: Command):
        """Add command to the executor queue.

        Parameters
        ----------
        command : Command
            Command to add.
        """
        self._commands.append(command)

    def execute(self, dry_run: bool = False):
        """Execute a list of commands.

        Parameters
        ----------
        dry_run : bool, optional
            Indicates if files should be write or not, by default False.
        """
        for self._current_index, command in enumerate(self._commands):
            if dry_run:
                print(command.diff())
            else:
                error = command.do()
                if error:
                    self._do_errors.append(error)
                    for i in range(self._current_index, -1, -1):
                        error = self._commands[i].undo()
                        if error:
                            self._undo_errors.append(error)


def validate_version(version: str) -> None:
    """Validate version format.

    Raises:
        ValueError: If version is invalid.
    """
    if not isinstance(version, str):
        raise ValueError(f'Version must be a string, got {type(version)}')

    if not re.match(f'^{PATTERN_VERSION}$', version):
        raise ValueError(f"Invalid version value '{version}'")


def validate_stage(stage: str) -> None:
    """Validate stage format.

    Raises:
        ValueError: If stage is invalid.
    """
    if not isinstance(stage, str):
        raise ValueError(f'Stage must be a string, got {type(stage)}')

    if not re.match(f'^{PATTERN_STAGE}$', stage):
        raise ValueError(f"Invalid stage value '{stage}'")


def validate_date(date: str) -> None:
    """Validate date format.

    Raises:
        ValueError: If date is invalid.
    """
    try:
        datetime.strptime(date, '%Y-%m-%d')
    except ValueError:
        raise ValueError(f"Invalid date value '{date}'")


def load_version(version_file_path: Path) -> tuple[str, str]:
    """Load version and stage from VERSION.json.

    Returns:
        tuple[str, str]: (version, stage)

    Raises:
        FileNotFoundError: If VERSION.json does not exist.
        ValueError: If VERSION.json is invalid or missing keys.
    """
    if not version_file_path.exists():
        raise FileNotFoundError(f'{version_file_path} not found')

    try:
        with version_file_path.open('r', encoding='utf-8') as f:
            json_version = json.load(f)
    except json.JSONDecodeError:
        raise ValueError(f'{version_file_path} is not a valid JSON file')

    version = json_version.get('version')
    stage = json_version.get('stage')

    if not version or not stage:
        raise ValueError(f"Missing 'version' or 'stage' in {version_file_path}")

    validate_version(version)
    validate_stage(stage)

    return version, stage


def update_file_version(
    executor: Executor, file_path: Path, new_version: str | None = None, new_stage: str | None = None
) -> None:
    """Update version file.

    Args:
        executor (Executor): Executor to handle commands.
        file_path (Path): Path to file.
        new_version (str | None, optional): Defaults to None.
        new_stage (str | None, optional): Defaults to None.

    Raises:
        Exception: If failed to create a command.
    """
    if not new_version and not new_stage:
        return

    current = file_path.read_text()
    updated = json.loads(current)

    if new_version:
        updated['version'] = new_version
    if new_stage:
        updated['stage'] = new_stage

    to_write = json.dumps(updated, indent=4) + '\n'
    if current != to_write:
        executor.add_command(Command(file_path, current, json.dumps(updated, indent=4)))


def update_file(executor: Executor, file_path: Path, patterns: dict[str, tuple[re.Pattern, str | None]]) -> None:
    """Update patterns in a given file."""
    content = file_path.read_text()
    updated_content = content

    for key, (pattern, replacement) in patterns.items():
        if replacement:
            updated_content = pattern.sub(replacement, updated_content)

    if content != updated_content:
        executor.add_command(Command(file_path, content, updated_content))


def update_file_sources(executor: Executor, new_version: str | None = None, new_stage: str | None = None) -> None:
    """Update source files with new version and stage."""
    if not new_version and not new_stage:
        return

    patterns_doxyfile = {
        'version': (
            re.compile(rf'(PROJECT_NUMBER\s+=\s+"v)({PATTERN_VERSION})(-.+"$)', re.MULTILINE),
            rf'\g<1>{new_version}\g<3>' if new_version else None,
        ),
        'stage': (
            re.compile(rf'(PROJECT_NUMBER\s+=\s+"v{PATTERN_VERSION}-)(.+)("$)', re.MULTILINE),
            rf'\g<1>{new_stage}\g<3>' if new_stage else None,
        ),
    }
    update_file(executor, DIR_SRC / 'Doxyfile', patterns_doxyfile)


def update_file_framework(executor: Executor, new_version: str | None = None, new_stage: str | None = None) -> None:
    """Update framework files with new version and stage."""
    if not new_version and not new_stage:
        return

    version_pattern = (
        re.compile(rf'(^__version__\s+=\s+\')({PATTERN_VERSION})(\'$)', re.MULTILINE),
        rf'\g<1>{new_version}\g<3>' if new_version else None,
    )

    patterns_framework = {'version': version_pattern}
    update_file(executor, DIR_FRAMEWORK / 'wazuh/__init__.py', patterns_framework)

    patterns_cluster = {
        'version': version_pattern,
        'stage': (
            re.compile(r'(^__revision__\s+=\s+\')(.+)(\'$)', re.MULTILINE),
            rf'\g<1>{new_stage}\g<3>' if new_stage else None,
        ),
    }
    update_file(executor, DIR_FRAMEWORK / 'wazuh/core/cluster/__init__.py', patterns_cluster)


def update_file_api(executor: Executor, new_version: str | None = None, new_stage: str | None = None) -> None:
    """Update API files with new version and stage."""
    if not new_version and not new_stage:
        return

    patterns_api_setup = {
        'version': (
            re.compile(rf'(^\s+version=\')({PATTERN_VERSION})(\',$)', re.MULTILINE),
            rf'\g<1>{new_version}\g<3>' if new_version else None,
        )
    }

    for file in (DIR_MANAGEMENT_API / 'setup.py', DIR_COMMUNICATIONS_API / 'setup.py'):
        update_file(executor, file, patterns_api_setup)

    patterns_api_spec = {
        'version_1': (
            re.compile(rf'(^\s+version:\s+\')({PATTERN_VERSION})(\'$)', re.MULTILINE),
            rf'\g<1>{new_version}\g<3>' if new_version else None,
        ),
        'version_2': (
            re.compile(rf'(/v)({PATTERN_VERSION})(/)', re.MULTILINE),
            rf'\g<1>{new_version}\g<3>' if new_version else None,
        ),
        'version_3': (
            re.compile(r'(com/)(\d+.\d+)(/)', re.MULTILINE),
            rf'\g<1>{".".join(new_version.split(".")[:-1])}\g<3>' if new_version else None,
        ),
        'stage': (
            re.compile(r'(^\s+x-revision:\s+\')(.+)(\'$)', re.MULTILINE),
            rf'\g<1>{new_stage}\g<3>' if new_stage else None,
        ),
    }
    update_file(executor, DIR_MANAGEMENT_API / 'server_management_api/spec/spec.yaml', patterns_api_spec)


def update_file_packages(executor: Executor, new_version: str, new_stage: str, new_date: str) -> None:
    """Update package-related files with new version, stage, and release date."""
    major, minor, patch = new_version.split('.')

    formatted_date = datetime.strptime(new_date, '%Y-%m-%d').strftime('%a, %d %b %Y 00:00:00 +0000')
    spec_date = datetime.strptime(new_date, '%Y-%m-%d').strftime('%a %b %d %Y')

    # Define regex patterns for different files
    pattern_spec = re.compile(r'^.+\.spec$')
    pattern_changelog = re.compile(r'^changelog$')
    pattern_copyright = re.compile(r'^copyright$')
    pattern_pkginfo = re.compile(r'^pkginfo$')

    # Update .spec files
    for spec_file in [f for f in DIR_PACKAGE.rglob('*') if pattern_spec.match(f.name)]:
        patterns = {
            'changelog_entry': (
                re.compile(r'(^%changelog\s*$)', re.MULTILINE),
                rf'\g<1>\n* {spec_date} support <info@wazuh.com> - {new_version}\n- More info: https://documentation.wazuh.com/current/release-notes/release-{new_version.replace(".", "-")}.html',
            )
        }
        update_file(executor, spec_file, patterns)

    # Update changelog files
    for changelog_file in [f for f in DIR_PACKAGE.rglob('*') if pattern_changelog.match(f.name)]:
        install_type = changelog_file.resolve().parent.parent.name
        patterns = {
            'changelog_entry': (
                re.compile('^'),
                rf'{install_type} ({new_version}-RELEASE) stable; urgency=low\n\n  * More info: https://documentation.wazuh.com/current/release-notes/release-{new_version.replace(".", "-")}.html\n\n -- Wazuh, Inc <info@wazuh.com>  {formatted_date}\n\n',
            )
        }
        update_file(executor, changelog_file, patterns)

    # Update copyright files
    for copyright_file in [f for f in DIR_PACKAGE.rglob('*') if pattern_copyright.match(f.name)]:
        patterns = {
            'copyright_date': (
                re.compile(r'(^    Wazuh, Inc <info@wazuh.com> on )(.+)($)', re.MULTILINE),
                rf'\g<1>{formatted_date}\g<3>',
            ),
        }
        update_file(executor, copyright_file, patterns)

    # Update pkginfo files
    for pkginfo_file in [f for f in DIR_PACKAGE.rglob('*') if pattern_pkginfo.match(f.name)]:
        patterns = {
            'pkginfo_version': (
                re.compile(rf'(^VERSION=")({PATTERN_VERSION})("$)', re.MULTILINE),
                rf'\g<1>{new_version}\g<3>',
            ),
        }
        update_file(executor, pkginfo_file, patterns)


def update_version(
    current_version: str,
    current_stage: str,
    new_version: str | None = None,
    new_stage: str | None = None,
    new_date: str | None = None,
) -> None:
    """Update version to a specific version.

    Args:
        current_version (str): Current version.
        current_stage (str): Current stage.
        new_version (str | None): New version.
        new_stage (str | None): New stage to set.
        new_date (str | None): New date to set.
    """
    if new_version:
        validate_version(new_version)
    if new_stage:
        validate_stage(new_stage)
    if new_date:
        validate_date(new_date)

    executor = Executor()

    # Create commands
    # Update version files and references
    update_file_version(executor, FILE_VERSION, new_version, new_stage)
    update_file_sources(executor, new_version, new_stage)
    update_file_framework(executor, new_version, new_stage)
    update_file_api(executor, new_version, new_stage)

    # Add package entries
    update_file_packages(
        executor,
        new_version or current_version,
        new_stage or current_stage,
        new_date or datetime.now().strftime('%Y-%m-%d'),
    )

    # Execute commands
    executor.execute(DRY_RUN)


def parse_args() -> tuple[str | None, str | None, str | None, bool, bool]:
    """Parse CLI arguments.

    Returns
    -------
    tuple[str | None, str | None, str | None, bool, bool]
        The parsed aguments.
    """
    parser = argparse.ArgumentParser(description='Bump version, stage and date for all packages')

    parser.add_argument('--version', help='Update version')
    parser.add_argument('--stage', help='Update stage')
    parser.add_argument('--date', help='Update date')
    parser.add_argument('--verbose', help='Verbose output', action='store_true')
    parser.add_argument('--dry-run', help='Dry run', action='store_true')
    args = parser.parse_args()

    if not args.version and not args.stage and not args.date:
        parser.error('No arguments provided. Use at least one of --version, --stage, or --date')

    return args.version, args.stage, args.date, args.verbose, args.dry_run


if __name__ == '__main__':
    new_version, new_stage, new_date, VERBOSE, DRY_RUN = parse_args()
    print_v(debug_globals())
    try:
        current_version, current_stage = load_version(FILE_VERSION)
        print_v(f'Current version: {current_version}\nCurrent stage: {current_stage}\n')
        print_v(f'New version: {new_version}\nNew stage: {new_stage}\nNew date: {new_date}\n')
    except Exception as e:
        sys.exit(f'Error loading current {FILE_VERSION}: {e}')

    try:
        update_version(current_version, current_stage, new_version, new_stage, new_date)
    except Exception as e:
        sys.exit(f'Error updating version: {e}')
