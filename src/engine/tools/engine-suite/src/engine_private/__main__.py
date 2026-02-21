import sys
import argparse
from importlib.metadata import metadata
from importlib import import_module

from shared.default_settings import Constants as DefaultSettings

# ======================
# CM (Content Manager) commands
# ======================
from engine_private.cmds.cm.list import configure as configure_cm_list
from engine_private.cmds.cm.upsert import configure as configure_cm_upsert
from engine_private.cmds.cm.delete import configure as configure_cm_delete
from engine_private.cmds.cm.get import configure as configure_cm_get
from engine_private.cmds.cm.policy_upsert import configure as configure_cm_policy_upsert
from engine_private.cmds.cm.policy_delete import configure as configure_cm_policy_delete

# ======================
# Namespace commands
# ======================
from engine_private.cmds.ns.list import configure as configure_ns_list
from engine_private.cmds.ns.create import configure as configure_ns_create
from engine_private.cmds.ns.delete import configure as configure_ns_delete
from engine_private.cmds.ns.import_ns import configure as configure_ns_import

# ======================
# Geo commands
# ======================
from engine_private.cmds.geo.get import configure as configure_geo_get
from engine_private.cmds.geo.list import configure as configure_geo_list

def parse_args():
    meta = metadata('engine-suite')

    # Root parser
    parser = argparse.ArgumentParser(prog='engine-private')
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {meta.get("Version")}'
    )

    # Global argument: API socket
    parser.add_argument(
        '--api-socket',
        type=str,
        default=DefaultSettings.SOCKET_PATH,
        help='Path to the Wazuh API socket'
    )

    # Top-level subcommands (cm / ns)
    # dest is required because of https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands',
        required=True,
        dest='subcommand'
    )

    # ==========================================================
    # CM commands (operate INSIDE a namespace → require --space)
    # ==========================================================
    cm_parser = subparsers.add_parser(
        'cm',
        help='Content Manager operations'
    )

    cm_parser.add_argument(
        '-n', '--space',
        type=str,
        required=True,
        help='Namespace to use for Content Manager operations'
    )

    cm_subparsers = cm_parser.add_subparsers(
        title='cm commands',
        required=True,
        dest='cm_command'
    )

    configure_cm_upsert(cm_subparsers)
    configure_cm_delete(cm_subparsers)
    configure_cm_get(cm_subparsers)
    configure_cm_list(cm_subparsers)
    configure_cm_policy_upsert(cm_subparsers)
    configure_cm_policy_delete(cm_subparsers)

    # ==========================================================
    # Namespace commands (global → do NOT require --space)
    # ==========================================================
    ns_parser = subparsers.add_parser(
        'ns',
        help='Namespace management operations'
    )

    ns_subparsers = ns_parser.add_subparsers(
        title='namespace commands',
        required=True,
        dest='ns_command'
    )

    configure_ns_list(ns_subparsers)
    configure_ns_create(ns_subparsers)
    configure_ns_delete(ns_subparsers)
    configure_ns_import(ns_subparsers)

    # ==========================================================
    # Geo commands (global → do NOT require --space)
    # ==========================================================
    geo_parser = subparsers.add_parser(
        'geo',
        help='Geo management operations'
    )

    geo_subparsers = geo_parser.add_subparsers(
        title='geo commands',
        required=True,
        dest='geo_command'
    )

    configure_geo_get(geo_subparsers)
    configure_geo_list(geo_subparsers)

    # ==========================================================
    # Raw event indexer commands (global → do NOT require --space)
    # ==========================================================
    rawevt_parser = subparsers.add_parser(
        'rawevt',
        help='Raw event indexer operations'
    )

    rawevt_subparsers = rawevt_parser.add_subparsers(
        title='rawevt commands',
        required=True,
        dest='rawevt_command'
    )

    configure_rawevt_enable = import_module('engine_private.cmds.rawevt.enable').configure
    configure_rawevt_disable = import_module('engine_private.cmds.rawevt.disable').configure
    configure_rawevt_status = import_module('engine_private.cmds.rawevt.status').configure

    configure_rawevt_enable(rawevt_subparsers)
    configure_rawevt_disable(rawevt_subparsers)
    configure_rawevt_status(rawevt_subparsers)

    try:
        import argcomplete
        argcomplete.autocomplete(parser, always_complete_options=False)
    except ImportError:
        pass

    return parser.parse_args()


def main():
    args = parse_args()

    # Each configure_* function must register args.func
    # and receive the parsed arguments as a dict
    args.func(vars(args))


if __name__ == '__main__':
    sys.exit(main())
