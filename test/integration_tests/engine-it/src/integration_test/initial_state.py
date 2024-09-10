from shutil import copy
import sys
from pathlib import Path
from typing import Optional

from engine_handler.handler import EngineHandler

PLACEHOLDER = "ENV_PATH_PLACEHOLDER"


def cpy_conf(env_path: Path, it_path: Path) -> Path:
    serv_conf_file = it_path / 'configuration_files' / 'general.conf'
    dest_conf_file = env_path / 'engine' / 'general.conf'
    backup_dest_conf_file = env_path / 'engine' / 'general-bk.conf'

    conf_str = serv_conf_file.read_text().replace(PLACEHOLDER, env_path.as_posix())
    dest_conf_file.write_text(conf_str)
    backup_dest_conf_file.write_text(conf_str)

    return dest_conf_file


def cpy_bin(env_path: Path, bin_path: Path) -> Path:
    dest_bin_path = env_path / 'bin/wazuh-engine'
    dest_bin_path.parent.mkdir(parents=True, exist_ok=True)

    return copy(bin_path, dest_bin_path)


def create_dummy_integration(env_path: Path):
    wazuh_core_test = env_path / 'engine' / 'wazuh-core-test'
    wazuh_core_test.mkdir(parents=True, exist_ok=True)
    (wazuh_core_test / 'decoders').mkdir(exist_ok=True)
    (wazuh_core_test / 'filters').mkdir(exist_ok=True)

    (wazuh_core_test / 'decoders' / 'test-message.yml').write_text("""\
name: decoder/test-message/0
check: $wazuh.queue == 49 # "1"
""")

    (wazuh_core_test / 'filters' /
     'allow-all.yml').write_text("name: filter/allow-all/0\n")

    (wazuh_core_test / 'manifest.yml').write_text(
        "name: integration/wazuh-core-test/0\ndecoders:\n- decoder/test-message/0\n")


def create_other_dummy_integration(env_path: Path):
    other_wazuh_core_test = env_path / 'engine' / 'other-wazuh-core-test'
    other_wazuh_core_test.mkdir(parents=True, exist_ok=True)
    (other_wazuh_core_test / 'decoders').mkdir(exist_ok=True)
    (other_wazuh_core_test / 'filters').mkdir(exist_ok=True)

    (other_wazuh_core_test / 'decoders' / 'other-test-message.yml').write_text("""\
name: decoder/other-test-message/0
check: $wazuh.queue == 50 # "2"
""")

    (other_wazuh_core_test / 'manifest.yml').write_text(
        "name: integration/other-wazuh-core-test/0\ndecoders:\n- decoder/other-test-message/0\n")


def create_dummy_integration_with_parents(env_path: Path):
    parent_wazuh_core_test = env_path / 'engine' / 'parent-wazuh-core-test'
    parent_wazuh_core_test.mkdir(parents=True, exist_ok=True)
    (parent_wazuh_core_test / 'decoders').mkdir(exist_ok=True)
    (parent_wazuh_core_test / 'filters').mkdir(exist_ok=True)

    (parent_wazuh_core_test / 'decoders' / 'parent-message.yml').write_text("""\
name: decoder/parent-message/0
check: $wazuh.queue == 49 # "1"
""")

    (parent_wazuh_core_test / 'decoders' / 'test-message.yml').write_text("""\
name: decoder/test-message/0
parents:
    - decoder/parent-message/0
    """)

    (parent_wazuh_core_test / 'manifest.yml').write_text(
        "name: integration/parent-wazuh-core-test/0\ndecoders:\n- decoder/parent-message/0\n")


def init(env_path: Path, bin_path: Path, test_path: Path):
    engine_handler: Optional[EngineHandler] = None

    try:
        print(f"Copying configuration file to {env_path}...")
        config_path = cpy_conf(env_path, test_path)
        print("Configuration file copied.")

        print(f"Copying binary to {env_path}...")
        bin_path = cpy_bin(env_path, bin_path)
        print("Binary copied.")

        print("Starting the Engine...")
        engine_handler = EngineHandler(
            bin_path.as_posix(), config_path.as_posix())
        engine_handler.start()
        print("Engine started.")

        print("Creating dummy integrations...")
        create_dummy_integration(env_path)
        create_other_dummy_integration(env_path)
        create_dummy_integration_with_parents(env_path)
        print("Dummy integrations created.")

        print("Stopping the Engine...")
        engine_handler.stop()
        print("Engine stopped.")

    except Exception as e:
        print(f"An error occurred: {e}")
        if engine_handler:
            print("Stopping the engine...")
            engine_handler.stop()
            print("Engine stopped.")

        sys.exit(1)

    sys.exit(0)


def run(args):
    env_path = Path(args['environment']).resolve()
    bin_path = Path(args['binary']).resolve()
    test_path = Path(args['test_dir']).resolve()

    init(env_path, bin_path, test_path)
