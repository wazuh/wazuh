from shutil import copy
import sys
from pathlib import Path
from typing import Optional

from engine_handler.handler import EngineHandler

PLACEHOLDER = "ENV_PATH_PLACEHOLDER"


def cpy_conf(env_path: Path, it_path: Path) -> Path:
    serv_conf_file = it_path / 'configuration_files' / 'config.env'
    dest_conf_file = env_path / 'config.env'
    backup_dest_conf_file = env_path / 'config.env.bak'

    if not serv_conf_file.is_file():
        raise FileNotFoundError(f"File {serv_conf_file} does not exist")
    if dest_conf_file.is_file():
        dest_conf_file.rename(backup_dest_conf_file)

    conf_str = serv_conf_file.read_text().replace(PLACEHOLDER, env_path.as_posix())
    dest_conf_file.write_text(conf_str)

    return dest_conf_file

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


def init(env_path: Path, test_path: Path):
    engine_handler: Optional[EngineHandler] = None

    try:
        print(f"Copying configuration file to {env_path}...")
        config_path = cpy_conf(env_path, test_path)
        print("Configuration file copied.")

        # Binary path
        bin_path = env_path / 'wazuh-engine'

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
    test_path = Path(args['test_dir']).resolve()

    init(env_path, test_path)
