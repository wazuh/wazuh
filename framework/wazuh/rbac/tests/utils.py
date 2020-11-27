import os
from importlib import reload
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker


def create_memory_db(sql_file, session, test_data_path):
    with open(os.path.join(test_data_path, sql_file)) as f:
        for line in f.readlines():
            line = line.strip()
            if '* ' not in line and '/*' not in line and '*/' not in line and line != '':
                session.execute(line)
                #session.commit()


def init_db(schema, test_data_path):
    with patch('wazuh.core.common.ossec_uid'), patch('wazuh.core.common.ossec_gid'):
        with patch('sqlalchemy.create_engine', return_value=create_engine("sqlite://")):
            with patch('shutil.chown'), patch('os.chmod'):
                with patch('os.path.exists', return_value=False):
                    with patch('wazuh.rbac.orm._auth_db_file', new='test_database'):
                        with patch('wazuh.rbac.orm.DatabaseManager.get_api_revision', return_value='0'):
                            with patch('wazuh.rbac.orm.DatabaseManager.close_sessions'):
                                import wazuh.rbac.orm as orm
                                try:
                                    print(f'db en utils: {orm._auth_db_file}')
                                    print(f'sesiones: {str(orm.db_manager.sessions)}')
                                    create_memory_db(schema, sessionmaker(bind=create_engine('sqlite://'))(), test_data_path)
                                except OperationalError as e:
                                    print(f"OperationalError: {e}")
                                    pass
                                return orm
