import json
import logging
import os

from sqlalchemy import create_engine, Column, Text, String, UniqueConstraint
from sqlalchemy.exc import IntegrityError, OperationalError, StatementError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_NAME = "azure.db"
database_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), DATABASE_NAME)
LAST_DATES_NAME = "last_dates.json"
last_dates_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), LAST_DATES_NAME)
last_dates_default_contents = {'log_analytics': {}, 'graph': {}, 'storage': {}}

engine = create_engine('sqlite:///' + database_path, echo=False)
session = sessionmaker(bind=engine)()
Base = declarative_base()


class AzureTable:
    md5 = Column(Text, primary_key=True)
    query = Column(Text, nullable=False)
    min_processed_date = Column(String(28), nullable=False)
    max_processed_date = Column(String(28), nullable=False)

    def __init__(self, md5: str, query: str, min_processed_date: str, max_processed_date: str):
        self.md5 = md5
        self.query = query
        self.min_processed_date = min_processed_date
        self.max_processed_date = max_processed_date


class Graph(AzureTable, Base):
    __tablename__ = 'graph'
    __table_args__ = (UniqueConstraint('md5', name='md5_restriction'),)


class LogAnalytics(AzureTable, Base):
    __tablename__ = 'log_analytics'
    __table_args__ = (UniqueConstraint('md5', name='md5_restriction'),)


class Storage(AzureTable, Base):
    __tablename__ = 'storage'
    __table_args__ = (UniqueConstraint('md5', name='md5_restriction'),)


class AzureORMError(Exception):
    pass


def add_row(row: Base):
    """Insert a new row object into the database.

    Parameters
    ----------
    row : Base
        The row object to insert into the database.

    Raises
    ------
    AzureORMError
    """
    try:
        session.add(row)
        session.commit()
    except (IntegrityError, OperationalError) as e:
        session.rollback()
        raise AzureORMError(str(e))


def check_database_integrity() -> bool:
    """Create a database file if not present and migrate from an old last_dates.json file if required.

    Returns
    -------
    bool
        True if the check finished successfully, False otherwise.
    """
    logging.info("Checking database integrity")
    create_db()

    # Check if a migration from an old last_dates_file is required
    if os.path.exists(last_dates_path) and os.path.getsize(last_dates_path) > 0:
        try:
            migrate_from_last_dates_file()
        except Exception as e:
            logging.error(f"Error during last_dates file migration process: {e}")
            return False
        try:
            os.remove(last_dates_path)
        except OSError:
            logging.warning(f"It was not possible to remove the old last_dates file at {last_dates_path}")
    logging.info("Database integrity check finished")
    return True


def create_db():
    """Create the Azure database if it does not exist yet."""
    Base.metadata.create_all(engine)


def get_row(table: Base, md5: str) -> AzureTable:
    """Get a row from the specified table using the md5 value provided.

    Returns
    -------
    AzureTable
        The row object if present or False if an exception was caught when attempting to obtain the row object.

    Raises
    ------
    AzureORMError
    """
    try:
        return session.query(table).filter_by(md5=md5).first()
    except (IntegrityError, OperationalError, AttributeError) as e:
        raise AzureORMError(str(e))


def get_all_rows(table: Base) -> list:
    """Get a list of all the rows available for the given table. For testing purposes.

    Returns
    -------
    list
        A list containing the different row objects available or False if an exception was raised.

    Raises
    ------
    AzureORMError
    """
    try:
        return session.query(table).all()
    except (IntegrityError, OperationalError, AttributeError) as e:
        raise AzureORMError(str(e))


def migrate_from_last_dates_file():
    """Load a 'last_dates.json' file and insert its contents into the database."""
    logging.info("Migration from an old last_dates file is necessary. ")
    last_dates_content = load_dates_json()
    keys = last_dates_content.keys()
    for service in [Graph, LogAnalytics, Storage]:
        if service.__tablename__ in keys:
            for md5_hash in last_dates_content[service.__tablename__].keys():
                min_value = last_dates_content[service.__tablename__][md5_hash]["min"]
                max_value = last_dates_content[service.__tablename__][md5_hash]["max"]
                row = service(md5=md5_hash, query="", min_processed_date=min_value, max_processed_date=max_value)
                add_row(row=row)
    logging.info("The database migration process finished successfully.")


def update_row(table: Base, md5: str, min_date: str, max_date: str, query: str = None):
    """Update an existing row in the specified table.

    Parameters
    ----------
    table : Base
        The table to work with.
    md5 : str
        The key of the row object to update.
    min_date : str
        The new value for the lowest date processed.
    max_date : str
        The new value for the highest date processed.
    query : str
        The query value for the row object.

    Raises
    ------
    AzureORMError
    """
    try:
        row_data = {'min_processed_date': min_date, 'max_processed_date': max_date}
        if query:
            row_data['query'] = query
        session.query(table).filter(table.md5 == md5).update(row_data)
        session.commit()
    except (IntegrityError, OperationalError, StatementError) as e:
        session.rollback()
        raise AzureORMError(str(e))


def load_dates_json() -> dict:
    """Read the "last_dates_file" containing the different processed dates. It will be created with empty values in
    case it does not exist.

    Returns
    -------
    dict
        The contents of the "last_dates_file".

    Raises
    ------
    json.JSONDecodeError
    OSError
    """
    logging.info(f"Getting the data from {last_dates_path}.")
    try:
        if os.path.exists(last_dates_path):
            with open(last_dates_path) as file:
                contents = json.load(file)
                # This adds compatibility with "last_dates_files" from previous releases as the format was different
                for key in contents.keys():
                    for md5_hash in contents[key].keys():
                        if not isinstance(contents[key][md5_hash], dict):
                            contents[key][md5_hash] = {"min": contents[key][md5_hash], "max": contents[key][md5_hash]}
        else:
            contents = last_dates_default_contents
        return contents
    except (json.JSONDecodeError, OSError) as e:
        logging.error(f"Error: The file of the last dates could not be read: '{e}.")
        raise e
