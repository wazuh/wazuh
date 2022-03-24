import logging
import os
import sys
import typing

from sqlalchemy import create_engine, Column, Text, String, UniqueConstraint
from sqlalchemy.exc import IntegrityError, OperationalError, StatementError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import tools


DATABASE_NAME = "azure.db"
database_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), DATABASE_NAME)
LAST_DATES_NAME = "last_dates.json"
last_dates_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), LAST_DATES_NAME)

engine = create_engine('sqlite:///' + database_path, echo=False)
session = sessionmaker(bind=engine)()
Base = declarative_base()


class AzureTable:
    md5 = Column('md5', Text, primary_key=True)
    min_processed_date = Column(String(28), nullable=False)
    max_processed_date = Column(String(28), nullable=False)

    def __init__(self, md5: str, min_processed_date: str, max_processed_date: str):
        self.md5 = md5
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


def add_row(row: Base) -> bool:
    """Insert a new row object into the database.

    Parameters
    ----------
    row : Base
        The row object to insert into the database.

    Returns
    -------
    bool
        True if the row was successfully inserted, False otherwise.
    """
    try:
        session.add(row)
        session.commit()
        return True
    except (IntegrityError, OperationalError) as e:
        session.rollback()
        return False


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


def get_row(table: Base, md5: str) -> typing.Union[AzureTable, bool]:
    """Get a row from the specified table using the md5 value provided.

    Returns
    -------
    AzureTable or bool
        The row object if present or False if an exception was caught when attempting to obtain the row object.
    """
    try:
        return session.query(table).filter_by(md5=md5).first()
    except (IntegrityError, OperationalError, AttributeError):
        return False


def get_all_rows(table: Base) -> typing.Union[list, bool]:
    """Get a list of all the rows available for the given table. For testing purposes.

    Returns
    -------
    list or bool
        A list containing the different row objects available or False if an exception was raised.
    """
    try:
        return session.query(table).all()
    except (IntegrityError, OperationalError, AttributeError):
        logging.error(f"Error trying to obtain every row from '{table.__tablename__}'")
        return False


def migrate_from_last_dates_file():
    """Load a 'last_dates.json' file and insert its contents into the database."""
    logging.info("Migration from an old last_dates file is necessary. ")
    last_dates_content = tools.load_dates_json()
    keys = last_dates_content.keys()
    for service in [Graph, LogAnalytics, Storage]:
        if service.__tablename__ in keys:
            for md5_hash in last_dates_content[service.__tablename__].keys():
                min_value = last_dates_content[service.__tablename__][md5_hash]["min"]
                max_value = last_dates_content[service.__tablename__][md5_hash]["max"]
                row = service(md5=md5_hash, min_processed_date=min_value, max_processed_date=max_value)
                add_row(row=row)
    logging.info("The database migration process finished successfully.")


def update_row(table: Base, md5: str, min_date: str, max_date: str) -> bool:
    """Update an existing row in the specified table.

    Parameters
    ----------
    table : Base
        The table to work with.
    md5 : str
        The key of the item to update.
    min_date : str
        The new value for the lowest date processed.
    max_date : str
        The new value for the highest date processed.

    Returns
    -------
    bool
        True if the entry has been inserted successfully. False otherwise (i.e. already exists)
    """
    try:
        session.query(table).filter(table.md5 == md5).update({
            'min_processed_date': min_date,
            'max_processed_date': max_date})
        session.commit()
        return True
    except (IntegrityError, OperationalError, StatementError) as e:
        session.rollback()
        return False
