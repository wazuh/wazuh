
import json
import logging
import os
import sys

LAST_DATES_NAME = "last_dates.json"
last_dates_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), LAST_DATES_NAME)

last_dates_default_contents = {'log_analytics': {}, 'graph': {}, 'storage': {}}


def load_dates_json() -> dict:
    """Read the "last_dates_file" containing the different processed dates. It will be created with empty values in
    case it does not exist.

    Returns
    -------
    dict
        The contents of the "last_dates_file".
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
            # If file does not exist, create it and dump the default structure
            contents = last_dates_default_contents
            with open(last_dates_path, 'w') as file:
                json.dump(contents, file)
        return contents
    except (json.JSONDecodeError, OSError) as e:
        logging.error(f"Error: The file of the last dates could not be read: '{e}.")
        raise e
