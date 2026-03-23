#!/usr/bin/env python3

from pathlib import Path
from argparse import ArgumentParser
from typing import Optional
import pandas as pd
from json import dumps, loads

HEADERS = {"field": 0, "waz": 1, "oth": 2, "match": 5, "direct": 6}


def need_to_match(field: str, df: pd.DataFrame) -> bool:
    field_column = df.columns[HEADERS["field"]]
    match_column = df.columns[HEADERS["match"]]

    match_row = df[df[field_column] == field]

    if not match_row.empty:
        return match_row[match_column].iloc[0] == "Yes"
    else:
        return False


def need_by_waz(field: str, df: pd.DataFrame) -> bool:
    field_column = df.columns[HEADERS["field"]]
    waz_column = df.columns[HEADERS["waz"]]

    match_row = df[df[field_column] == field]

    if not match_row.empty:
        return match_row[waz_column].iloc[0] == "Yes"
    else:
        return False


def need_by_oth(field: str, df: pd.DataFrame) -> bool:
    field_column = df.columns[HEADERS["field"]]
    oth_column = df.columns[HEADERS["oth"]]

    match_row = df[df[field_column] == field]

    if not match_row.empty:
        return match_row[oth_column].iloc[0] == "Yes"
    else:
        return False


def get_value(field: str, expected: dict):
    parts = field.split('.')
    current = expected
    for part in parts:
        if part not in current:
            return None
        current = current[part]

    return current


def fields_mapped_by_waz(df: pd.DataFrame) -> str:
    field_column = df.columns[HEADERS["field"]]
    waz_column = df.columns[HEADERS["waz"]]

    for _, row in df.iterrows():
        if row[waz_column] == "Yes":
            yield row[field_column]


def fields_mapped_by_oth(df: pd.DataFrame) -> str:
    field_column = df.columns[HEADERS["field"]]
    oth_column = df.columns[HEADERS["oth"]]

    for _, row in df.iterrows():
        if row[oth_column] == "Yes":
            yield row[field_column]


def fields_needed_to_match(df: pd.DataFrame) -> str:
    field_column = df.columns[HEADERS["field"]]
    match_column = df.columns[HEADERS["match"]]

    for _, row in df.iterrows():
        if row[match_column] == "Yes":
            yield row[field_column]


def get_direct(field: str, df: pd.DataFrame) -> Optional[str]:
    # Identify the column name for 'field' and 'direct' using the HEADERS dictionary
    field_column = df.columns[HEADERS["field"]]
    direct_column = df.columns[HEADERS["direct"]]

    # Locate the row where the value in the 'field' column matches the provided 'field'
    match_row = df[df[field_column] == field]

    # Check if there is a matching row and if so, retrieve the value from the 'direct' column
    if not match_row.empty and not pd.isna(match_row[direct_column].iloc[0]):
        return match_row[direct_column].iloc[0]
    else:
        return None


if __name__ == '__main__':
    try:
        arg_parser = ArgumentParser(
            description='Compare expected results of an output and wazuh output. Files should be a json consisting of an array of output objects, the script expects that the order of both files is the same')
        arg_parser.add_argument(
            'table', help='CSV table with metadata about the test')
        arg_parser.add_argument(
            'wazuh_output', type=Path, help='Path to the file with wazuh output')
        arg_parser.add_argument(
            'other_output', type=Path, help='Path to the file with other output')
        arg_parser.add_argument('-o', '--output', type=Path, help='Path to the output file, default: /tmp/compare_expected/compare_diff.json',
                                default='/tmp/compare_expected/compare_diff.json')
        arg_parser.add_argument('-e', '--extra', action='store_true', help='Show extra fields in the output, default: False',
                                default=False)
        arg_parser.add_argument('-m', '--missing', action='store_true',
                                help='Show missing fields in the output, default: False', default=False)

        args = arg_parser.parse_args()

        table = args.table
        wazuh_output_path = Path(args.wazuh_output)
        other_output_path = Path(args.other_output)
        output_path = Path(args.output)
        show_extra = args.extra
        show_missing = args.missing

        # Read the table
        df = pd.read_csv(table)

        # Read the files
        wazuh_expected = loads(wazuh_output_path.read_text())
        other_expected = loads(other_output_path.read_text())

        # Verify that the number of outputs is the same
        if len(wazuh_expected) != len(other_expected):
            raise Exception(
                f'Expected the same number of outputs, got {len(wazuh_expected)} wazuh outputs and {len(other_expected)} other outputs')

        # Compare each output following the table rules
        compare_results = []

        for wazuh_output, other_output in zip(wazuh_expected, other_expected):
            current_result = {}
            current_result['original'] = get_value(
                'event.original', wazuh_output)
            checked_fields = set()
            checked_fields.add('event.original')

            # Need to match
            for field in fields_needed_to_match(df):
                waz_value = get_value(field, wazuh_output)
                oth_field = get_direct(field, df)
                if oth_field is None:
                    oth_field = field

                oth_value = get_value(oth_field, other_output)

                key = field if field == oth_field else f'{field}|{oth_field}'
                if (waz_value != oth_value):
                    if 'need_to_match' not in current_result:
                        current_result['need_to_match'] = {}
                    current_result['need_to_match'][key] = {
                        'wazuh': waz_value,
                        'other': oth_value
                    }

            # Extra wazuh fields and missing wazuh fields
            for field in fields_mapped_by_waz(df):
                waz_value = get_value(field, wazuh_output)
                oth_value = get_value(field, other_output)

                # Wazuh missing fields
                if waz_value is None and show_missing:
                    if 'need_by_waz' not in current_result:
                        current_result['need_by_waz'] = []
                    current_result['need_by_waz'].append(field)

                # Wazuh extra fields
                if waz_value is not None and oth_value is None and show_extra:
                    if 'wazuh_extra' not in current_result:
                        current_result['wazuh_extra'] = []
                    current_result['wazuh_extra'].append(field)

            # Extra other fields and missing other fields
            for field in fields_mapped_by_oth(df):
                waz_value = get_value(field, wazuh_output)
                oth_value = get_value(field, other_output)

                # other missing fields
                if oth_value is None and show_missing:
                    if 'need_by_oth' not in current_result:
                        current_result['need_by_oth'] = []
                    current_result['need_by_oth'].append(field)

                # other extra fields
                if oth_value is not None and waz_value is None and show_extra:
                    if 'other_extra' not in current_result:
                        current_result['other_extra'] = []
                    current_result['other_extra'].append(field)

            compare_results.append(current_result)

        # Write the results
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(dumps(compare_results, indent=2))

        # Notify the user
        print(
            f'{wazuh_output_path.name} and {other_output_path.name} -> {output_path}')

    except KeyboardInterrupt:
        print('Interrupted by the user')
    except Exception as e:
        print(f'Unexpected error: {e}')
