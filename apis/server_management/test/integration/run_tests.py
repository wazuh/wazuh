# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import argparse
import glob
import os
import re
import subprocess

PYTEST_COMMAND = 'pytest -vv'
RESULTS_FOLDER = '_test_results'
TESTS_PATH = os.path.dirname(os.path.abspath(__file__))


def calculate_result(file_name: str):
    """Extract and print a test result from its result file.

    Parameters
    ----------
    file_name : str
        Indicates the name of the file from which the test result is going to be parsed.
    """
    with open(file_name, 'r') as f:
        file = f.read()
    try:
        result = re.search(r'= ((\d+ .+){1,}) in (.+) =', file).group(1)
        print(f'\t {result}\n')
    except AttributeError:
        print('\tCould not retrieve results from this test')


def collect_tests(test_list: str = None, keyword: str = None, rbac: str = 'both') -> list:
    """Collect API integration tests from the test path filtering by the given parameters.

    Parameters
    ----------
    test_list : str
        List of tests substrings used to match and collect API integration tests. They must be separated by comma.
    keyword : str
        Keyword used to match and collect API integration tests.
    rbac : str
        Indicates whether RBAC tests are going to be collected or not. The possible values are `yes`, `no`, and `both`.

    Returns
    -------
    list
        List with the API integration tests collected.
    """
    os.chdir(TESTS_PATH)

    def filter_tests(kw: str, rb: str, t_list: str = None) -> list:
        """Filter API integration tests by the given parameters.

        Parameters
        ----------
        t_list : str
            List of tests substrings used to match and collect API integration tests. They must be separated by comma.
        kw : str
            Keyword used to match and collect API integration tests.
        rb : str
            Indicates whether RBAC tests are going to be collected or not. The possible values are `yes`, `no`, and
            `both`.

        Returns
        -------
        list
            Sorted list with the API integration tests collected.
        """
        kw = kw if kw is not None else ''
        t_list = t_list.split(',') if t_list else None
        collected_items = []
        candidate_tests = (
            [test for test in glob.glob('test_*.yaml') for t in t_list if t in test]
            if t_list
            else glob.glob('test_*.yaml')
        )
        for file in candidate_tests:
            if kw in file:
                if rb == 'yes' and 'rbac' in file:
                    collected_items.append(file)
                elif rb == 'no' and 'rbac' not in file:
                    collected_items.append(file)
                elif rb == 'both':
                    collected_items.append(file)
        return sorted(collected_items)

    collected_tests = filter_tests(keyword, rbac, t_list=test_list)
    print(f'Collected tests [{len(collected_tests)}]:')
    print('{}\n\n'.format(', '.join(collected_tests)))

    return collected_tests


def collect_non_excluded_tests() -> list:
    """Collect API integration tests without any results in the results folder.

    Returns
    -------
    list
        Sorted list with the API integration tests collected.
    """
    os.chdir(f'{TESTS_PATH}/{RESULTS_FOLDER}')
    done_tests = glob.glob('test_*')
    os.chdir(TESTS_PATH)
    collected_tests = sorted(
        [test for test in glob.glob('test_*') if f'{test.rstrip(".tavern.yaml")}' not in done_tests]
    )
    print(f'Collected tests [{len(collected_tests)}]:')
    print('{}\n\n'.format(', '.join(collected_tests)))

    return collected_tests


def run_tests(collected_tests: list, n_iterations: int = 1):
    """Run a certain number of iterations of API integration tests.

    Parameters
    ----------
    collected_tests : list
        Collected API integration tests that are going to be run.
    n_iterations : int
        Number of iterations for the API integration tests to be run.
    """

    def run_test(test: str, iteration: int):
        """Run a single API integration test once.

        Parameters
        ----------
        test : str
            API integration test to be run.
        iteration : int
            Number indicating the iteration to be run.
        """
        test_name = f'{test.rsplit(".")[0]}{iteration if iteration != 1 else ""}'
        html_params = [f'--html={RESULTS_FOLDER}/html_reports/{test_name}.html', '--self-contained-html']
        with open(os.path.join(RESULTS_FOLDER, test_name), 'w') as f:
            command = PYTEST_COMMAND.split(' ') + html_params + [test]
            subprocess.call(command, stdout=f)
        get_results(filename=os.path.join(RESULTS_FOLDER, test_name))

    os.chdir(TESTS_PATH)
    for test in collected_tests:
        for i in range(1, n_iterations + 1):
            iteration_info = f'[{i}/{n_iterations}]' if n_iterations > 1 else ''
            # Run test with the default environment
            print(f'Running {test} {iteration_info}')
            run_test(test=test, iteration=i)


def get_results(filename: str = None):
    """Get API integration tests results. Unless `filename` is given, all API integration tests results will be got.

    Parameters
    ----------
    filename : str
        Indicates the result test file to get the result from.
    """
    if filename:
        calculate_result(filename)
    else:
        os.chdir(RESULTS_FOLDER)
        for file in sorted(glob.glob('test_*')):
            print(f'Calculating result for {file}')
            calculate_result(file)


def get_script_arguments():
    """Get command line arguments given to the script."""
    rbac_choices = ['both', 'yes', 'no']
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options]', description='API integration tests', formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '-l',
        '--list',
        dest='test_list',
        default=None,
        help='Specify a list of tests separated by a comma.',
        action='store',
    )
    group.add_argument(
        '-e',
        '--exclude',
        dest='exclude',
        action='store_true',
        default=None,
        help='Run every test excluding the already saved in the RESULTS_FOLDER.',
    )
    group.add_argument(
        '-r',
        '--results',
        dest='results',
        action='store_true',
        default=None,
        help='Get result summary from the already run tests.',
    )
    parser.add_argument(
        '-k',
        '--keyword',
        dest='keyword',
        default=None,
        help='Specify the keyword to filter tests out. Default None.',
        action='store',
    )
    parser.add_argument(
        '-R',
        '--rbac',
        dest='rbac',
        default='both',
        choices=rbac_choices,
        help='Specify what to do with RBAC tests. Run everything, only RBAC ones or no RBAC. Default "both".',
        action='store',
    )
    parser.add_argument(
        '-i',
        '--iterations',
        dest='iterations',
        default=1,
        type=int,
        help='Specify how many times will every test be run. Default 1.',
        action='store',
    )

    return parser.parse_args()


if __name__ == '__main__':
    os.makedirs(os.path.join(TESTS_PATH, RESULTS_FOLDER, 'html_reports'), exist_ok=True)
    options = get_script_arguments()
    key = options.keyword
    tl = options.test_list
    exclude = options.exclude
    results = options.results
    rbac_arg = options.rbac
    mode_arg = options.mode
    iterations = options.iterations

    if results:
        get_results()
    else:
        tests = collect_non_excluded_tests() if exclude else collect_tests(test_list=tl, keyword=key, rbac=rbac_arg)
        run_tests(collected_tests=tests, n_iterations=iterations)
