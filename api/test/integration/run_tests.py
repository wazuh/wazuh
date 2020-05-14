import argparse
import glob
import os
import re
import subprocess


RESULTS_PATH = 'test_results'
PYTEST_COMMAND = 'pytest -vv'
TESTS_PATH = os.path.dirname(os.path.abspath(__file__))


def calculate_result(file_name):
    with open(file_name, 'r') as f:
        file = f.read()
    print(f'\t{re.search(r"=+(.*) in (.*)s.*=+", file).group(1)}\n')


def collect_tests(keyword=None, rbac='both'):
    os.chdir(TESTS_PATH)

    def filter_tests(kw, rb):
        kw = kw if kw is not None else ''
        test_list = []
        for file in glob.glob('test_*'):
            if rb == 'yes':
                if kw in file and 'rbac' in file:
                    test_list.append(file)
            elif kw in file and rb == 'no':
                if 'rbac' not in file:
                    test_list.append(file)
            else:
                if kw in file:
                    test_list.append(file)
        return sorted(test_list)

    collected_tests = filter_tests(keyword, rbac)
    print(f'Collected tests [{len(collected_tests)}]:')
    print('{}\n\n'.format(", ".join([t for t in collected_tests])))

    return collected_tests


def run_tests(collected_tests, n_iterations=1):
    for test in collected_tests:
        for i in range(1, n_iterations + 1):
            iteration_info = f'[{i}/{n_iterations}]' if n_iterations > 1 else ''
            test_name = f'{test.rsplit(".")[0]}{i if i != 1 else ""}'
            print(f'{test} {iteration_info}')
            f = open(os.path.join(RESULTS_PATH, test_name), 'w')
            subprocess.call(PYTEST_COMMAND.split(' ') + [test], stdout=f)
            f.close()
            calculate_result(os.path.join(RESULTS_PATH, test_name))


def get_script_arguments():
    rbac_choices = ['both', 'yes', 'no']
    parser = argparse.ArgumentParser(usage="%(prog)s [options]",
                                     description="API integration tests",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-k', '--keyword', dest='keyword', default=None,
                        help='Specify the keyword to filter tests out. Default None.', action='store')
    parser.add_argument('-rbac', dest='rbac', default='both', choices=rbac_choices,
                        help='Specify what to do with RBAC tests. Run everything, only RBAC ones or no RBAC. Default '
                             '"both".', action='store')
    parser.add_argument('-i', '--iterations', dest='iterations', default=1, type=int,
                        help='Specify how many times will every test be run. Default 1.', action='store')

    return parser.parse_args()


if __name__ == '__main__':
    os.makedirs(os.path.join(TESTS_PATH, RESULTS_PATH), exist_ok=True)
    options = get_script_arguments()
    key = options.keyword
    rbac_arg = options.rbac
    iterations = options.iterations

    tests = collect_tests(keyword=key, rbac=rbac_arg)
    run_tests(collected_tests=tests, n_iterations=iterations)
