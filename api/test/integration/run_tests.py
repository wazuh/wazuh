import argparse
import glob
import os
import re
import subprocess


RESULTS_PATH = '_test_results'
PYTEST_COMMAND = 'pytest -vv'
TESTS_PATH = os.path.dirname(os.path.abspath(__file__))


def calculate_result(file_name):
    with open(file_name, 'r') as f:
        file = f.read()
    try:
        result = re.search(r'={5,} (.+) in (.*) ={5,}', file).group(1)
        print(f'\t {result}\n')
    except AttributeError:
        print('\tCould not retrieve results from this test')


def collect_tests(test_list=None, keyword=None, rbac='both'):
    os.chdir(TESTS_PATH)

    def filter_tests(kw, rb, t_list=None):
        kw = kw if kw is not None else ''
        t_list = t_list.split(',') if t_list else None
        collected_items = []
        candidate_tests = [test for test in glob.glob('test_*.yaml') for t in t_list if t in test] \
            if t_list else glob.glob('test_*.yaml')
        for file in candidate_tests:
            if rb == 'yes':
                if kw in file and 'rbac' in file:
                    collected_items.append(file)
            elif kw in file and rb == 'no':
                if 'rbac' not in file:
                    collected_items.append(file)
            else:
                if kw in file:
                    collected_items.append(file)
        return sorted(collected_items)

    collected_tests = filter_tests(keyword, rbac, t_list=test_list)
    print(f'Collected tests [{len(collected_tests)}]:')
    print('{}\n\n'.format(", ".join([t for t in collected_tests])))

    return collected_tests


def collect_non_excluded_tests():
    os.chdir(f'{TESTS_PATH}/{RESULTS_PATH}')
    done_tests = glob.glob(f'test_*')
    os.chdir(TESTS_PATH)
    collected_tests = sorted([test for test in glob.glob('test_*') if test.rstrip('.tavern.yaml') not in done_tests])
    print(f'Collected tests [{len(collected_tests)}]:')
    print('{}\n\n'.format(", ".join([t for t in collected_tests])))

    return collected_tests


def run_tests(collected_tests, n_iterations=1):
    os.chdir(TESTS_PATH)
    for test in collected_tests:
        for i in range(1, n_iterations + 1):
            iteration_info = f'[{i}/{n_iterations}]' if n_iterations > 1 else ''
            test_name = f'{test.rsplit(".")[0]}{i if i != 1 else ""}'
            print(f'{test} {iteration_info}')
            f = open(os.path.join(RESULTS_PATH, test_name), 'w')
            html_params = [f"--html={RESULTS_PATH}/html_reports/{test_name}.html", '--self-contained-html']
            subprocess.call(PYTEST_COMMAND.split(' ') + html_params + [test], stdout=f)
            f.close()
            get_results(filename=os.path.join(RESULTS_PATH, test_name))


def get_results(filename=None):
    if filename:
        calculate_result(filename)
    else:
        os.chdir(RESULTS_PATH)
        for file in sorted(glob.glob('test_*')):
            print(file)
            calculate_result(file)


def get_script_arguments():
    rbac_choices = ['both', 'yes', 'no']
    parser = argparse.ArgumentParser(usage="%(prog)s [options]",
                                     description="API integration tests",
                                     formatter_class=argparse.RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-l', '--list', dest='test_list', default=None,
                       help='Specify a list of tests separated by a comma.', action='store')
    group.add_argument('-e', '--exclude', dest='exclude', action='store_true', default=None,
                       help='Run every test excluding the already saved in the RESULTS_PATH.')
    group.add_argument('-r', '--results', dest='results', action='store_true', default=None,
                       help='Get result summary from the already run tests.')
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
    os.makedirs(os.path.join(TESTS_PATH, RESULTS_PATH, 'html_reports'), exist_ok=True)
    options = get_script_arguments()
    key = options.keyword
    tl = options.test_list
    exclude = options.exclude
    results = options.results
    rbac_arg = options.rbac
    iterations = options.iterations

    if results:
        get_results()
    else:
        tests = collect_non_excluded_tests() if exclude else collect_tests(test_list=tl, keyword=key, rbac=rbac_arg)
        run_tests(collected_tests=tests, n_iterations=iterations)
