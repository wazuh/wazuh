#!/usr/bin/python3

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import subprocess
import logging
import os
import contextlib
import re
import glob


BUILDDIR = '/build'
THREADS_DEFAULT = 4
DOXYGEN_TARGET = 'doc_doxygen'
MIN_LINES_COVERAGE_PERCENT=95.0
MIN_FUNCTIONS_COVERAGE_PERCENT=95.0

def log(outputdir, module, stdout, stderr):
    with open(outputdir + f'/{module}.stdout.log', 'w') as f:
        f.write(stdout.decode('utf-8'))
    with open(outputdir + f'/{module}.stderr.log', 'w') as f:
        f.write(stderr.decode('utf-8'))

def cppcheck(params):
    command = 'cppcheck'
    # Creating folder for cppcheck build
    os.makedirs(os.path.join(params.output, 'build', 'cppcheck-build'), exist_ok=True)
    args = f'--error-exitcode=1 --force {params.source}'
    args += f' --std=c++17 --enable=warning,style,performance,portability,unusedFunction --suppress=constParameterCallback '
    args += f' --cppcheck-build-dir={params.output}{BUILDDIR}/cppcheck-build '
    if params.exclude:
        abs_ignore = [os.path.join(params.source, path)
                      for path in params.exclude]
        args += f'-i {" -i ".join(abs_ignore)}'
    logging.debug(f'Executing {command} {args}')
    result = subprocess.run(
        f'{command} {args}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if result.returncode == 0 and not result.stderr:
        logging.info('CPPCHECK: successful')
    else:
        logging.info('CPPCHECK: fail')
        # TODO: we force the return code to 0 to allow the tool to continue
        result.returncode = 0
    log(params.output, 'cppcheck', result.stdout, result.stderr)
    return bool(not result.returncode)


def clangformat(params):
    file_extensions = ["*.cpp", "*.hpp"]
    find_extensions = f'-iname {" -o -iname ".join(file_extensions)}'
    if params.exclude:
        abs_ignore = [os.path.join(params.source, path)
                      for path in params.exclude]
        find_ignoredir = f'-path {" -o -path ".join(abs_ignore)}'
    find_cmd = f'find {params.source} -type f \( {find_extensions} \) -print -o \( {find_ignoredir} \) -prune'
    clangformat_dry_cmd = 'clang-format --dry-run -Werror -style=file -i'
    clangformat_cmd = 'clang-format -style=file -i'
    logging.debug(f'Executing {find_cmd} | xargs {clangformat_dry_cmd}')
    result = subprocess.run(f'{find_cmd} | xargs {clangformat_dry_cmd}',
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if not result.stderr and not result.stdout:
        logging.info('CLANG-FORMAT: successful')
    else:
        logging.info('CLANG-FORMAT: dry run fails.')
        # TODO: we force the return code to 0 to allow the tool to continue
        result.returncode = 0
        if params.fix:
            logging.info('CLANG-FORMAT: applying format')
            result = subprocess.run(f'{find_cmd} | xargs {clangformat_cmd}',
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            result.returncode = 0
    log(params.output, 'clangformat', result.stdout, result.stderr)
    return bool(not result.returncode)


def unittests(params):
    command = 'ctest'
    builddir = params.output + BUILDDIR
    args = f'--test-dir {builddir} --output-on-failure'
    logging.debug(f'Executing {command} {args}')
    # Creating directory tree for tests
    os.makedirs('/var/ossec', exist_ok=True)
    os.makedirs('/var/ossec/queue', exist_ok=True)
    os.makedirs('/var/ossec/queue/db', exist_ok=True)
    os.makedirs('/var/ossec/queue/alerts', exist_ok=True)

    result = subprocess.run(
        f'{command} {args}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if result.returncode == 0 and not result.stderr:
        logging.info('TESTING: successful')
    else:
        logging.info('TESTING: fail')
    log(params.output, 'unittests', result.stdout, result.stderr)
    return bool(not result.returncode)


def clean(params):
    command = 'make'
    builddir = params.output + BUILDDIR
    args = f'-C {builddir} clean'
    logging.debug(f'Executing {command} {args}')

    result = subprocess.run(
        f'{command} {args}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if result.returncode == 0 and not result.stderr:
        logging.info('Clean: successful')
    else:
        logging.info('Clean: fail')
    log(params.output, 'clean', result.stdout, result.stderr)
    return bool(not result.returncode)


def configure(params):
    # Removing cache file
    with contextlib.suppress(FileNotFoundError):
        os.remove(params.output + BUILDDIR + '/CMakeCache.txt')
    builddir = params.output + BUILDDIR
    configureOptions = ""
    if params.options:
        for opt in params.options:
            configureOptions += ' -D' + opt
    args = f'-B {builddir} -S {params.source} {configureOptions}'
    command = 'cmake'
    logging.debug(f'Executing {command} {args}')
    result = subprocess.run(
        f'{command} {args}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    log(builddir, 'configure', result.stdout, result.stderr)
    return bool(not result.returncode)


def build(params):
    builddir = params.output + BUILDDIR
    #Adding safe directory in case the user running the command is not root
    subprocess.run(f"git config --global --add safe.directory '*'", shell=True)
    if configure(params):
        if (params.threads):
            if (int(params.threads) > 0):
                global THREADS_DEFAULT
                THREADS_DEFAULT = params.threads
                logging.debug(f'Using {params.threads} threads for the building process')

        command = 'cmake'
        args = f'--build {builddir} -j{THREADS_DEFAULT}'
        logging.debug(f'Executing {command} {args}')
        result = subprocess.run(
            f'{command} {args}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if result.returncode == 0 and not result.stderr:
            logging.info('BUILDING: successful')
        else:
            logging.info('BUILDING: fail')
        log(params.output, 'build', result.stdout, result.stderr)
        return bool(not result.returncode)
    else:
        return False

def docs(params):
    command = 'make'
    args = f'-C {params.output}{BUILDDIR} {DOXYGEN_TARGET} -j{THREADS_DEFAULT}'
    logging.debug(f'Executing {command} {args}')
    # Creating a symbolic link to the source folder
    with contextlib.suppress(FileNotFoundError):
        os.remove(params.output + params.source)
    os.symlink(params.source, params.output + params.source, target_is_directory=True)
    result = subprocess.run(
        f'{command} {args}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, cwd=params.output)
    if result.returncode == 0 and not result.stderr:
        logging.info('DOXYGEN GENERATION: successful')
    else:
        logging.info('DOXYGEN GENERATION: fail')
        # TODO: we force the return code to 0 to allow the tool to continue
        result.returncode = 0
    log(params.output, 'docs', result.stdout, result.stderr)
    return bool(not result.returncode)


def clangtidy(params):
    builddir = params.output + BUILDDIR
    file_extensions = ["*.cpp", "*.hpp"]
    find_extensions = f'-iname {" -o -iname ".join(file_extensions)}'
    if params.exclude:
        abs_ignore = [os.path.join(params.source, path) for path in params.exclude]
        find_ignoredir = f'-path {" -o -path ".join(abs_ignore)}'
    find_cmd = f'find {params.source} -type f \( {find_extensions} \) -print -o \( {find_ignoredir} \) -prune '
    command = f' clang-tidy $({find_cmd}) -p {builddir} --extra-arg=-ferror-limit=0 --extra-arg=-std=c++1z ' \
              f' --extra-arg=-Wno-unused-function --extra-arg=-Wno-error=unused-command-line-argument --extra-arg=-header-filter=.'
    if params.fix:
        command += ' -fix-errors'
    logging.debug(f'Executing {command}')
    result = subprocess.run(f'{command}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

    if params.fix:
        logging.info('CLANG-TIDY: successful (fixes applied)')
    else:
        if result.stdout or result.returncode:
            logging.info('CLANG-TIDY: dry run fails')
            # TODO: we force the return code to 0 to allow the tool to continue
            result.returncode = 0
        else:
            logging.info('CLANG-TIDY: successful')

    log(params.output, 'clangtidy', result.stdout, result.stderr)
    return bool(not result.returncode)


def checkCoverage(output):

    success = True
    #######################
    # Test lines coverage #
    regexLines = re.search("lines.*(% ).*(lines)", str(output))
    if regexLines:
        end = regexLines.group().index('%')
        start = regexLines.group()[0:end].rindex(' ') + 1
        linesCoverage = regexLines.group()[start:end]

        if float(linesCoverage) >= MIN_LINES_COVERAGE_PERCENT:
            logging.info(f'LINES COVERAGE {linesCoverage}%: PASSED')
        else:
            logging.info(f'LINES COVERAGE {linesCoverage}%: LOW')
            success = False
    else:
        logging.info(f'Error (Coverage): No information about lines')

    ###########################
    # Test functions coverage #
    regexFunctions = re.search("functions.*%", str(output))
    if regexFunctions:
        end = regexFunctions.group().index('%')
        start = regexFunctions.group().rindex(' ') + 1
        functionsCoverage = regexFunctions.group()[start:end]

        if float(functionsCoverage) >= MIN_FUNCTIONS_COVERAGE_PERCENT:
            logging.info(f'FUNCTIONS COVERAGE {functionsCoverage}%: PASSED')
        else:
            logging.info(f'FUNCTIONS COVERAGE {functionsCoverage}%: LOW')
            success = False
    else:
        logging.info(f'Error (Coverage): No information about functions')

    return success

def coverage(params):
    # Prepare excluded files
    exclude = ''
    if params.exclude:
        for path in params.exclude:
            exclude += '--exclude="' + os.path.join(params.source, path)
            if not path.endswith('.cpp') and not path.endswith('.hpp'):
                exclude += '/*'
            exclude += '" '

    # Prepare included files
    include = ''
    if params.include:
        for path in params.include:
            include += '--include="' + os.path.join(params.source, path)
            if not path.endswith('.cpp') and not path.endswith('.hpp'):
                include += '/*'
            include += '" '

    builddir = params.output + BUILDDIR
    folders = ""

    # UT coverage
    cmakeFiles = os.path.join(builddir,'test/source/*/CMakeFiles/*.dir')
    for dir in glob.glob(cmakeFiles):
        folders += '--directory ' + dir + ' '

    reportDir = params.output + '/coverage'
    if not os.path.exists(reportDir):
        os.mkdir(reportDir)

    reportFile = reportDir + '/code_coverage.info'

    ########################
    # Generate LCOV report #
    command = f'lcov {folders} --capture --output-file {reportFile} {exclude} {include} -rc lcov_branch_coverage=0 --quiet'
    logging.debug(f'Executing: {command}')
    result = subprocess.run(
        f'{command}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, cwd=params.source)

    if result.returncode == 0:
        logging.info('COVERAGE - LCOV: successful')
    else:
        logging.info('COVERAGE - LCOV: fail')
        log(params.output, 'coverage', result.stdout, result.stderr)
        return bool(not result.returncode)

    log(params.output, 'coverage', result.stdout, result.stderr)

    ###############################
    # Get LCOV report information #
    command = f'genhtml --ignore-errors source {reportFile} --output-directory={reportDir}'
    logging.debug(f'Executing: {command}')
    result = subprocess.run(command, stdout=subprocess.PIPE, shell=True)

    if result.returncode == 0:
        logging.info('COVERAGE - GENHTML: successful')
    else:
        logging.info('COVERAGE - GENHTML: fail')
        log(params.output, 'coverage', result.stdout, result.stderr)
        return bool(not result.returncode)

    ########################
    return checkCoverage(result.stdout)
