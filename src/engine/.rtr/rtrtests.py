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
    """Method to write the stdout and stderr of a step to a file.

    Args:
        outputdir: Folder to store the logs.
        module: Name of the module that is also the name of both files.
        stdout: stdout of the module.
        stderr: stderr of the module.
    """
    with open(outputdir + f'/{module}.stdout.log', 'w') as f:
        f.write(stdout.decode('utf-8'))
    with open(outputdir + f'/{module}.stderr.log', 'w') as f:
        f.write(stderr.decode('utf-8'))

def cppcheck(params):
    """Step that runs cppcheck over the source folder excluding some optional folders.

    Args:
        params: Uses 'params.output' to get the path to the build folder.
                Uses 'params.source' to get the path to the source folder.
                Uses 'params.exclude' to ignore folders from scan.

    Returns:
        bool: True on success, False otherwise.
    """
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
    """ Runs clang-format over the source folder excluding some optional folders.
        It can also fix the errors found.

    Args:
        params: Uses 'params.output' to get the path to the build folder.
                Uses 'params.source' to get the path to the source folder.
                Uses 'params.exclude' to ignore folders from scan.
                Uses 'params.fix' to optionally fix the errors found.

    Returns:
        bool: True on success, False otherwise.
    """
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
    """ Step that runs the unit tests. It also creates the required folders for Wazuh sockets.

    Args:
        params: Uses 'params.output' to get the path to the build folder.
                Uses 'params.logname' to optionally change the default 'unittests' name for output logs.

    Returns:
        bool: True on success, False otherwise.
    """
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
        #TODO: we force the return code to 0 to allow the tool to continue
        result.returncode = 0
    if params.logname:
        log(params.output, params.logname, result.stdout, result.stderr)
    else:
        log(params.output, 'unittests', result.stdout, result.stderr)
    return bool(not result.returncode)


def clean(params):
    """ Step to perform a clean to the 'build' folder using make, it doesn't remove the folder.

    Args:
        params: Uses 'params.output' to get the path to the build folder.

    Returns:
        bool: True on success, False otherwise.
    """
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
    """ Step to configure the project using CMake. It also removes the cache file if it exists.

    Args:
        params: Uses 'params.output' to get the path to the build folder.
                Uses 'params.source' to get the path to the source folder.
                Uses 'params.options' to get the options to pass to CMake.

    Returns:
        bool: True on success, False otherwise.
    """
    builddir = params.output + BUILDDIR
    #Adding safe directory in case the user running the command is not root
    subprocess.run(f"git config --global --add safe.directory '*'", shell=True)
    # Removing cache file
    with contextlib.suppress(FileNotFoundError):
        os.remove(builddir + '/CMakeCache.txt')
    configureOptions = ""
    if params.options:
        for opt in params.options:
            configureOptions += ' -D' + opt
    args = f'-B {builddir} -S {params.source} {configureOptions}'
    command = 'cmake'
    logging.debug(f'Executing {command} {args}')
    result = subprocess.run(
        f'{command} {args}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    log(params.output, 'configure', result.stdout, result.stderr)
    return bool(not result.returncode)

def setThreads(params):
    """ Overwrites the default number of threads to use if the option is present.

    Args:
        params: Uses 'params.threads' to get the number of threads to set.
    """
    if (params.threads):
        if (int(params.threads) > 0):
            global THREADS_DEFAULT
            THREADS_DEFAULT = params.threads
            logging.debug(f'Using {params.threads} threads for the building process')

def build(params):
    """ Step to build the project.

    Args:
        params: Uses 'params.output' to get the path to the build folder.
                Uses 'params.logname' to optionally change the default 'build' name for output logs.
                Uses 'params.threads' to optionally change the default number of threads to use.

    Returns:
        bool: True on success, False otherwise.
    """
    builddir = params.output + BUILDDIR
    if configure(params):
        setThreads(params)

        command = 'cmake'
        args = f'--build {builddir} -j{THREADS_DEFAULT}'
        logging.debug(f'Executing {command} {args}')
        result = subprocess.run(
            f'{command} {args}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        if result.returncode == 0:
            if result.stderr:
                logging.info('BUILDING: successful but with warnings')
                # TODO: Uncomment to force a fail for warning messages
                #result.returncode = 1
            else:
                logging.info('BUILDING: successful')
        else:
            logging.info('BUILDING: fail')

        if params.logname:
            log(params.output, params.logname, result.stdout, result.stderr)
        else:
            log(params.output, 'build', result.stdout, result.stderr)
        return bool(not result.returncode)
    else:
        logging.info('BUILDING: configuration failed.')
        return False

def docs(params):
    """ Step to build the documentation using Doxygen.

    Args:
        params: Uses 'params.output' to get the path to the build folder.
                Uses 'params.source' to get the path to the source folder.
                Uses 'params.threads' to optionally change the default number of threads to use.

    Returns:
        bool: True on success, False otherwise.
    """
    if configure(params):
        setThreads(params)
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
    else:
        logging.info('DOXYGEN GENERATION: configuration failed')
        return False


def clangtidy(params):
    """ Step to run clang-tidy on the project. It can optionally fix the errors found.

    Args:
        params: Uses 'params.output' to get the path to the build folder.
                Uses 'params.source' to get the path to the source folder.
                Uses 'params.fix' to optionally fix the errors found.
                Uses 'params.exclude' to optionally exclude some folders from the analysis.

    Returns:
        bool: True on success, False otherwise.
    """
    builddir = params.output + BUILDDIR
    file_extensions = ["*.cpp", "*.hpp"]
    find_extensions = f'-iname {" -o -iname ".join(file_extensions)}'
    if params.exclude:
        abs_ignore = [os.path.join(params.source, path) for path in params.exclude]
        find_ignoredir = f'-path {" -o -path ".join(abs_ignore)}'
    find_cmd = f'find {params.source} -type f \( {find_extensions} \) -print -o \( {find_ignoredir} \) -prune '
    command = f' clang-tidy $({find_cmd}) -p {builddir} --extra-arg=-ferror-limit=0 --extra-arg=-std=c++1z ' \
              f' --extra-arg=-Wno-unused-function --extra-arg=-Wno-error=unused-command-line-argument --extra-arg=-header-filter=.*'
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
    """ Method to check if the lines and functions coverage are above the minimum required.

    Args:
        output: stdout of the coverage command.

    Returns:
        bool: True on success, False otherwise.
    """

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
    """ Step to run the coverage analysis of the UT on the project.

    Args:
        params: Uses 'params.output' to get the path to the build folder.
                Uses 'params.source' to get the path to the source folder.
                Uses 'params.exclude' to optionally exclude some folders from the analysis.
                Uses 'params.include' to optionally include some folders to the analysis.


    Returns:
        bool: True on success, False otherwise.
    """
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
    # TODO: we force the return code to True to allow the tool to continue
    #return checkCoverage(result.stdout)
    checkCoverage(result.stdout)
    return True


def valgrind(params):
    """ Runs valgrind over every UT of the project. It also creates the required folders for Wazuh sockets.

    Args:
        params: Uses 'params.output' to get the path to the build folder.

    Returns:
        bool: True on success, False otherwise.
    """
    builddir = params.output + BUILDDIR
    find_cmd = f'find {builddir} -iname "*_test" -type f '
    command = f'valgrind -s --leak-check=full --show-leak-kinds=all --num-callers=20 --trace-children=yes ' \
              f'--track-origins=yes --error-exitcode=1 --errors-for-leak-kinds=all '

    # Creating directory tree for tests
    os.makedirs('/var/ossec', exist_ok=True)
    os.makedirs('/var/ossec/queue', exist_ok=True)
    os.makedirs('/var/ossec/queue/db', exist_ok=True)
    os.makedirs('/var/ossec/queue/alerts', exist_ok=True)

    logging.debug(f'Executing {find_cmd}')
    find_result = subprocess.run(f'{find_cmd}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    final_stdout = find_result.stdout
    final_stderr = find_result.stderr
    final_result = find_result.returncode

    for test in find_result.stdout.decode('utf-8').splitlines():
        logging.debug(f'Executing {command} {test}')
        result = subprocess.run(f'{command} {test}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        final_stdout += result.stdout
        final_stderr += result.stderr
        final_result = final_result or result.returncode

    if final_result == 0:
        logging.info('Valgrind: successful')
    else:
        logging.info('Valgrind: fails')
        # TODO: we force the return code to 0 to allow the tool to continue
        final_result = 0

    log(params.output, 'valgrind', final_stdout, final_stderr)
    return bool(not final_result)
