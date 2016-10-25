#!/usr/bin/env python
################################################################################
# Wazuh wrapper for OpenSCAP
# Wazuh Inc.
# Oct 25, 2016
################################################################################

from re import compile
from sys import argv, exit, version_info
from os.path import isfile, exists
from tempfile import mkstemp
from xml.etree import ElementTree
from os import remove, close as close
from subprocess import call, CalledProcessError, STDOUT
from getopt import getopt, GetoptError
from signal import signal, SIGINT
from random import randrange
from time import time
import tempfile
import string

OSCAP_BIN = "oscap"
XSLT_BIN = "xsltproc"
PATTERN_HEAD = "Profiles:\n"
PATTERN_PROFILE = "(\t+)(\S+)\n"
OSCAP_LOG_ERROR = "oscap: ERROR:"
OSSEC_PATH = "/var/ossec"
TEMPLATE_XCCDF = "{0}/wodles/oscap/template_xccdf.xsl".format(OSSEC_PATH)
TEMPLATE_OVAL = "{0}/wodles/oscap/template_oval.xsl".format(OSSEC_PATH)
CONTENT_PATH = "{0}/wodles/oscap/content".format(OSSEC_PATH)

tempfile.tempdir = OSSEC_PATH + "/tmp"

if version_info[0] >= 3:
    import sys
    sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf8', buffering=1)

################################################################################

try:
    from subprocess import check_output
except ImportError:
    def check_output(arguments, stdin=None, stderr=None, shell=False):
        temp_f = mkstemp()
        returncode = call(arguments, stdin=stdin, stdout=temp_f[0], stderr=stderr, shell=shell)
        close(temp_f[0])
        file_o = open(temp_f[1], 'r')
        cmd_output = file_o.read()
        file_o.close()
        remove(temp_f[1])

        if returncode != 0:
            error_cmd = CalledProcessError(returncode, arguments[0])
            error_cmd.output = cmd_output
            raise error_cmd
        else:
            return cmd_output


def extract_profiles_from_file(oscap_file):
    regex_head = compile(PATTERN_HEAD)
    regex_profile = compile(PATTERN_PROFILE)

    try:
        profiles_output = check_output([OSCAP_BIN, "info", oscap_file], stderr=STDOUT)
        if version_info[0] >= 3:
            profiles_output = profiles_output.decode('utf-8', 'backslashreplace')
    except CalledProcessError as err:
        print("{0} Parsing file \"{1}\". Details: \"{2}\".".format(OSCAP_LOG_ERROR, oscap_file, err.output.replace('\r', '').split("\n")[0]))
        exit(1)

    # Find word "Profiles:"

    match_head = regex_head.search(profiles_output)

    if not match_head:
        if debug:
            print("oscap: No profiles at file \"{0}\".".format(oscap_file))
        return None

    # Extract profiles

    match_profile = regex_profile.match(profiles_output, match_head.end())

    if not match_profile:
        if debug:
            print("oscap: No profiles at file \"{0}\".".format(oscap_file))
        return None

    indent = match_profile.group(1)
    ex_profiles = [match_profile.group(2)]
    match_profile = regex_profile.match(profiles_output, match_profile.end())

    while match_profile and match_profile.group(1) == indent:
        ex_profiles.append(match_profile.group(2))
        match_profile = regex_profile.match(profiles_output, match_profile.end())

    return ex_profiles

def oscap(profile=None):
    temp = mkstemp()
    close(temp[0])

    try:
        cmd = [OSCAP_BIN, arg_module, 'eval', '--results', temp[1]]

        if profile:
            cmd.extend(["--profile", profile])
        if arg_xccdfid:
            for arg_id in arg_xccdfid:
                cmd.extend(["--xccdf-id", arg_id])
        if arg_ovalid:
            for arg_id in arg_ovalid:
                cmd.extend(["--oval-id", arg_id])
        if arg_dsid:
            for arg_id in arg_dsid:
                cmd.extend(["--datastream-id", arg_id])
        if arg_cpe:
            cmd.extend(["--cpe", arg_cpe])

        cmd.append(arg_file)

        if debug:
            print("\nCMD: '{0}'".format(' '.join(cmd)))

        check_output(cmd, stderr=STDOUT)

    except CalledProcessError as error:

        # return code 2 means that some checks failed
        if error.returncode != 2:
            # output = error.output
            print("{0} Executing profile \"{1}\" of file \"{2}\": Return Code: \"{3}\" Error: \"{4}\".".format(OSCAP_LOG_ERROR, profile, arg_file, error.returncode,
                                                                                                               error.output.replace('\r', '').split("\n")[0]))
            remove(temp[1])
            return

    try:
        content_filename = arg_file.split('/')[-1]

        # Generate scan ID: agent_id + epoch
        try:
            if exists('{0}/rules'.format(OSSEC_PATH)):
                agent_id = '000'
            else:
                with open('{0}/etc/client.keys'.format(OSSEC_PATH), 'r') as f:
                    first_line = f.readline()
                agent_id = first_line.split(' ')[0]
        except:
            agent_id = randrange(1, 9999)

        scan_id = "{0}{1}".format(agent_id, int(time()))

        if arg_module == 'xccdf':
            output = check_output((XSLT_BIN, TEMPLATE_XCCDF, temp[1]))
            if version_info[0] >= 3:
                output = output.decode('utf-8', 'backslashreplace')

            for line in output.split("\n"):
                if not line:
                    continue

                # Adding file
                if 'msg: "xccdf-overview"' in line:
                    new_line = line.replace('oscap: msg: "xccdf-overview",', 'oscap: msg: "xccdf-overview", scan-id: "{0}", content: "{1}",'.format(scan_id, content_filename))
                else:
                    new_line = line.replace('oscap: msg: "xccdf-result",', 'oscap: msg: "xccdf-result", scan-id: "{0}", content: "{1}",'.format(scan_id, content_filename))

                print(new_line)

        else:
            output = check_output((XSLT_BIN, TEMPLATE_OVAL, temp[1]))
            if version_info[0] >= 3:
                output = output.decode('utf-8', 'backslashreplace')

            total = 0
            total_KO = 0
            for line in output.split("\n"):
                if not line:
                    continue

                total += 1

                # Adding file
                new_line = line.replace('oscap: msg: "oval-result"', 'oscap: msg: "oval-result", scan-id: "{0}", content: "{1}"'.format(scan_id, content_filename))

                class1 = ['class: "compliance"', 'class: "patch"', 'class: "inventory"']
                class2 = ['class: "vulnerability"']

                if any(x in line for x in class1):
                    if 'result: "false"' in line:
                        total_KO += 1
                        new_line = new_line.replace('result: "false"', 'result: "fail"')
                    elif 'result: "true"' in line:
                        new_line = new_line.replace('result: "true"', 'result: "pass"')
                elif any(x in line for x in class2):
                    if 'result: "true"' in line:
                        total_KO += 1
                        new_line = new_line.replace('result: "true"', 'result: "fail"')
                    elif 'result: "false"' in line:
                        new_line = new_line.replace('result: "false"', 'result: "pass"')

                new_line = new_line.replace('", class: "', '", profile-title: "')

                print(new_line)

            score = (float((total-total_KO))/float(total)) * 100

            # summary
            print('oscap: msg: "oval-overview", scan-id: "{0}", content: "{1}", score: "{2:.2f}".'.format(scan_id, content_filename, score))

    except CalledProcessError as error:
        print("{0} Formatting data for profile \"{1}\" of file \"{2}\": Return Code: \"{3}\" Error: \"{4}\".".format(OSCAP_LOG_ERROR, profile, arg_file, error.returncode,
                                                                                                           error.output.replace('\r', '').split("\n")[0]))

    remove(temp[1])

def signal_handler(n_signal, frame):
    print("\nExiting...({0})".format(n_signal))
    exit(1)

def usage():
    help_msg = '''
    Wazuh wrapper for OpenSCAP
    Perform evaluation of a policy (XCCDF or DataStrem file).

    Usage: oscap.py --[xccdf|oval] file.xml [--profiles profileA,profileB | --view-profiles] [--debug]

    Mandatory arguments (one of them)
    \t-x, --xccdf           Select XCCDF content (XCCDF or DS file).
    \t-o, --oval            Select OVAL content.

    Optional arguments:
    \t-p, --profiles        Select XCCDF profile. Multiple profiles can be defined if separated by a comma.
    \t--xccdf-id            Select a particular XCCDF component.
    \t--oval-id             Select particular OVAL component.
    \t--ds-id               Use a datastream with that particular ID from the given datastream collection.
    \t--cpe                 Use given CPE dictionary for applicability checks.

    Other arguments:
    \t-v, --view-profiles  Do not launch oscap. Only show extracted profiles.
    \t-d, --debug          Debug mode.
    \t-h, --help           Show help.

    '''
    print(help_msg)
    exit(1)

################################################################################

if __name__ == "__main__":
    arg_file = None
    arg_profiles = None
    arg_xccdfid = None
    arg_ovalid = None
    arg_dsid = None
    arg_cpe = None
    arg_view_profiles = False
    debug = False
    arg_module = None

    # Reading arguments
    try:
        opts, args = getopt(argv[1:], "p:x:o:vdh", ["xccdf=", "oval=", "profiles=", "xccdf-id=", "oval-id=", "ds-id=", "cpe=", "view-profiles", "debug", "help"])
        n_args = len(opts)
        if not (1 <= n_args <= 5):
            print("Incorrect number of arguments.\nTry '--help' for more information.")
            exit(1)
    except GetoptError as err_args:
        print(str(err_args))
        print("Try '--help' for more information.")
        exit(1)

    for o, a in opts:
        if o in ("-x", "--xccdf"):
            if a[0] == '/' or a[0] == '.':
                arg_file = a
            else:
                arg_file = "{0}/{1}".format(CONTENT_PATH, a)
            arg_module = 'xccdf'
        elif o in ("-o", "--oval"):
            if a[0] == '/' or a[0] == '.':
                arg_file = a
            else:
                arg_file = "{0}/{1}".format(CONTENT_PATH, a)
            arg_module = 'oval'
        elif o in ("-p", "--profiles"):
            arg_profiles = a.split(",") if a != '_' else None
        elif o == "--xccdf-id":
            arg_xccdfid = a.split(",") if a != '_' else None
        elif o == "--oval-id":
            arg_ovalid = a.split(",") if a != '_' else None
        elif o == "--ds-id":
            arg_dsid = a.split(",") if a != '_' else None
        elif o == "--cpe":
            if a[0] == '/' or a[0] == '.':
                arg_cpe = a
            else:
                arg_cpe = "{0}/{1}".format(CONTENT_PATH, a)
        elif o in ("-v", "--view-profiles"):
            arg_view_profiles = True
        elif o in ("-d", "--debug"):
            debug = True
        elif o in ("-h", "--help"):
            usage()
        else:
            exit(1)

    if debug:
        print("Arguments:\n\tPolicy: {0}\n\tProfiles: {1}\n\txccdf-id: {2}\n\tds-id: {3}\n\tcpe: {4}\n\tview-profiles: {5}\n".format(arg_file, arg_profiles,
                                                                                                                                     arg_xccdfid, arg_dsid, arg_cpe,
                                                                                                                                     arg_view_profiles))
    if not arg_module:
        print("No argument '--xccdf' or '--oval'.\nTry '--help' for more information.")
        exit(1)

    # Capture Cntrl + C
    signal(SIGINT, signal_handler)

    # Check oscap installed
    try:
        output_installed = check_output([OSCAP_BIN, "-V"], stderr=STDOUT)
    except Exception as e:
        if "No such file or directory" in e:
            print("{0} OpenSCAP not installed. Details: {1}.".format(OSCAP_LOG_ERROR, e))
        else:
            print("{0} Impossible to execute OpenSCAP. Details: {1}.".format(OSCAP_LOG_ERROR, e))
        exit(1)

    # Check xsltproc installed
    try:
        output_installed = check_output([XSLT_BIN, "-V"], stderr=STDOUT)
    except Exception as e:
        if "No such file or directory" in e:
            print("{0} xsltproc not installed. Details: {1}.".format(OSCAP_LOG_ERROR, e))
        else:
            print("{0} Impossible to execute xsltproc. Details: {1}.".format(OSCAP_LOG_ERROR, e))
        exit(1)

    # Check policy
    if not isfile(arg_file):
        print("{0} File \"{1}\" does not exist.".format(OSCAP_LOG_ERROR, arg_file))
        exit(1)
    policy_name = arg_file.split("/")[-1]

    if arg_module == 'xccdf':
        # Check profile argument
        if arg_profiles:
            # Get profiles
            profiles = extract_profiles_from_file(arg_file)

            for p in arg_profiles:
                if p not in profiles:
                    print("{0} Profile \"{1}\" does not exist at \"{2}\".".format(OSCAP_LOG_ERROR, p, arg_file))
                    exit(1)

            profiles = arg_profiles
        else:
            # Get profiles
            profiles = extract_profiles_from_file(arg_file)
    else:
        profiles = None

    # Execute checkings
    if profiles:
        for profile in profiles:
            if arg_view_profiles:
                print("\t{0}".format(profile))
                continue

            oscap(profile)
    else:
        oscap()
