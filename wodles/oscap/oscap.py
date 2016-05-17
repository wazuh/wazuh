#!/usr/bin/python
################################################################################
# Wazuh wrapper for OpenSCAP
# Wazuh Inc.
# May 12, 2016
################################################################################

from re import compile
from sys import argv, exit
from os.path import isfile
from tempfile import mkstemp
from xml.etree import ElementTree
from os import remove, close as close
from subprocess import call, CalledProcessError, STDOUT
from getopt import getopt, GetoptError
from signal import signal, SIGINT
import tempfile
import random
import string

OSCAP_BIN = "oscap"
PATTERN_HEAD = "Profiles:\n"
PATTERN_PROFILE = "(\t+)(\S+)\n"
OSCAP_LOG_ERROR = "oscap: ERROR:"
OSSEC_PATH = "/var/ossec"
POLICIES_PATH = "{0}/wodles/oscap/policies".format(OSSEC_PATH)

tempfile.tempdir = OSSEC_PATH + "/tmp"

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


def search_element_in_xml(xml_tree, element, idref):
    """
    Search element in XML
    :param xml_tree: XML
    :param element: 'severity' or 'idref'
    :param idref: rule ID
    :return: String
    """
    if not xml_tree:
        return None

    root = xml_tree.getroot()

    for reports in root.getchildren():
        if reports.tag.endswith("reports"):
            for report in reports.getchildren():
                content = report.getchildren()[0]
                testresult = content.getchildren()[0]

                # Reports -> Report -> Content -> TestResult
                if testresult.tag.endswith("TestResult"):
                    for item in testresult.getchildren():
                        # -> rule-result
                        # <rule-result idref="xccdf_org.ssgproject.content_rule_update_process" time="2016-05-09T06:42:40" severity="low" weight="1.000000">
                        if element == "severity" and item.tag.endswith("rule-result"):
                            attrib = item.attrib
                            if attrib["idref"] == idref:
                                if "severity" in attrib:
                                    return attrib["severity"]
                                else:
                                    return "n/a"

                        # -> score
                        # <score system="urn:xccdf:scoring:default" maximum="100.000000">56.835060</score>
                        if element == "score" and item.tag.endswith("score"):
                            if "maximum" in item.attrib:
                                max_score = item.attrib["maximum"]
                            else:
                                max_score = 0
                            return "\"{0}\" / \"{1}\"".format(item.text, max_score)


def extract_profiles_from_file(oscap_file):
    regex_head = compile(PATTERN_HEAD)
    regex_profile = compile(PATTERN_PROFILE)

    try:
        profiles_output = check_output([OSCAP_BIN, "info", oscap_file], stderr=STDOUT)
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


def exec_and_parse_oscap(profile_selected="no-profiles"):
    temp = mkstemp()
    close(temp[0])

    rand1 = temp[1].split("/")[-1][3:]
    rand2 = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(14))
    eval_id = rand1 + rand2

    try:
        cmd = [OSCAP_BIN, "xccdf", "eval", "--results-arf", temp[1]]

        if profile_selected != "no-profiles":
            cmd.extend(["--profile", profile_selected])
        if arg_xccdfid:
            for arg_id in arg_xccdfid:
                cmd.extend(["--xccdf-id", arg_id])
        if arg_dsid:
            for arg_id in arg_dsid:
                cmd.extend(["--datastream-id", arg_id])
        if arg_cpe:
            cmd.extend(["--cpe", arg_cpe])

        cmd.append(arg_policy)

        if debug:
            print("CMD:\n{0}\n".format(' '.join(cmd)))

        output = check_output(cmd, stderr=STDOUT)
    except CalledProcessError as error:

        # return code 2 means that some checks failed
        if error.returncode == 2:
            output = error.output
        else:
            # output = error.output
            print("{0} Executing profile \"{1}\" of file \"{2}\": Return Code: \"{3}\" Error: \"{4}\".".format(OSCAP_LOG_ERROR, profile_selected, arg_policy, error.returncode,
                                                                                                               error.output.replace('\r', '').split("\n")[0]))
            return

    # Open ARF XML results file
    try:
        tree = ElementTree.parse(temp[1])
    except IOError:
        if debug:
            print("oscap: Error reading temporary file \"{0}\".".format(temp[1]))
        tree = None
    except ElementTree.ParseError:
        if debug:
            print("oscap: Error parsing temporary file \"{0}\".".format(temp[1]))
        tree = None

    if not (tree or debug):
        print("{0} could not extract \"severity\" field from ARF XML results file.".format(OSCAP_LOG_ERROR))

    remove(temp[1])

    # Print check results
    severity_failed_rules = {'low': 0, 'medium': 0, 'high': 0, 'n/a': 0}

    ident = ""
    for line in output.replace('\r', '').splitlines():
        line = line.split('\t')

        if len(line) < 2:
            continue

        if line[0] == "Title":
            title = line[1].replace("\"", "")
            ident = ""
        elif line[0] == "Rule":
            rule = line[1].replace("\"", "")
        elif line[0] == "Ident":
            ident += line[1].replace("\"", "") + ", "
        elif line[0] == "Result":
            result = line[1].replace("\"", "")
            ident = ident[:-2]

            if tree:
                severity = search_element_in_xml(tree, "severity", rule)
            else:
                severity = "n/a"

            if result == "fail":
                severity_failed_rules[severity] += 1

            # Filters
            skip_line = False
            if (arg_result and result in arg_result) or (arg_severity and severity in arg_severity):
                skip_line = True

            if not skip_line:
                print("oscap: msg: \"rule-result\", id: \"{0}\", policy: \"{1}\", profile: \"{2}\", rule_id: \"{3}\", result: \"{4}\", title: \"{5}\", ident: \"{6}\", severity: \"{7}\".".format(eval_id,
                                                                                                                                                                                     policy_name,
                                                                                                                                                                                     profile_selected, rule,
                                                                                                                                                                                     result, title, ident,
                                                                                                                                                                                     severity))

            ident = ""
        else:
            print("{0} Unknown line: \"{1}\".".format(OSCAP_LOG_ERROR, line[0]))

    score = search_element_in_xml(tree, "score", None)

    msg_failed_r = ""
    for k in severity_failed_rules:
        msg_failed_r += "\"{0}\": \"{1}\", ".format(k, severity_failed_rules[k])

    print("oscap: msg: \"report-overview\", id: \"{0}\", policy: \"{1}\", profile: \"{2}\", score: {3}, severity of failed rules: {4}.".format(eval_id, policy_name, profile_selected, score, msg_failed_r[:-2]))


def signal_handler(n_signal, frame):
    print("\nExiting...({0})".format(n_signal))
    exit(1)


def usage():
    help_msg = '''
    Wazuh wrapper for OpenSCAP
    Perform evaluation of a policy (XCCDF or DataStrem file).

    Usage: oscap.py --policy file.xml [--profiles profileA,profileB --skip-result resultA,resultB --skip-severity severityA,severityB | --view-profiles] [--debug]

    Mandatory arguments
    \t-f, --policy           Select policty (SCAP content).

    Optional arguments:
    \t-p, --profiles       Select profile. Multiple profiles can be defined if separated by a comma.
    \t-r, --skip-result    Do not print rules with the specified result.
                             Values: pass, notchecked, notapplicable, fail, fixed, informational, error, unknown, notselected.
                             Multiple results can be defined if separated by a comma.
    \t-s, --skip-severity  Do not print rules with the specified severity.
                             Values: high, medium, low.
                             Multiple results can be defined if separated by a comma.
    \t-x, --xccdf-id       Select a particular XCCDF component.
    \t-d, --ds-id          Use a datastream with that particular ID from the given datastream collection.
    \t-c, --cpe            Use given CPE dictionary for applicability checks.


    Other arguments:
    \t-v, --view-profiles  Do not launch oscap. Only show extracted profiles.
    \t-d, --debug          Debug mode.
    \t-h, --help           Show help.

    '''
    print(help_msg)
    exit(1)


################################################################################

if __name__ == "__main__":
    arg_policy = None
    arg_profiles = None
    arg_result = None
    arg_severity = None
    arg_xccdfid = None
    arg_dsid = None
    arg_cpe = None
    arg_view_profiles = False
    debug = False
    mandatory_args = 0

    # Reading arguments
    try:
        opts, args = getopt(argv[1:], "f:p:r:s:x:d:c:vdh", ["policy=", "profiles=", "skip-result=", "skip-severity=", "xccdf-id=", "ds-id=", "cpe=", "view-profiles", "debug", "help"])
        n_args = len(opts)
        if not (1 <= n_args <= 5):
            print("Incorrect number of arguments.\nTry '--help' for more information.")
            exit(1)
    except GetoptError as err_args:
        print(str(err_args))
        print("Try '--help' for more information.")
        exit(1)

    for o, a in opts:
        if o in ("-f", "--policy"):
            if a[0] == '/' or a[0] == '.':
                arg_policy = a
            else:
                arg_policy = "{0}/{1}".format(POLICIES_PATH, a)
            mandatory_args += 1
        elif o in ("-p", "--profiles"):
            arg_profiles = a.split(",") if a != '_' else None
        elif o in ("-r", "--skip-result"):
            arg_result = a.split(",") if a != '_' else None
        elif o in ("-s", "--skip-severity"):
            arg_severity = a.split(",") if a != '_' else None
        elif o in ("-x", "--xccdf-id"):
            arg_xccdfid = a.split(",") if a != '_' else None
        elif o in ("-d", "--ds-id"):
            arg_dsid = a.split(",") if a != '_' else None
        elif o in ("-c", "--cpe"):
            if a[0] == '/' or a[0] == '.':
                arg_cpe = a
            else:
                arg_cpe = "{0}/{1}".format(POLICIES_PATH, a)
        elif o in ("-v", "--view-profiles"):
            arg_view_profiles = True
        elif o in ("-d", "--debug"):
            debug = True
        elif o in ("-h", "--help"):
            usage()
        else:
            exit(1)

    if debug:
        print("Arguments:\n\tPolicy: {0}\n\tProfiles: {1}\n\tskip-result: {2}\n\tskip-severity: {3}\n\txccdf-id: {4}\n\tds-id: {5}\n\tcpe: {6}\n\tview-profiles: {7}\n".format(arg_policy, arg_profiles,
                                                                                                                                                                               arg_result, arg_severity,
                                                                                                                                                                               arg_xccdfid, arg_dsid, arg_cpe,
                                                                                                                                                                               arg_view_profiles))
    if mandatory_args != 1:
        print("No argument '--policy'.\nTry '--help' for more information.")
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

    # Check policy
    if not isfile(arg_policy):
        print("{0} File \"{1}\" does not exist.".format(OSCAP_LOG_ERROR, arg_policy))
        exit(1)
    policy_name = arg_policy.split("/")[-1]

    # Get profiles
    profiles = extract_profiles_from_file(arg_policy)

    # Check profile argument
    if arg_profiles:
        for p in arg_profiles:
            if p not in profiles:
                print("{0} Profile \"{1}\" does not exist at \"{2}\".".format(OSCAP_LOG_ERROR, p, arg_policy))
                exit(1)

        profiles = arg_profiles

    # Execute checkings
    if profiles:
        for profile in profiles:
            if arg_view_profiles:
                print("\t{0}".format(profile))
                continue

            exec_and_parse_oscap(profile)
    else:
        exec_and_parse_oscap()
