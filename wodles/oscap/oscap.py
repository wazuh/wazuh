#!/usr/bin/env python
################################################################################
# Wazuh wrapper for OpenSCAP
# Wazuh Inc.
# Oct 25, 2016
################################################################################

from __future__ import print_function
from re import compile
import re
from sys import argv, exit, version_info
from os.path import isfile, isdir
from os import mkfifo, unlink, devnull
from subprocess import CalledProcessError, STDOUT, Popen, PIPE
from getopt import getopt, GetoptError
from signal import signal, SIGINT
from random import randrange
from time import time
import xml.sax
import lxml.sax

OSCAP_BIN = "oscap"
XSLT_BIN = "xsltproc"
PATTERN_HEAD = "Profiles:\n"
PATTERN_PROFILE = "(\t+)(\S+)\n"
PATTERN_ID_PROFILE = "\t+Id:\s(\S+)\n"
OSCAP_LOG_ERROR = "oscap: ERROR:"
TEMPLATE_XCCDF = "wodles/oscap/template_xccdf.xsl"
CONTENT_PATH = "wodles/oscap/content"
FIFO_PATH = "wodles/oscap/oscap.fifo"

def check_installed(arguments, stdin=None, stderr=None, shell=False):

    ps = Popen(arguments,shell=shell, stdin=None, stdout=PIPE, stderr=STDOUT)
    cmd_output = ps.communicate()[0]
    returncode = ps.returncode

    if returncode != 0:
        error_cmd = CalledProcessError(returncode, arguments[0])
        error_cmd.output = cmd_output
        raise error_cmd
    else:
        return cmd_output

if version_info[0] >= 3:
    import sys
    sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf8', buffering=1)

################################################################################

def extract_profiles_from_file(oscap_file):
    regex_head = compile(PATTERN_HEAD)
    regex_profile = compile(PATTERN_PROFILE)
    regex_id_profile = compile(PATTERN_ID_PROFILE)

    try:
        profiles_output = check_installed([OSCAP_BIN, "info", oscap_file], stderr=STDOUT)
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

    # Extract profiles (> v1.2.15)

    match_id_profile = regex_id_profile.search(profiles_output)

    if match_id_profile:
        ex_profiles = regex_id_profile.findall(profiles_output)
        return ex_profiles

    # Extract profiles (< v1.2.15)

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


def process_oval(in_file, out_file, scan_id, content_filename):

    class Handler(xml.sax.ContentHandler):

        def __init__(self):
            xml.sax.ContentHandler.__init__(self)
            self.total = 0
            self.total_KO = 0
            self.definitions = {}
            self.handler = None
            self.parsing_definitions = False
            self.parsing_results = False
            self.prefix = ('oscap: msg: "oval-result", '
                           'scan-id: "{scan_id}", '
                           'content: "{content}", ').format(
                               scan_id=scan_id,
                               content=content_filename)

        def startElementNS(self, name, qname, attrs):
            (ns, localname) = name
            if self.parsing_definitions or self.parsing_results:

                if localname == 'definition':
                    self.handler = lxml.sax.ElementTreeContentHandler()
                if self.handler:
                    self.handler.startElementNS(name, qname, attrs)

            if localname == 'oval_definitions':
                self.parsing_definitions = True
            elif localname == 'results':
                self.parsing_results = True

        def characters(self, contents):
            if (self.parsing_definitions or self.parsing_results) and self.handler:
                self.handler.characters(contents)

        def endElementNS(self, name, qname):
            (ns, localname) = name
            if localname == 'oval_definitions':
                self.parsing_definitions = False

            if localname == 'results':
                self.parsing_results = False

            if self.parsing_results:
                if self.handler:
                    self.handler.endElementNS(name, qname)
                if localname == 'definition':
                    t = self.handler.etree.getroot()
                    c, definition = self.definitions[t.get('definition_id')]
                    result = t.get('result')
                    self.total += 1
                    if c in ('compliance', 'inventory'):
                        if result == 'false':
                            self.total_KO += 1
                            result = 'fail'
                        elif result == 'true':
                            result = 'pass'
                    elif c in ('vulnerability', 'patch'):
                        if result == 'true':
                            self.total_KO += 1
                            result = 'fail'
                        elif result == 'false':
                            result = 'pass'
                    s = definition.replace('%%RESULT%%', result)
                    s = self.prefix + s.replace("\n", " ")
                    s = re.sub(r'\s+', ' ', s)
                    print(s, file=out_file)
                    self.handler = None

            if self.parsing_definitions:
                if self.handler:
                    self.handler.endElementNS(name, qname)
                if localname == 'definition':
                    t = self.handler.etree.getroot()
                    ns0 = t.nsmap
                    metadata = t.find('ns0:metadata', ns0)
                    references = []
                    for reference in metadata.findall('ns0:reference', ns0):
                        references.append("{ref_id} ({ref_url})".format(
                            ref_id=reference.get('ref_id'),
                            ref_url=reference.get('ref_url')))
                    s = ('title: "{title}", '
                         'id: "{id}", '
                         'result: "%%RESULT%%", '
                         'description: "{description}", '
                         'profile-title: "{c}", '
                         'reference: "{references}".').format(
                        title=metadata.find('ns0:title', ns0).text,
                        description=metadata.find('ns0:description', ns0).text or '',
                        references=",".join(references),
                        id=t.get('id'),
                        c=t.get('class'))
                    self.definitions[t.get('id')] = (t.get('class'), s)
                    self.handler = None

    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_namespaces, True)
    parser.setFeature(xml.sax.handler.feature_validation, False)
    parser.setFeature(xml.sax.handler.feature_external_ges, False)
    handler = Handler()
    parser.setContentHandler(handler)
    parser.parse(in_file)
    score = (float((handler.total-handler.total_KO))/float(handler.total)) * 100
    print('oscap: msg: "oval-overview", scan-id: "{0}", content: "{1}", score: "{2:.2f}".'.format(
        scan_id, content_filename, score), file=out_file)


def oscap(profile=None):

    # If FIFO exists, delete it
    try:
        unlink(FIFO_PATH)
    except OSError:
        pass

    # Create an unique FIFO file
    mkfifo(FIFO_PATH, 0666)

    try:
        cmd = [OSCAP_BIN, arg_module, 'eval', '--results', FIFO_PATH]

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

        DEVNULL = open(devnull, 'wb')
        ps = Popen(cmd, shell=False, stdout=DEVNULL, stderr=None)

    except CalledProcessError as error:

        # return code 2 means that some checks failed
        if error.returncode != 2:
            # output = error.output
            print("{0} Executing profile \"{1}\" of file \"{2}\": Return Code: \"{3}\" Error: \"{4}\".".format(OSCAP_LOG_ERROR, profile, arg_file, error.returncode,
                                                                                                               error.output.replace('\r', '').split("\n")[0]))
            unlink(FIFO_PATH)
            return

    try:
        content_filename = arg_file.split('/')[-1]

        # Generate scan ID: agent_id + epoch
        try:
            if isdir('ruleset'):
                agent_id = '000'
            else:
                with open('etc/client.keys', 'r') as f:
                    first_line = f.readline()
                agent_id = first_line.split(' ')[0]
        except:
            agent_id = randrange(1, 9999)

        scan_id = "{0}{1}".format(agent_id, int(time()))

        if arg_module == 'xccdf':

            ps_xsltproc = Popen([XSLT_BIN, TEMPLATE_XCCDF, FIFO_PATH], stdin=None, stdout=PIPE, stderr=STDOUT)
            ps.wait()
            output = ps_xsltproc.communicate()[0]
            ps_xsltproc.wait()
            returncode = ps_xsltproc.returncode


            if returncode != 0:
                error_cmd = CalledProcessError(returncode, [XSLT_BIN, TEMPLATE_XCCDF, FIFO_PATH])
                error_cmd.output = output
                raise error_cmd
            else:

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

            process_oval(FIFO_PATH, sys.stdout, scan_id, content_filename)

    except CalledProcessError as error:
        print("{0} Formatting data for profile \"{1}\" of file \"{2}\": Return Code: \"{3}\" Error: \"{4}\".".format(OSCAP_LOG_ERROR, profile, arg_file, error.returncode,
                                                                                                           error.output.replace('\r', '').split("\n")[0]))

    unlink(FIFO_PATH)

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
        output_installed = check_installed([OSCAP_BIN, "-V"], stderr=STDOUT)
    except Exception as e:
        if "No such file or directory" in e:
            print("{0} OpenSCAP not installed. Details: {1}.".format(OSCAP_LOG_ERROR, e))
        else:
            print("{0} Impossible to execute OpenSCAP. Details: {1}.".format(OSCAP_LOG_ERROR, e))

        exit(2)

    # Check xsltproc installed
    try:
        output_installed = check_installed([XSLT_BIN, "-V"], stderr=STDOUT)

    except Exception as e:
        if "No such file or directory" in e:
            print("{0} xsltproc not installed. Details: {1}.".format(OSCAP_LOG_ERROR, e))
        else:
            print("{0} Impossible to execute xsltproc. Details: {1}.".format(OSCAP_LOG_ERROR, e))
        exit(2)


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
