#!/usr/bin/env python
################################################################################
# Wazuh wrapper for Vuls
# Wazuh Inc.
# Dec 19, 2017
################################################################################


from datetime import datetime
from socket import socket, AF_UNIX, SOCK_DGRAM
from subprocess import call
import json
import sys
import getopt

# Enable/disable debug mode
enable_debug = 0
# Wazuh installation path
wazuh_path = open('/etc/ossec-init.conf').readline().split('"')[1]
# Vuls installation path
vuls_path = '{0}/wodles/vuls'.format(wazuh_path)
# Wazuh queue
wazuh_queue = '{0}/queue/ossec/queue'.format(wazuh_path)
# Path to VULS logs
vuls_log = '{0}/logs/vuls/'.format(wazuh_path)
# Path to VULS binary
vuls_bin = '{0}/go/bin/vuls'.format(vuls_path)
# Path to CVE fetcher
cve_db_fetcher = '{0}/go/bin/go-cve-dictionary'.format(vuls_path)
# Path to OVAL fetcher
oval_db_fetcher = '{0}/go/bin/goval-dictionary'.format(vuls_path)
# Path to VULS config
vuls_config = '{0}/config.toml'.format(vuls_path)
# Path to CVE database
cve_db = '{0}/cve.sqlite3'.format(vuls_path)
# Path to OVAL database
oval_db = '{0}/oval.sqlite3'.format(vuls_path)

def help():
    print('vuls.py \n' \
    '           [--mincvss 5]               Minimum score to report.\n' \
    '           [--updatenvd]               Update NVD database.\n' \
    '           [--nvd-year 2002]           Year from which the CVE database will be downloaded.\n' \
    '           [--updaterh]                Update Redhat OVAL database.\n' \
    '           [--updateub]                Update Ubuntu OVAL database.\n' \
    '           [--updatedeb]               Update Debian OVAL database.\n' \
    '           [--updateorac]              Update Oracle OVAL database.\n' \
    '           [--autoupdate]              Oval database auto-update.\n' \
    '           [--os-version]              OS version for downloading the OVAL database.\n' \
    '           [--onlyupdate]              Only update databases.\n' \
    '           [--source <nvd|oval>]       CVE database preferred. The default will be the one that takes the highest CVSS.\n' \
    '           [--antiquity-limit 30]      Warn if vulnerability update date is less than X days.\n' \
    '           [--disable-package-info]    Disable packages info.\n' \
    '           [--debug]                   Debug mode.\n')

def extract_CVEinfo(cve, type):
    if type == 'nvd':
        source = 'National Vulnerability Database'
    elif type == 'redhat':
        source = 'RedHat OVAL'
    elif type == 'ubuntu':
            source = 'Ubuntu OVAL'
    elif type == 'debian':
            source = 'Debian OVAL'
    elif type == 'oracle':
            source = 'Oracle OVAL'
    else:
        print('Error: Invalid {0} type.'.format(type))
        sys.exit(1)

    link = cve['CveContents'][type]['SourceLink']
    last_modified = cve['CveContents'][type]['LastModified']
    tittle = cve['CveContents'][type]['Title']
    if tittle == '':
        tittle = cve['CveContents'][type]['CveID']
    return source, link, last_modified, tittle

def extract_CVEscore(cve, type):
    cvss2 = cve['CveContents'][type]['Cvss2Score']
    cvss3 = cve['CveContents'][type]['Cvss3Score']
    score = cvss2 if cvss2 > cvss3 else cvss3
    if score == 0 and cve['CveContents'][type]['Severity'] != '':
        severity = cve['CveContents'][type]['Severity']
        if severity == 'Critical':
            score = 10
        elif severity == 'High':
            score = 8.99
        elif severity == 'Medium':
            score = 6.99
        elif severity == 'Low':
            score = 3.99
        else:
            score = 1
    return score

def has_vector(cve, type):
    return type in cve['CveContents']

def change_vector(type, family):
    return family if type == 'nvd' else 'nvd'

def send_msg(wazuh_queue, header, msg):
    msg['integration'] = 'vuls'
    debug(json.dumps(msg, indent=4))
    formatted = {}
    formatted['vuls'] = msg
    formatted = '{0}{1}'.format(header, json.dumps(formatted))
    s = socket(AF_UNIX, SOCK_DGRAM)
    try:
        s.connect(wazuh_queue)
    except:
        print('Error: Wazuh must be running.')
        sys.exit(1)
    s.send(formatted.encode())
    s.close()

def debug(msg):
    if enable_debug:
        print(msg)

def update_oval(OS, update_os_version):
    global oval_db_fetcher
    global vuls_log
    global vuls_path

    if not update_os_version:
        print('Error: To update the OVAL database, the OS version must be attached with --os-version. You can do it automatically with --autoupdate.')
        sys.exit(1)
    debug('Updating {0} {1} OVAL database...'.format(OS, update_os_version))
    try:
        call([oval_db_fetcher, 'fetch-{0}'.format(OS), '-dbpath={0}/oval.sqlite3'.format(vuls_path), '-log-dir={0}'.format(vuls_log), update_os_version])
    except:
        print('Error: OVAL database could not be fetched.')
        sys.exit(1)
def update(update_nvd, update_rh, update_ub, update_deb, update_orac, os_name, update_os_version, nvd_year):
    if update_nvd:
        debug('Updating NVD database...')
        for i in range(nvd_year, (int(str(datetime.now()).split('-')[0]) + 1)):
            try:
                call([cve_db_fetcher, 'fetchnvd', '-dbpath={0}/cve.sqlite3'.format(vuls_path), '-log-dir={0}'.format(vuls_log), '-years', str(i)])
            except:
                print('Error: CVE database could not be fetched.')
                sys.exit(1)
    if update_rh or os_name == 'redhat':
        debug('Updating Redhat OVAL database...')
        update_oval('redhat', update_os_version) #5 6 7
    elif update_ub or os_name == 'ubuntu':
        debug('Updating Ubuntu OVAL database...')
        update_oval('ubuntu', update_os_version) #12 14 16
    elif update_deb or os_name == 'debian':
        debug('Updating Debian OVAL database...')
        update_oval('debian', update_os_version) #7 8 9 10
    elif update_orac or os_name == 'oracle':
        debug('Updating Oracle OVAL database...')
        update_oval('oracle', update_os_version) #5 6 7

def main(argv):

    # Minimum CVSS for reporting
    cvss_min = 0
    # CVSS source
    cvss_source=''
    # Message header
    header = '1:Wazuh-VULS:'
    # Notify message header
    notify_header = '9:rootcheck:'
    # Show packages info
    package_info = 1
    # Minimum antiquity
    antiquity_limit = 0
    # Update databases
    nvd_year = int(str(datetime.now()).split('-')[0]) - 10
    update_nvd = 0
    update_rh = 0
    update_ub = 0
    update_deb = 0
    update_orac = 0
    autoupdate = 0
    update_os_version = ''
    only_update = 0

    try:
        opts, args = getopt.getopt(argv,'h',["mincvss=","updatenvd", "nvd-year=", "updaterh", "updateub", "updatedeb", "updateorac", "autoupdate", "os-version=", "disable-package-info", "antiquity-limit=", "debug", "source=", "onlyupdate"])
    except getopt.GetoptError:
        help()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '--updatenvd':
            update_nvd = 1
        elif opt == '--nvd-year':
            nvd_year = int(arg)
        elif opt == '--updaterh':
            update_rh = 1
        elif opt == '--updateub':
            update_ub = 1
        elif opt == '--updatedeb':
            update_deb = 1
        elif opt == '--updateorac':
            update_orac = 1
        elif opt == '--autoupdate':
            autoupdate = 1
        elif opt == '--onlyupdate':
            only_update = 1
        elif opt == '--os-version':
            update_os_version = arg
        elif opt == '--disable-package-info':
            package_info = 0
        elif opt == '--antiquity-limit':
            antiquity_limit = int(arg)
        elif opt == '--mincvss':
            cvss_min = float(arg)
        elif opt == '--source':
            if arg == 'nvd' or arg == 'oval':
                cvss_source = arg
            else:
                help()
                sys.exit()
        elif opt == '--debug':
            global enable_debug
            enable_debug = 1
        elif opt == '-h':
            help()
            sys.exit()
        else:
            print('Error: Invalid parameter')
            help()
            sys.exit(1)

    update(update_nvd, update_rh, update_ub, update_deb, update_orac, '', update_os_version, nvd_year)

    if not only_update:
        msg = {}
        msg['event'] = 'Starting vulnerability scan.'
        send_msg(wazuh_queue, notify_header, msg)

        try:
            call([vuls_bin, 'scan', '-results-dir={0}'.format(vuls_log), '-config={0}'.format(vuls_config), '-log-dir={0}'.format(vuls_log)])
        except:
            print('Error: Could not launch a Vuls scan.')
            sys.exit(1)
        try:
            call([vuls_bin, 'report', '-format-json', '-ignore-unscored-cves', '-results-dir={0}'.format(vuls_log), '-cvedb-path={0}'.format(cve_db), '-ovaldb-path={0}'.format(oval_db), '-config={0}'.format(vuls_config), '-log-dir={0}'.format(vuls_log)])
        except:
            print('Error: Could not launch a Vuls report.')
            sys.exit(1)
    elif not autoupdate:
        sys.exit(0)

    # Load JSON report
    try:
        data = json.load(open('{0}/current/localhost.json'.format(vuls_log)))
    except:
        print('Error: You must run at least a scan before.')
        sys.exit(1)
    date = data['ScannedAt'].split('.')[0].replace('T', ' ')
    os_family = data['Family'].lower()
    family = (os_family if os_family != 'centos' else 'redhat').lower()
    cvss_source = family if cvss_source == 'oval' else cvss_source
    os_release = data['Release']
    kernel = data['RunningKernel']['Release']

    if autoupdate:
        update(0, 0, 0, 0, 0, family, os_release.split('.')[0].split('-')[0], nvd_year)

    if only_update:
        sys.exit(0)

    # Send scanned CVEs
    for c, cve in iter(data['ScannedCves'].items()):
        if cvss_source:
            source = cvss_source if has_vector(cve, cvss_source) else change_vector(cvss_source, family)
            score = extract_CVEscore(cve, source)
            source, link, last_modified, tittle = extract_CVEinfo(cve, source)
        else:
            # Higher
            nvd_score = extract_CVEscore(cve, 'nvd') if has_vector(cve, 'nvd') else -1
            nat_score = extract_CVEscore(cve, family) if has_vector(cve, family) else -1

            if nvd_score > nat_score:
                score = nvd_score
                source, link, last_modified, tittle = extract_CVEinfo(cve, 'nvd')
            else:
                score = nat_score
                source, link, last_modified, tittle = extract_CVEinfo(cve, family)

        if score < cvss_min:
            debug('\n{0} has a score lower than {1}. Skipping.'.format(cve['CveID'], cvss_min))
            continue

        msg = {}
        msg['scan_date'] = date
        msg['os_version'] = '{0} {1}'.format(os_family, os_release)
        msg['kernel_version'] = kernel
        msg['scanned_cve'] = cve['CveID']
        msg['tittle'] = tittle
        msg['assurance'] = '{0}%'.format(cve['Confidence']['Score'])
        msg['detection_method'] = cve['Confidence']['DetectionMethod']
        msg['score'] = score
        msg['source'] = source
        msg['link'] = link
        msg['last_modified'] = last_modified.split('.')[0].replace('T', ' ')[0:19]

        diff = (datetime.now() - datetime.strptime(msg['last_modified'], '%Y-%m-%d %H:%M:%S')).days
        if diff < antiquity_limit:
            msg['days'] = antiquity_limit
            msg['event'] = '{0} has a update date lower than {1} days.'.format(msg['scanned_cve'], antiquity_limit)
            send_msg(wazuh_queue, header, msg)
            del msg['days']
            del msg['event']

        if package_info:
            msg['affected_packages_info'] = {}
        # Look for affected packages
        for p in cve['AffectedPackages']:
            name = p['Name']
            package = data['Packages'][name]
            if package_info:
                msg['affected_packages_info'][name] = {}
                if package ['Version'] != '': msg['affected_packages_info'][name]['version'] = package['Version']
                if package ['Release'] != '': msg['affected_packages_info'][name]['release'] = package ['Release']
                if package ['NewVersion'] != '': msg['affected_packages_info'][name]['new_version'] = package ['NewVersion']
                if package ['NewRelease'] != '': msg['affected_packages_info'][name]['new_release'] = package ['NewRelease']
                if package ['Arch'] != '': msg['affected_packages_info'][name]['arch'] = package ['Arch']
                if package ['Repository'] != '': msg['affected_packages_info'][name]['repository'] = package ['Repository']
                if p ['NotFixedYet'] != '': msg['affected_packages_info'][name]['fixable'] = 'Yes' if p['NotFixedYet'] == False else 'No'
            if 'affected_packages' not in msg:
                msg['affected_packages'] = ''
            msg['affected_packages'] = '{0}{1} ({2}), '.format(msg['affected_packages'], name,  'Fixable' if p['NotFixedYet'] == False else 'Not fixable')

        msg['affected_packages'] = msg['affected_packages'][0:-2]

        send_msg(wazuh_queue, header, msg)

    msg = {}
    msg['event'] = 'Ending vulnerability scan.'
    send_msg(wazuh_queue, notify_header, msg)

if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except:
        print('Error: Cannot launch VULS.')
        sys.exit(1)
