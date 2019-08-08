/*
 * SQL schema for Vulnerability Detector tests
 * Copyright (C) 2015-2019, Wazuh Inc.
 * July 29, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE IF NOT EXISTS VULNERABILITIES_INFO (
        ID TEXT NOT NULL,
        TITLE TEXT,
        SEVERITY TEXT,
        PUBLISHED TEXT,
        UPDATED TEXT,
        REFERENCE TEXT,
        OS TEXT NOT NULL,
        RATIONALE TEXT,
        CVSS TEXT,
        CVSS_VECTOR TEXT,
        CVSS3 TEXT,
        BUGZILLA_REFERENCE TEXT,
        CWE TEXT,
        ADVISORIES TEXT,
        PRIMARY KEY(ID, OS)
);

INSERT INTO VULNERABILITIES_INFO(ID, TITLE, SEVERITY, PUBLISHED, UPDATED, REFERENCE, OS, RATIONALE, CVSS, CVSS_VECTOR, CVSS3, BUGZILLA_REFERENCE, CWE, ADVISORIES) VALUES
    ('CVE-2019-9959', 'CVE-2019-9959', 'Low', '2019-07-22', '', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9959', 'BIONIC', "The JPXStream::init function in Poppler 0.78.0 and earlier doesn't check for negative values of stream length, leading to an Integer Overflow, thereby making it possible to allocate a large memory chunk on the heap, with a size controlled by an attacker, as demonstrated by pdftocairo.", '', '', '', '', '', ''),
    ('CVE-2019-9956', 'CVE-2019-9956 on Ubuntu 18.04 LTS (bionic) - medium.', 'Medium', '2019-03-23', '', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9956', 'BIONIC', "In ImageMagick 7.0.8-35 Q16, there is a stack-based buffer overflow in the function PopHexPixel of coders/ps.c, which allows an attacker to cause a denial of service or code execution via a crafted image file.", '', '', '', '', '', ''),    ('CVE-2019-9948', 'CVE-2019-9948 on Ubuntu 18.04 LTS (bionic) - medium.', 'Medium', '2019-03-23', '', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9948', 'BIONIC', "urllib in Python 2.x through 2.7.16 supports the local_file: scheme, which makes it easier for remote attackers to bypass protection mechanisms that blacklist file: URIs, as demonstrated by triggering a urllib.urlopen('local_file:///etc/passwd') call.", '', '', '', '', '', ''),
    ('CVE-2019-9948', '', 'moderate', '2019-03-23T00:00:00+00:00', '', 'https://access.redhat.com/security/cve/CVE-2019-9948', 'REDHAT', "python: Undocumented local_file protocol allows remote attackers to bypass protection mechanisms", '', '', '7.400000', 'https://bugzilla.redhat.com/show_bug.cgi?id=1695570', 'CWE-749', 'RHSA-2019:1700'),
    ('CVE-2019-9947', 'CVE-2019-9947 on Ubuntu 18.04 LTS (bionic) - medium.', 'Medium', '2019-03-23', '', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9947', 'BIONIC', "An issue was discovered in urllib2 in Python 2.x through 2.7.16 and urllib in Python 3.x through 3.7.3. CRLF injection is possible if the attacker controls a url parameter, as demonstrated by the first argument to urllib.request.urlopen with \r\n (specifically in the path component of a URL that lacks a ? character) followed by an HTTP header or a Redis command. This is similar to the CVE-2019-9740 query string issue.", '', '', '', '', '', ''),
    ('CVE-2019-9947', '', 'moderate', '2019-03-23T00:00:00+00:00', '', 'https://access.redhat.com/security/cve/CVE-2019-9947', 'REDHAT', "python: CRLF injection via the path part of the url passed to urlopen()", '', '', '6.500000', 'https://bugzilla.redhat.com/show_bug.cgi?id=1695572', 'CWE-113', 'RHSA-2019:1260');

CREATE TABLE IF NOT EXISTS VULNERABILITIES (
        CVEID TEXT NOT NULL REFERENCES VULNERABILITIES_INFO(ID),
        OS TEXT NOT NULL REFERENCES VULNERABILITIES_INFO(V_OS),
        OS_MINOR TEXT,
        PACKAGE TEXT NOT NULL,
        PENDING BOOLEAN NOT NULL,
        OPERATION TEXT NOT NULL,
        OPERATION_VALUE TEXT,
        CHECK_VARS INTEGER DEFAULT 0,
        PRIMARY KEY(CVEID, OS, PACKAGE, OPERATION_VALUE)
);

INSERT INTO VULNERABILITIES(CVEID, OS, OS_MINOR, PACKAGE, PENDING, OPERATION, OPERATION_VALUE, CHECK_VARS) VALUES
    ('CVE-2019-9948', 'STRETCH', '', 'python2.7', '0', 'less than', '0:0', '0'),
    ('CVE-2019-9948', 'RHEL7', '', 'python27-python', '0', 'less than', '2.7.16-6.el7', '0'),
    ('CVE-2019-9948', 'RHEL6', '', 'python27-python', '0', 'less than', '2.7.16-6.el6', '0'),
    ('CVE-2019-9947', 'STRETCH', '', 'python2.7', '0', 'less than', '0:0', '0'),
    ('CVE-2019-9947', 'RHEL7', '', 'python27-python', '0', 'less than', '2.7.16-4.el7', '0'),
    ('CVE-2019-9947', 'RHEL6', '', 'python27-python', '0', 'less than', '2.7.16-4.el6', '0'),
    ('CVE-2019-9956', 'BIONIC', '', 'oval:com.ubuntu.bionic:var:2017131440000000', '0', 'less than', '8:6.9.7.4+dfsg-16ubuntu6.7', '1'),
    ('CVE-2019-9956', 'STRETCH', '', 'imagemagick', '0', 'less than', '0:8:6.9.7.4+dfsg-11+deb9u7', '0');
