import sh
import six
import oscap

def test_process_oval_realist():
    input = """\
<?xml version="1.0" encoding="UTF-8"?>
<oval_results xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns="http://oval.mitre.org/XMLSchema/oval-results-5" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-results-5 oval-results-schema.xsd http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd">
  <generator>
    <oval:product_name>cpe:/a:open-scap:oscap</oval:product_name>
  </generator>
  <directives>
    <definition_true reported="true" content="full"/>
    <definition_not_applicable reported="true" content="full"/>
  </directives>
  <oval_definitions xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:unix-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" xmlns:ind-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" xmlns:lin-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#independent independent-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#linux linux-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd">
    <generator>
      <oval:product_name>Debian</oval:product_name>
      <oval:timestamp>2017-10-31T07:40:47.188-04:00</oval:timestamp>
    </generator>
    <definitions>
      <definition id="oval:org.debian:def:20179998" version="1" class="vulnerability">
        <metadata>
          <title>CVE-2017-9998</title>
          <affected family="unix">
            <platform>Debian GNU/Linux 9</platform>
            <product>dwarfutils</product>
          </affected>
          <reference source="CVE" ref_id="CVE-2017-9998" ref_url="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9998"/>
          <description>The _dwarf_decode_s_leb128_chk function in dwarf_leb.c in libdwarf through 2017-06-28 allows remote attackers to cause a denial of service (Segmentation fault) via a crafted file.</description>
          <debian xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
          <date>2017-10-31</date>
          <moreinfo/>
        </debian>
        </metadata>
        <criteria comment="Release section">
          <criterion test_ref="oval:org.debian.oval:tst:1" comment="Debian 9 is installed"/>
          <criteria operator="OR" comment="Architecture section">
            <criteria comment="Architecture independent section">
              <criterion test_ref="oval:org.debian.oval:tst:2" comment="all architecture"/>
              <criterion test_ref="oval:org.debian.oval:tst:16247" comment="dwarfutils DPKG is earlier than 20161124-1+deb9u1"/>
            </criteria>
          </criteria>
        </criteria>
      </definition>
      <definition id="oval:org.debian:def:20179996" version="1" class="vulnerability">
        <metadata>
          <title>CVE-2017-9996</title>
          <affected family="unix">
            <platform>Debian GNU/Linux 9</platform>
            <product>ffmpeg</product>
          </affected>
          <reference source="CVE" ref_id="CVE-2017-9996" ref_url="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9996"/>
          <description>The cdxl_decode_frame function in libavcodec/cdxl.c in FFmpeg 2.8.x before 2.8.12, 3.0.x before 3.0.8, 3.1.x before 3.1.8, 3.2.x before 3.2.5, and 3.3.x before 3.3.1 does not exclude the CHUNKY format, which allows remote attackers to cause a denial of service (heap-based buffer overflow and application crash) or possibly have unspecified other impact via a crafted file.</description>
          <debian xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
          <date>2017-10-31</date>
          <moreinfo/>
        </debian>
        </metadata>
        <criteria comment="Release section">
          <criterion test_ref="oval:org.debian.oval:tst:1" comment="Debian 9 is installed"/>
          <criteria operator="OR" comment="Architecture section">
            <criteria comment="Architecture independent section">
              <criterion test_ref="oval:org.debian.oval:tst:2" comment="all architecture"/>
              <criterion test_ref="oval:org.debian.oval:tst:16246" comment="ffmpeg DPKG is earlier than 7:3.2.5-1"/>
            </criteria>
          </criteria>
        </criteria>
      </definition>
    </definitions>
  </oval_definitions>
  <results>
    <system>
      <definitions>
        <definition definition_id="oval:org.debian:def:20179998" result="false" version="1">
          <criteria operator="AND" result="false">
            <criterion test_ref="oval:org.debian.oval:tst:1" version="1" result="true"/>
            <criteria operator="OR" result="false">
              <criteria operator="AND" result="false">
                <criterion test_ref="oval:org.debian.oval:tst:2" version="1" result="true"/>
                <criterion test_ref="oval:org.debian.oval:tst:16247" version="1" result="false"/>
              </criteria>
            </criteria>
          </criteria>
        </definition>
        <definition definition_id="oval:org.debian:def:20179996" result="false" version="1">
          <criteria operator="AND" result="false">
            <criterion test_ref="oval:org.debian.oval:tst:1" version="1" result="true"/>
            <criteria operator="OR" result="false">
              <criteria operator="AND" result="false">
                <criterion test_ref="oval:org.debian.oval:tst:2" version="1" result="true"/>
                <criterion test_ref="oval:org.debian.oval:tst:16246" version="1" result="false"/>
              </criteria>
            </criteria>
          </criteria>
        </definition>
      </definitions>
    </system>
  </results>
</oval_results>
    """

    i = six.StringIO(input)
    o = six.StringIO()
    r = oscap.process_oval(i, o, 'SCAN_ID', 'CONTENT_FILENAME')
    lines = o.getvalue().strip().split("\n")
    assert len(lines) == 3
    assert lines[0] == 'oscap: msg: "oval-result", scan-id: "SCAN_ID", content: "CONTENT_FILENAME", title: "CVE-2017-9998", id: "oval:org.debian:def:20179998", result: "pass", description: "The _dwarf_decode_s_leb128_chk function in dwarf_leb.c in libdwarf through 2017-06-28 allows remote attackers to cause a denial of service (Segmentation fault) via a crafted file.", profile-title: "vulnerability", reference: "CVE-2017-9998 (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9998)".'
    assert lines[1] == 'oscap: msg: "oval-result", scan-id: "SCAN_ID", content: "CONTENT_FILENAME", title: "CVE-2017-9996", id: "oval:org.debian:def:20179996", result: "pass", description: "The cdxl_decode_frame function in libavcodec/cdxl.c in FFmpeg 2.8.x before 2.8.12, 3.0.x before 3.0.8, 3.1.x before 3.1.8, 3.2.x before 3.2.5, and 3.3.x before 3.3.1 does not exclude the CHUNKY format, which allows remote attackers to cause a denial of service (heap-based buffer overflow and application crash) or possibly have unspecified other impact via a crafted file.", profile-title: "vulnerability", reference: "CVE-2017-9996 (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9996)".'
    assert lines[2] == 'oscap: msg: "oval-overview", scan-id: "SCAN_ID", content: "CONTENT_FILENAME", score: "100.00".'

def test_process_oval_result_conversion():
    input = """\
<?xml version="1.0" encoding="UTF-8"?>
<oval_results xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns="http://oval.mitre.org/XMLSchema/oval-results-5" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-results-5 oval-results-schema.xsd http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd">
  <oval_definitions>
    <definitions>

      <definition id="oval:org.debian:def:VULNERABILITY" version="1" class="vulnerability">
        <metadata>
          <title>CVE-001</title>
          <reference source="CVE" ref_id="CVE-001" ref_url="URL-001"/>
          <description>DESCRIPTION VULNERABILITY 001</description>
        </metadata>
      </definition>

      <definition id="oval:org.debian:def:PATCH" version="1" class="patch">
        <metadata>
          <title>CVE-002</title>
          <reference source="CVE" ref_id="CVE-002" ref_url="URL-002"/>
          <description>DESCRIPTION PATCH 002</description>
        </metadata>
      </definition>

      <definition id="oval:org.debian:def:COMPLIANCE" version="1" class="compliance">
        <metadata>
          <title>CVE-003</title>
          <reference source="CVE" ref_id="CVE-003" ref_url="URL-003"/>
          <description>DESCRIPTION COMPLIANCE 003</description>
        </metadata>
      </definition>

      <definition id="oval:org.debian:def:INVENTORY" version="1" class="inventory">
        <metadata>
          <title>CVE-004</title>
          <reference source="CVE" ref_id="CVE-004" ref_url="URL-004"/>
          <description>DESCRIPTION INVENTORY 004</description>
        </metadata>
      </definition>
    </definitions>
  </oval_definitions>
  <results>
    <system>
      <definitions>
        <definition definition_id="oval:org.debian:def:VULNERABILITY" result="false" version="1"/>
        <definition definition_id="oval:org.debian:def:VULNERABILITY" result="true" version="1"/>
        <definition definition_id="oval:org.debian:def:PATCH" result="false" version="1"/>
        <definition definition_id="oval:org.debian:def:PATCH" result="true" version="1"/>
        <definition definition_id="oval:org.debian:def:COMPLIANCE" result="false" version="1"/>
        <definition definition_id="oval:org.debian:def:COMPLIANCE" result="true" version="1"/>
        <definition definition_id="oval:org.debian:def:INVENTORY" result="false" version="1"/>
        <definition definition_id="oval:org.debian:def:INVENTORY" result="true" version="1"/>
      </definitions>
    </system>
  </results>
</oval_results>
    """

    i = six.StringIO(input)
    o = six.StringIO()
    r = oscap.process_oval(i, o, 'SCAN_ID', 'CONTENT_FILENAME')
    lines = o.getvalue().strip().split("\n")
    assert len(lines) == 9
    assert lines[0] == 'oscap: msg: "oval-result", scan-id: "SCAN_ID", content: "CONTENT_FILENAME", title: "CVE-001", id: "oval:org.debian:def:VULNERABILITY", result: "pass", description: "DESCRIPTION VULNERABILITY 001", profile-title: "vulnerability", reference: "CVE-001 (URL-001)".'
    assert lines[1] == 'oscap: msg: "oval-result", scan-id: "SCAN_ID", content: "CONTENT_FILENAME", title: "CVE-001", id: "oval:org.debian:def:VULNERABILITY", result: "fail", description: "DESCRIPTION VULNERABILITY 001", profile-title: "vulnerability", reference: "CVE-001 (URL-001)".'
    assert lines[2] == 'oscap: msg: "oval-result", scan-id: "SCAN_ID", content: "CONTENT_FILENAME", title: "CVE-002", id: "oval:org.debian:def:PATCH", result: "pass", description: "DESCRIPTION PATCH 002", profile-title: "patch", reference: "CVE-002 (URL-002)".'
    assert lines[3] == 'oscap: msg: "oval-result", scan-id: "SCAN_ID", content: "CONTENT_FILENAME", title: "CVE-002", id: "oval:org.debian:def:PATCH", result: "fail", description: "DESCRIPTION PATCH 002", profile-title: "patch", reference: "CVE-002 (URL-002)".'
    assert lines[4] == 'oscap: msg: "oval-result", scan-id: "SCAN_ID", content: "CONTENT_FILENAME", title: "CVE-003", id: "oval:org.debian:def:COMPLIANCE", result: "fail", description: "DESCRIPTION COMPLIANCE 003", profile-title: "compliance", reference: "CVE-003 (URL-003)".'
    assert lines[5] == 'oscap: msg: "oval-result", scan-id: "SCAN_ID", content: "CONTENT_FILENAME", title: "CVE-003", id: "oval:org.debian:def:COMPLIANCE", result: "pass", description: "DESCRIPTION COMPLIANCE 003", profile-title: "compliance", reference: "CVE-003 (URL-003)".'
    assert lines[6] == 'oscap: msg: "oval-result", scan-id: "SCAN_ID", content: "CONTENT_FILENAME", title: "CVE-004", id: "oval:org.debian:def:INVENTORY", result: "fail", description: "DESCRIPTION INVENTORY 004", profile-title: "inventory", reference: "CVE-004 (URL-004)".'
    assert lines[7] == 'oscap: msg: "oval-result", scan-id: "SCAN_ID", content: "CONTENT_FILENAME", title: "CVE-004", id: "oval:org.debian:def:INVENTORY", result: "pass", description: "DESCRIPTION INVENTORY 004", profile-title: "inventory", reference: "CVE-004 (URL-004)".'
    assert lines[8] == 'oscap: msg: "oval-overview", scan-id: "SCAN_ID", content: "CONTENT_FILENAME", score: "50.00".'

def test_process_oval_xslt_compat():
    # to populate compat,
    # manually run oscap.py from master and output the result in compat/reference.out
    # manually run oscap and output the result in compat/oscap.out
    r = oscap.process_oval('compat/oscap.out', open('compat/lxml.out', 'w'), 'SCAN_ID', 'CONTENT_FILENAME')
    # cd compat ; xsltproc template_oval.xsl oscap.out > xslt.out
    sh.diff('-u', 'compat/reference.out', 'compat/lxml.out')
