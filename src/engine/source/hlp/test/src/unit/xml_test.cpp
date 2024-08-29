#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "xmlParser";
static const std::string TARGET = "/TargetField";

INSTANTIATE_TEST_SUITE_P(
    XmlBuild,
    HlpBuildTest,
    ::testing::Values(BuildT(FAILURE, getXMLParser, {NAME, TARGET, {}, {}}),
                      BuildT(FAILURE, getXMLParser, {NAME, TARGET, {}, {"windows"}}),
                      BuildT(SUCCESS, getXMLParser, {NAME, TARGET, {""}, {}}),
                      BuildT(SUCCESS, getXMLParser, {NAME, TARGET, {""}, {"windows"}}),
                      BuildT(FAILURE, getXMLParser, {NAME, TARGET, {""}, {"not_supported"}}),
                      BuildT(FAILURE, getXMLParser, {NAME, TARGET, {""}, {"windows", "unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    XmlParse,
    HlpParseTest,
    ::testing::Values(
        ParseT(
            SUCCESS,
            R"(<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider
Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"
/><EventID>1100</EventID><Version>0</Version><Level
TestAtt="value">4</Level><Task>103</Task><Opcode>0</Opcode><Keywords>0x4020000000000000</Keywords><TimeCreated
SystemTime="2019-11-07T10:37:04.2260925Z" /><EventRecordID>14257</EventRecordID><Correlation
/><Execution ProcessID="1144" ThreadID="4532"
/><Channel>Security</Channel><Computer>WIN-41OB2LO92CR.wlbeat.local</Computer><Security
/></System><UserData><ServiceShutdown
xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog" /></UserData></Event>)",
            j(fmt::format(
                R"({{"{}":{}}})",
                TARGET.substr(1),
                R"({"System":{"Provider":{"@Name":"Microsoft-Windows-Eventlog","@Guid":"{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"},"EventID":{"#text":"1100"},"Version":{"#text":"0"},"Level":{"#text":"4","@TestAtt":"value"},"Task":{"#text":"103"},"Opcode":{"#text":"0"},"Keywords":{"#text":"0x4020000000000000"},"TimeCreated":{"@SystemTime":"2019-11-07T10:37:04.2260925Z"},"EventRecordID":{"#text":"14257"},"Correlation":{},"Execution":{"@ProcessID":"1144","@ThreadID":"4532"},"Channel":{"#text":"Security"},"Computer":{"#text":"WIN-41OB2LO92CR.wlbeat.local"},"Security":{}},"UserData":{"ServiceShutdown":{"@xmlns":"http://manifests.microsoft.com/win/2004/08/windows/eventlog"}}})")),
            684,
            getXMLParser,
            {NAME, TARGET, {""}, {"windows"}}),
        ParseT(FAILURE,
               R"(>Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider
Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"
/><EventID>1100</EventID><Version>0</Version><Level
TestAtt="value">4</Level><Task>103</Task><Opcode>0</Opcode><Keywords>0x4020000000000000</Keywords><TimeCreated
SystemTime="2019-11-07T10:37:04.2260925Z" /><EventRecordID>14257</EventRecordID><Correlation
/><Execution ProcessID="1144" ThreadID="4532"
/><Channel>Security</Channel><Computer>WIN-41OB2LO92CR.wlbeat.local</Computer><Security
/></System><UserData><ServiceShutdown
xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog" /></UserData></Event>)",
               {},
               684,
               getXMLParser,
               {NAME, TARGET, {""}, {}}),
        ParseT(FAILURE,
               R"(3:[678] (someAgentName) any->/some/route:Some : random -> ([)] log )",
               {},
               67,
               getXMLParser,
               {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            R"(<EventData><Data
Name='SubjectUserSid'>S-1-5-21-3541430928-2051711210-1391384369-1001</Data><Data
Name='SubjectUserName'>vagrant</Data><Data
Name='SubjectDomainName'>VAGRANT-2012-R2</Data><Data Name='SubjectLogonId'>0x1008e</Data><Data
Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>bosch</Data><Data
Name='TargetDomainName'>VAGRANT-2012-R2</Data><Data Name='Status'>0xc000006d</Data><Data
Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data
Name='LogonType'>2</Data><Data Name='LogonProcessName'>seclogo</Data><Data
Name='AuthenticationPackageName'>Negotiate</Data><Data
Name='WorkstationName'>VAGRANT-2012-R2</Data><Data Name='TransmittedServices'>-</Data><Data
Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data
Name='ProcessId'>0x344</Data><Data
Name='ProcessName'>C:\\Windows\\System32\\svchost.exe</Data><Data
Name='IpAddress'>::1</Data><Data Name='IpPort'>0</Data></EventData>)",
            j(fmt::format(
                R"({{"{}":{}}})",
                TARGET.substr(1),
                R"({"EventData":{"SubjectUserSid":"S-1-5-21-3541430928-2051711210-1391384369-1001","SubjectUserName":"vagrant","SubjectDomainName":"VAGRANT-2012-R2","SubjectLogonId":"0x1008e","TargetUserSid":"S-1-0-0","TargetUserName":"bosch","TargetDomainName":"VAGRANT-2012-R2","Status":"0xc000006d","FailureReason":"%%2313","SubStatus":"0xc0000064","LogonType":"2","LogonProcessName":"seclogo","AuthenticationPackageName":"Negotiate","WorkstationName":"VAGRANT-2012-R2","TransmittedServices":"-","LmPackageName":"-","KeyLength":"0","ProcessId":"0x344","ProcessName":"C:\\\\Windows\\\\System32\\\\svchost.exe","IpAddress":"::1","IpPort":"0"}})")),
            942,
            getXMLParser,
            {NAME, TARGET, {""}, {"windows"}}),
        ParseT(
            SUCCESS,
            R"(<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="PowerShell"/>
        <EventID Qualifiers="0">800</EventID>
        <Level>4</Level>
        <Security/>
    </System>
    <EventData>
        <Data/>
        <Data>DetailSequence=1 DetailTotal=1 SequenceNumber=143 UserId=VAGRANT\\vagrant HostName=ConsoleHost HostVersion=5.1.17763.1007 CommandLine=</Data>
        <Data>CommandInvocation(Out-Default): 'Out-Default' ParameterBinding(Out-Default): name='InputObject'; value='Cannot find the Windows PowerShell data file 'ArchiveResources.psd1' in directory 'C:\\Wazuh\\', or in any parent culture directories.'</Data>
    </EventData>
</Event>)",
            j(fmt::format(
                R"({{"{}":{}}})",
                TARGET.substr(1),
                R"({"System":{"Provider":{"@Name":"PowerShell"},"EventID":{"#text":"800","@Qualifiers":"0"},"Level":{"#text":"4"},"Security":{}},"EventData":["","DetailSequence=1 DetailTotal=1 SequenceNumber=143 UserId=VAGRANT\\\\vagrant HostName=ConsoleHost HostVersion=5.1.17763.1007 CommandLine=","CommandInvocation(Out-Default): 'Out-Default' ParameterBinding(Out-Default): name='InputObject'; value='Cannot find the Windows PowerShell data file 'ArchiveResources.psd1' in directory 'C:\\\\Wazuh\\\\', or in any parent culture directories.'"]})")),
            700,
            getXMLParser,
            {NAME, TARGET, {""}, {"windows"}}),
        ParseT(SUCCESS,
               R"(<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
        <EventID>5379</EventID>
        <Version>0</Version>
        <Level>0</Level>
        <Task>13824</Task>
        <Opcode>0</Opcode>
        <Keywords>0x8020000000000000</Keywords>
        <TimeCreated SystemTime="2023-10-20T19:07:06.3037119Z" />
        <EventRecordID>15126</EventRecordID>
        <Correlation ActivityID="{b7339175-03a1-0002-9f91-33b7a103da01}" />
        <Execution ProcessID="732" ThreadID="836" />
        <Channel>Security</Channel>
        <Computer>WIN-8I36CR3738L</Computer>
        <Security />
    </System>
    <EventData>
        <Data/>
        <Data Name="SubjectUserSid">S-1-5-21-1790562928-1395264351-1667849124-1000</Data>
        <Data Name="SubjectUserName">vagrant</Data>
        <Data Name="SubjectDomainName">WIN-8I36CR3738L</Data>
        <Data Name="SubjectLogonId">0x3c978</Data>
        <Data Name="TargetName">MicrosoftAccount:user=02ieynqiohajpobc</Data>
        <Data Name="Type">0</Data>
        <Data Name="Type">0</Data>
        <Data Name="">0</Data>
        <Data/>
        <Data Name="asdasd" />
        <Data Name="CountOfCredentialsReturned">0</Data>
        <Data Name="ReadOperation">%%8100</Data>
        <Data Name="ReturnCode">3221226021</Data>
        <Data Name="ProcessCreationTime">2023-10-20T19:07:00.4462204Z</Data>
        <Data Name="ClientProcessId">5572</Data>
        <Data/>
    </EventData>
</Event>)",
               j(fmt::format(R"({{"{}":{}}})",
                             TARGET.substr(1),
                             R"({
  "Event": {
    "@xmlns": "http://schemas.microsoft.com/win/2004/08/events/event",
    "EventData": {
      "Data": [
        {},
        {
          "#text": "S-1-5-21-1790562928-1395264351-1667849124-1000",
          "@Name": "SubjectUserSid"
        },
        {
          "#text": "vagrant",
          "@Name": "SubjectUserName"
        },
        {
          "#text": "WIN-8I36CR3738L",
          "@Name": "SubjectDomainName"
        },
        {
          "#text": "0x3c978",
          "@Name": "SubjectLogonId"
        },
        {
          "#text": "MicrosoftAccount:user=02ieynqiohajpobc",
          "@Name": "TargetName"
        },
        {
          "#text": "0",
          "@Name": "Type"
        },
        {
          "#text": "0",
          "@Name": "Type"
        },
        {
          "#text": "0",
          "@Name": ""
        },
        {},
        {
          "@Name": "asdasd"
        },
        {
          "#text": "0",
          "@Name": "CountOfCredentialsReturned"
        },
        {
          "#text": "%%8100",
          "@Name": "ReadOperation"
        },
        {
          "#text": "3221226021",
          "@Name": "ReturnCode"
        },
        {
          "#text": "2023-10-20T19:07:00.4462204Z",
          "@Name": "ProcessCreationTime"
        },
        {
          "#text": "5572",
          "@Name": "ClientProcessId"
        },
        {}
      ]
    },
    "System": {
      "Channel": {
        "#text": "Security"
      },
      "Computer": {
        "#text": "WIN-8I36CR3738L"
      },
      "Correlation": {
        "@ActivityID": "{b7339175-03a1-0002-9f91-33b7a103da01}"
      },
      "EventID": {
        "#text": "5379"
      },
      "EventRecordID": {
        "#text": "15126"
      },
      "Execution": {
        "@ProcessID": "732",
        "@ThreadID": "836"
      },
      "Keywords": {
        "#text": "0x8020000000000000"
      },
      "Level": {
        "#text": "0"
      },
      "Opcode": {
        "#text": "0"
      },
      "Provider": {
        "@Guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        "@Name": "Microsoft-Windows-Security-Auditing"
      },
      "Security": {},
      "Task": {
        "#text": "13824"
      },
      "TimeCreated": {
        "@SystemTime": "2023-10-20T19:07:06.3037119Z"
      },
      "Version": {
        "#text": "0"
      }
    }
  }
}
)")),
               1573,
               getXMLParser,
               {NAME, TARGET, {""}})));
