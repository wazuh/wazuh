#include <any>
#include <vector>

#include <json/json.hpp>

#include <gtest/gtest.h>
#include <hlp/hlp.hpp>

using namespace hlp;

TEST(parseXML, successDefault)
{
    const char* expression = "<_xml/xml>";
    const char* event =
        R"(<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" /><EventID>1100</EventID><Version>0</Version><Level TestAtt="value">4</Level><Task>103</Task><Opcode>0</Opcode><Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime="2019-11-07T10:37:04.2260925Z" /><EventRecordID>14257</EventRecordID><Correlation /><Execution ProcessID="1144" ThreadID="4532" /><Channel>Security</Channel><Computer>WIN-41OB2LO92CR.wlbeat.local</Computer><Security /></System><UserData><ServiceShutdown xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog" /></UserData></Event>)";
    JsonString expected {
        R"({"Event":{"@xmlns":"http://schemas.microsoft.com/win/2004/08/events/event","System":{"Provider":{"@Name":"Microsoft-Windows-Eventlog","@Guid":"{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"},"EventID":{"#text":"1100"},"Version":{"#text":"0"},"Level":{"#text":"4","@TestAtt":"value"},"Task":{"#text":"103"},"Opcode":{"#text":"0"},"Keywords":{"#text":"0x4020000000000000"},"TimeCreated":{"@SystemTime":"2019-11-07T10:37:04.2260925Z"},"EventRecordID":{"#text":"14257"},"Correlation":{},"Execution":{"@ProcessID":"1144","@ThreadID":"4532"},"Channel":{"#text":"Security"},"Computer":{"#text":"WIN-41OB2LO92CR.wlbeat.local"},"Security":{}},"UserData":{"ServiceShutdown":{"@xmlns":"http://manifests.microsoft.com/win/2004/08/windows/eventlog"}}}})"};

    ParserFn parseOp = getParserOp(expression);
    ParseResult result;
    bool ret = parseOp(event, result);
    ASSERT_TRUE(static_cast<bool>(ret));

    ASSERT_EQ(std::any_cast<json::Json>(result["_xml"]).str(), expected.jsonString);
}

TEST(parseXML, failureWrongXml)
{
    const char* expression = "<_xml/xml>";
    const char* event =
        R"(>Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" /><EventID>1100</EventID><Version>0</Version><Level TestAtt="value">4</Level><Task>103</Task><Opcode>0</Opcode><Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime="2019-11-07T10:37:04.2260925Z" /><EventRecordID>14257</EventRecordID><Correlation /><Execution ProcessID="1144" ThreadID="4532" /><Channel>Security</Channel><Computer>WIN-41OB2LO92CR.wlbeat.local</Computer><Security /></System><UserData><ServiceShutdown xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog" /></UserData></Event>)";

    ParserFn parseOp = getParserOp(expression);
    ParseResult result;
    bool ret = parseOp(event, result);
    ASSERT_FALSE(static_cast<bool>(ret));
}

TEST(parseXML, failureNotXml)
{
    const char* expression = "<_xml/xml>";
    const char* event =
        R"(3:[678] (someAgentName) any->/some/route:Some : random -> ([)] log )";

    ParserFn parseOp = getParserOp(expression);
    ParseResult result;
    bool ret = parseOp(event, result);
    ASSERT_FALSE(static_cast<bool>(ret));
}

TEST(parseXML, failureModuleNotSupported)
{
    const char* expression = "<_xml/xml/notsupported>";

    ASSERT_THROW(getParserOp(expression), std::runtime_error);
}

TEST(parseXML, failureMultipleArguments)
{
    const char* expression = "<_xml/xml/windows/other>";

    ASSERT_THROW(getParserOp(expression), std::runtime_error);
}

TEST(parseXML, successWinModule)
{
    const char* expression = "<_xml/xml/windows>";
    const char* event =
        R"(<EventData><Data Name='SubjectUserSid'>S-1-5-21-3541430928-2051711210-1391384369-1001</Data><Data Name='SubjectUserName'>vagrant</Data><Data Name='SubjectDomainName'>VAGRANT-2012-R2</Data><Data Name='SubjectLogonId'>0x1008e</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>bosch</Data><Data Name='TargetDomainName'>VAGRANT-2012-R2</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc0000064</Data><Data Name='LogonType'>2</Data><Data Name='LogonProcessName'>seclogo</Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>VAGRANT-2012-R2</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x344</Data><Data Name='ProcessName'>C:\\Windows\\System32\\svchost.exe</Data><Data Name='IpAddress'>::1</Data><Data Name='IpPort'>0</Data></EventData>)";
    JsonString expected {
        R"({"EventData":{"SubjectUserSid":"S-1-5-21-3541430928-2051711210-1391384369-1001","SubjectUserName":"vagrant","SubjectDomainName":"VAGRANT-2012-R2","SubjectLogonId":"0x1008e","TargetUserSid":"S-1-0-0","TargetUserName":"bosch","TargetDomainName":"VAGRANT-2012-R2","Status":"0xc000006d","FailureReason":"%%2313","SubStatus":"0xc0000064","LogonType":"2","LogonProcessName":"seclogo","AuthenticationPackageName":"Negotiate","WorkstationName":"VAGRANT-2012-R2","TransmittedServices":"-","LmPackageName":"-","KeyLength":"0","ProcessId":"0x344","ProcessName":"C:\\\\Windows\\\\System32\\\\svchost.exe","IpAddress":"::1","IpPort":"0"}})"};

    ParserFn parseOp = getParserOp(expression);
    ParseResult result;
    bool ret = parseOp(event, result);
    ASSERT_TRUE(static_cast<bool>(ret));
    ASSERT_EQ(std::any_cast<json::Json>(result["_xml"]).str(), expected.jsonString);
}
