#include <gtest/gtest.h>
#include "run_test.hpp"
#include <hlp/hlp.hpp>
#include <json/json.hpp>
#include <string>
#include <vector>

TEST(HLP2, XMLarser)
{
    auto fn = [](std::string in) -> json::Json {
        json::Json doc {in.c_str()};
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {
            R"(<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" /><EventID>1100</EventID><Version>0</Version><Level TestAtt="value">4</Level><Task>103</Task><Opcode>0</Opcode><Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime="2019-11-07T10:37:04.2260925Z" /><EventRecordID>14257</EventRecordID><Correlation /><Execution ProcessID="1144" ThreadID="4532" /><Channel>Security</Channel><Computer>WIN-41OB2LO92CR.wlbeat.local</Computer><Security /></System><UserData><ServiceShutdown xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog" /></UserData></Event>)",
            true,
            {},
            Options {},
            fn(R"({"Event":{"@xmlns":"http://schemas.microsoft.com/win/2004/08/events/event","System":{"Provider":{"@Name":"Microsoft-Windows-Eventlog","@Guid":"{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"},"EventID":{"#text":"1100"},"Version":{"#text":"0"},"Level":{"#text":"4","@TestAtt":"value"},"Task":{"#text":"103"},"Opcode":{"#text":"0"},"Keywords":{"#text":"0x4020000000000000"},"TimeCreated":{"@SystemTime":"2019-11-07T10:37:04.2260925Z"},"EventRecordID":{"#text":"14257"},"Correlation":{},"Execution":{"@ProcessID":"1144","@ThreadID":"4532"},"Channel":{"#text":"Security"},"Computer":{"#text":"WIN-41OB2LO92CR.wlbeat.local"},"Security":{}},"UserData":{"ServiceShutdown":{"@xmlns":"http://manifests.microsoft.com/win/2004/08/windows/eventlog"}}}})"),
            684},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getXMLParser);
    }
}
