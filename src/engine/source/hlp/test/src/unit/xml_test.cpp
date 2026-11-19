// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <pthread.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "hlp_test.hpp"

auto constexpr NAME = "xmlParser";
static const std::string TARGET = "/TargetField";

namespace
{
// Deep XML fixtures are generated; the expected events are asserted by path, never built with j() (capped at 256).

/// <e1>…<e{levels}>inner</e{levels}>…</e1>
std::string wrapXml(std::size_t levels, std::string_view inner)
{
    std::string xml;
    for (std::size_t level = 1; level <= levels; ++level)
    {
        xml += fmt::format("<e{}>", level);
    }
    xml += inner;
    for (auto level = levels; level > 0; --level)
    {
        xml += fmt::format("</e{}>", level);
    }
    return xml;
}

/// Markup of element e{level} for a leaf variant: empty | text | cdata | attr | siblings (two repeated elements).
std::string leafXml(std::size_t level, std::string_view leaf)
{
    if (leaf == "empty")
    {
        return fmt::format("<e{0}></e{0}>", level);
    }
    if (leaf == "text")
    {
        return fmt::format("<e{0}>t</e{0}>", level);
    }
    if (leaf == "cdata")
    {
        return fmt::format("<e{0}><![CDATA[t]]></e{0}>", level);
    }
    if (leaf == "attr")
    {
        return fmt::format(R"(<e{0} k="v"/>)", level);
    }
    if (leaf == "siblings")
    {
        return fmt::format("<e{0}>t</e{0}><e{0}>u</e{0}>", level);
    }
    throw std::invalid_argument(fmt::format("unknown leaf variant '{}'", leaf));
}

/// @p depth nested elements, the innermost one being the @p leaf variant.
std::string deepXml(std::size_t depth, std::string_view leaf)
{
    return wrapXml(depth - 1, leafXml(depth, leaf));
}

/// /e1/e2/…/e{levels}
std::string elementsPath(std::size_t levels)
{
    std::string path;
    for (std::size_t level = 1; level <= levels; ++level)
    {
        path += fmt::format("/e{}", level);
    }
    return path;
}

/// A row whose syntax step consumes the whole input and whose semantic step fails.
ParseT deepFailure(std::string xml, hlp::Options options)
{
    const auto size = xml.size();
    return ParseT(FAILURE, std::move(xml), {}, size, getXMLParser, {NAME, TARGET, {""}, std::move(options)});
}
} // namespace

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
        ParseT(SUCCESS,
               R"(<EventData><Data Name="x/3~label">value</Data></EventData>)",
               j(fmt::format(R"({{"{}":{}}})", TARGET.substr(1), R"({"EventData":{"x/3~label":"value"}})")),
               58,
               getXMLParser,
               {NAME, TARGET, {""}, {"windows"}}),
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
               {NAME, TARGET, {""}}),
        // An all-decimal Data name must stay a member name even when there is no enclosing object
        ParseT(SUCCESS,
               R"(<Event><Data Name="3">v</Data></Event>)",
               j(fmt::format(R"({{"{}":{}}})", TARGET.substr(1), R"({"3":"v"})")),
               38,
               getXMLParser,
               {NAME, TARGET, {""}, {"windows"}}),
        // ... and when the enclosing node was turned into an array by a previous unnamed Data
        ParseT(SUCCESS,
               R"(<EventData><Data>a</Data><Data Name="3">v</Data></EventData>)",
               j(fmt::format(R"({{"{}":{}}})", TARGET.substr(1), R"({"EventData":{"3":"v"}})")),
               60,
               getXMLParser,
               {NAME, TARGET, {""}, {"windows"}}),
        // Same as a name that cannot be read as an index: the named Data replaces the array
        ParseT(SUCCESS,
               R"(<EventData><Data>a</Data><Data Name="b">v</Data></EventData>)",
               j(fmt::format(R"({{"{}":{}}})", TARGET.substr(1), R"({"EventData":{"b":"v"}})")),
               60,
               getXMLParser,
               {NAME, TARGET, {""}, {"windows"}}),
        // A CDATA child is the text of its parent, not a member with an empty name
        ParseT(SUCCESS,
               R"(<a><![CDATA[x]]></a>)",
               j(fmt::format(R"({{"{}":{}}})", TARGET.substr(1), R"({"a":{"#text":"x"}})")),
               20,
               getXMLParser,
               {NAME, TARGET, {""}, {}}),
        ParseT(SUCCESS,
               R"(<a><![CDATA[x]]></a>)",
               j(fmt::format(R"({{"{}":{}}})", TARGET.substr(1), R"({"a":{"#text":"x"}})")),
               20,
               getXMLParser,
               {NAME, TARGET, {""}, {"windows"}}),
        // A document nested deeper than json::Json::MAX_DEPTH (256) containers: the root of the document is the first,
        // each element adds one, so 256 nested elements need 257; the Event skipped by windows adds none
        deepFailure(deepXml(256, "text"), {}),
        deepFailure(deepXml(256, "text"), {"windows"}),
        deepFailure("<Event>" + deepXml(256, "text") + "</Event>", {"windows"}),
        // an EMPTY leaf is rejected too (the guard is on the element, not the leaf's content)
        deepFailure(deepXml(256, "empty"), {}),
        // a repeated leaf costs two containers (the array and its element)
        deepFailure(deepXml(255, "siblings"), {}),
        // a windows named Data adds no container: below 256 elements the elements alone exceed the limit
        deepFailure(wrapXml(256, R"(<Data Name="n">v</Data>)"), {"windows"})));

namespace
{
json::Json parseXmlEvent(const std::string& xml, const hlp::Options& options)
{
    const auto parser = getXMLParser({NAME, TARGET, {""}, options});
    auto event = json::Json {};
    event.setObject();
    const auto error = hlp::parser::run(parser, xml, event, true);
    EXPECT_FALSE(error.has_value()) << error->message;
    return event;
}
} // namespace

TEST(XmlParserDepth, MaxDepthParses)
{
    // the root of the document is the first container, so MAX_DEPTH - 1 nested elements fill the cap
    const auto depth = json::Json::MAX_DEPTH - 1;
    const auto leaf = TARGET + elementsPath(depth);
    const auto parent = TARGET + elementsPath(depth - 1);
    for (const hlp::Options& options : {hlp::Options {}, hlp::Options {"windows"}})
    {
        SCOPED_TRACE(options.empty() ? "default" : options[0]);

        auto event = parseXmlEvent(deepXml(depth, "empty"), options);
        EXPECT_TRUE(event.isObject(leaf));
        EXPECT_EQ(event.size(leaf), 0u);

        event = parseXmlEvent(deepXml(depth, "text"), options);
        EXPECT_TRUE(event.equalsString(leaf + "/#text", "t"));

        event = parseXmlEvent(deepXml(depth, "cdata"), options);
        EXPECT_TRUE(event.equalsString(leaf + "/#text", "t"));
        EXPECT_EQ(event.size(leaf), 1u);

        event = parseXmlEvent(deepXml(depth, "attr"), options);
        EXPECT_TRUE(event.equalsString(leaf + "/@k", "v"));

        // a repeated leaf costs two containers (the array and its element), so it fits one level higher
        event = parseXmlEvent(deepXml(depth - 1, "siblings"), options);
        ASSERT_TRUE(event.isArray(parent));
        EXPECT_EQ(event.size(parent), 2u);
        EXPECT_TRUE(event.equalsString(parent + "/0/#text", "t"));
        EXPECT_TRUE(event.equalsString(parent + "/1/#text", "u"));
    }

    // windows: the skipped Event writes nothing and adds no container, and neither does a named Data
    auto event = parseXmlEvent("<Event>" + deepXml(depth, "text") + "</Event>", {"windows"});
    EXPECT_TRUE(event.equalsString(leaf + "/#text", "t"));
    EXPECT_FALSE(event.exists(TARGET + "/Event"));

    event = parseXmlEvent(wrapXml(depth, R"(<Data Name="n">v</Data>)"), {"windows"});
    EXPECT_TRUE(event.equalsString(leaf + "/n", "v"));
}

namespace
{
/// Containers of the deepest nesting in a serialized JSON document.
std::size_t jsonNesting(std::string_view text)
{
    std::size_t depth = 0;
    std::size_t deepest = 0;
    bool inString = false;
    bool escaped = false;
    for (const char c : text)
    {
        if (inString)
        {
            if (escaped)
            {
                escaped = false;
            }
            else if (c == '\\')
            {
                escaped = true;
            }
            else if (c == '"')
            {
                inString = false;
            }
            continue;
        }
        if (c == '"')
        {
            inString = true;
        }
        else if (c == '{' || c == '[')
        {
            deepest = std::max(deepest, ++depth);
        }
        else if (c == '}' || c == ']')
        {
            --depth;
        }
    }
    return deepest;
}

/// Parses @p xml, expecting a document of exactly MAX_DEPTH containers that the bounded JSON parser reads back.
void expectFillsDepth(const std::string& xml, const hlp::Options& options)
{
    const auto event = parseXmlEvent(xml, options);
    const auto parsed = event.getJson(TARGET);
    ASSERT_TRUE(parsed.has_value());
    const auto text = parsed->str();
    EXPECT_EQ(jsonNesting(text), json::Json::MAX_DEPTH);
    EXPECT_NO_THROW(json::Json {text.c_str()});
}

/// Expects the parser to reject @p xml with the depth error.
void expectDepthError(const std::string& xml, const hlp::Options& options)
{
    const auto parser = getXMLParser({NAME, TARGET, {""}, options});
    auto event = json::Json {};
    event.setObject();
    const auto error = hlp::parser::run(parser, xml, event, true);
    ASSERT_TRUE(error.has_value());
    EXPECT_NE(error->message.find(json::Json::DEPTH_ERROR_MSG), std::string::npos) << error->message;
    EXPECT_FALSE(event.exists(TARGET));
}

/// @p levels nested levels, each one a repeated element whose second sibling holds the next level; the innermost
/// level holds text. Each level costs two containers (the array and its element).
std::string repeatedLevelsXml(std::size_t levels)
{
    std::string xml;
    for (std::size_t level = 1; level <= levels; ++level)
    {
        xml += fmt::format("<e{0}/><e{0}>", level);
    }
    xml += "x";
    for (auto level = levels; level > 0; --level)
    {
        xml += fmt::format("</e{}>", level);
    }
    return xml;
}
} // namespace

// The cap counts the containers of the document built, not the XML elements read: repeated siblings at every level
// and a first sibling moved into its array when the second one appears.
TEST(XmlParserDepth, RepeatedSiblingsCountTheirArray)
{
    const auto maxDepth = json::Json::MAX_DEPTH;
    // root + w + two containers per repeated level
    const auto levels = (maxDepth - 2) / 2;
    // root + r + a + the chain below the first a: the second a moves the first one level down, into the array
    const auto chain = maxDepth - 3;
    for (const hlp::Options& options : {hlp::Options {}, hlp::Options {"windows"}})
    {
        SCOPED_TRACE(options.empty() ? "default" : options[0]);

        expectFillsDepth("<w>" + repeatedLevelsXml(levels) + "</w>", options);
        expectDepthError("<w>" + repeatedLevelsXml(levels + 1) + "</w>", options);

        expectFillsDepth("<r><a>" + wrapXml(chain - 1, "x") + "</a><a/></r>", options);
        expectDepthError("<r><a>" + wrapXml(chain, "x") + "</a><a/></r>", options);
    }

    // windows: the children of the skipped Event and its siblings share one object, so a sibling after the Event
    // moves the element written inside it
    expectFillsDepth("<Event><a>" + wrapXml(maxDepth - 3, "x") + "</a></Event><a/>", {"windows"});
    expectDepthError("<Event><a>" + wrapXml(maxDepth - 2, "x") + "</a></Event><a/>", {"windows"});
}

TEST(XmlParserDepth, TraceNamesLimit)
{
    const auto xml = deepXml(json::Json::MAX_DEPTH + 1, "text");
    for (const hlp::Options& options : {hlp::Options {}, hlp::Options {"windows"}})
    {
        SCOPED_TRACE(options.empty() ? "default" : options[0]);
        const auto parser = getXMLParser({NAME, TARGET, {""}, options});
        const auto result = parser(xml);
        ASSERT_TRUE(result.success());
        ASSERT_TRUE(result.hasValue());

        const auto traced = result.value().semParser(result.value().parsed, true);
        ASSERT_TRUE(std::holds_alternative<base::Error>(traced));
        EXPECT_EQ(std::get<base::Error>(traced).message, "XML nesting depth exceeds the limit (256)");

        const auto silent = result.value().semParser(result.value().parsed, false);
        ASSERT_TRUE(std::holds_alternative<base::Error>(silent));
        EXPECT_TRUE(std::get<base::Error>(silent).message.empty());
    }
}

/************************************************************************************/
// Stack probe (RNF-4): xmlToJson on a thread with a chosen stack size.
//
// Driven by the environment (read at run time, skipped when WAZUH_STACK_PROBE_XML_DEPTH is unset):
//   WAZUH_STACK_PROBE_XML_DEPTH  number of nested elements of the fixture
//   WAZUH_STACK_PROBE_XML_KIB    stack size of the probe thread in KiB (default 4096)
//   WAZUH_STACK_PROBE_XML_LEAF   empty | text (default) | cdata | attr: the innermost element
// Prints PROBE_EFFECTIVE_KIB=<n> (read inside the thread) and PROBE_RESULT=PASS|FAIL. Above MAX_DEPTH the
// conversion must be rejected with the depth error.
/************************************************************************************/
namespace
{
std::size_t envSize(const char* name, std::size_t fallback)
{
    const char* raw = std::getenv(name);
    return (raw == nullptr || *raw == '\0') ? fallback : static_cast<std::size_t>(std::stoull(raw));
}

struct ProbeContext
{
    std::function<void()> op;
    std::string error;
    std::size_t effectiveKiB {0};
    int attrRc {-1};
};

void* runProbe(void* arg)
{
    auto* ctx = static_cast<ProbeContext*>(arg);
    pthread_attr_t attr;
    ctx->attrRc = pthread_getattr_np(pthread_self(), &attr);
    if (ctx->attrRc == 0)
    {
        std::size_t stackSize {0};
        ctx->attrRc = pthread_attr_getstacksize(&attr, &stackSize);
        pthread_attr_destroy(&attr);
        ctx->effectiveKiB = stackSize / 1024;
    }
    std::printf("PROBE_EFFECTIVE_KIB=%zu\n", ctx->effectiveKiB);
    std::fflush(stdout);
    try
    {
        ctx->op();
    }
    catch (const std::exception& e)
    {
        ctx->error = e.what();
    }
    catch (...)
    {
        ctx->error = "unknown exception";
    }
    return nullptr;
}
} // namespace

TEST(XmlParserDepth, StackProbe)
{
    const char* depthEnv = std::getenv("WAZUH_STACK_PROBE_XML_DEPTH");
    if (depthEnv == nullptr || *depthEnv == '\0')
    {
        GTEST_SKIP() << "WAZUH_STACK_PROBE_XML_DEPTH is not set";
    }
    const auto depth = envSize("WAZUH_STACK_PROBE_XML_DEPTH", 0);
    const auto kib = envSize("WAZUH_STACK_PROBE_XML_KIB", 4096);
    const char* leafEnv = std::getenv("WAZUH_STACK_PROBE_XML_LEAF");
    const std::string leaf {(leafEnv == nullptr || *leafEnv == '\0') ? "text" : leafEnv};
    ASSERT_TRUE(leaf == "empty" || leaf == "text" || leaf == "cdata" || leaf == "attr") << "unknown leaf " << leaf;
    ASSERT_GE(depth, 1u);
    std::printf("PROBE_CASE depth=%zu leaf=%s kib=%zu\n", depth, leaf.c_str(), kib);
    std::fflush(stdout);

    // Fixture built here, on the main thread; the parser, the conversion and the mapping run on the probe thread.
    const auto xml = deepXml(depth, leaf);
    const auto leafPath = TARGET + elementsPath(depth);
    const bool tooDeep = depth > json::Json::MAX_DEPTH;

    json::Json event;
    event.setObject();
    std::optional<std::string> semError;
    ProbeContext ctx;
    ctx.op = [&]()
    {
        const auto parser = getXMLParser({NAME, TARGET, {""}, {}});
        const auto result = parser(xml);
        if (!result.success() || !result.hasValue())
        {
            throw std::runtime_error("syntax step failed");
        }
        auto sem = result.value().semParser(result.value().parsed, true);
        if (std::holds_alternative<base::Error>(sem))
        {
            semError = std::get<base::Error>(sem).message;
            return;
        }
        std::get<hlp::parser::Mapper>(sem)(event);
    };

    pthread_attr_t attr;
    ASSERT_EQ(pthread_attr_init(&attr), 0);
    const int stackRc = pthread_attr_setstacksize(&attr, kib * 1024);
    if (stackRc != 0)
    {
        pthread_attr_destroy(&attr);
        FAIL() << "pthread_attr_setstacksize(" << kib << " KiB) failed: " << stackRc;
    }
    pthread_t thread;
    const int createRc = pthread_create(&thread, &attr, runProbe, &ctx);
    pthread_attr_destroy(&attr);
    ASSERT_EQ(createRc, 0) << "pthread_create failed";
    ASSERT_EQ(pthread_join(thread, nullptr), 0) << "pthread_join failed";
    EXPECT_EQ(ctx.attrRc, 0) << "pthread_getattr_np/pthread_attr_getstacksize failed";

    bool pass = ctx.error.empty();
    if (pass && tooDeep)
    {
        pass = semError == "XML nesting depth exceeds the limit (256)";
    }
    else if (pass)
    {
        pass = !semError.has_value();
        if (pass && leaf == "empty")
        {
            pass = event.isObject(leafPath) && event.size(leafPath) == 0;
        }
        else if (pass && leaf == "attr")
        {
            pass = event.equalsString(leafPath + "/@k", "v");
        }
        else if (pass)
        {
            pass = event.equalsString(leafPath + "/#text", "t");
        }
    }
    std::printf("PROBE_RESULT=%s\n", pass ? "PASS" : "FAIL");
    std::fflush(stdout);
    EXPECT_TRUE(pass) << (!ctx.error.empty() ? "probe threw: " + ctx.error
                                             : "semantic error: " + semError.value_or("<none>"));
}

/************************************************************************************/
// Repeated sibling elements: every sibling is one element of the array, with its text, attributes and children.
/************************************************************************************/
namespace
{
struct SiblingsCase
{
    const char* xml;
    const char* expected; // content of the target field
};

void expectParsed(const SiblingsCase& row, const hlp::Options& options)
{
    SCOPED_TRACE(fmt::format("{} [{}]", row.xml, options.empty() ? "default" : options[0]));
    const auto event = parseXmlEvent(row.xml, options);
    const auto expected = j(fmt::format(R"({{"{}":{}}})", TARGET.substr(1), row.expected));
    EXPECT_EQ(event, expected) << "  parsed:   " << event.str() << "\n  expected: " << expected.str();
}
} // namespace

// Documents without Event or Data elements map the same way in both modules.
TEST(XmlParserSiblings, ElementsWithoutChildren)
{
    const std::vector<SiblingsCase> rows {
        {R"(<r><a>1</a></r>)", R"({"r":{"a":{"#text":"1"}}})"},
        {R"(<r><a><x>1</x></a></r>)", R"({"r":{"a":{"x":{"#text":"1"}}}})"},
        {R"(<r><a>1</a><a>2</a></r>)", R"({"r":{"a":[{"#text":"1"},{"#text":"2"}]}})"},
        {R"(<r><a k="1"/><a k="2">t</a><a/></r>)", R"({"r":{"a":[{"@k":"1"},{"#text":"t","@k":"2"},{}]}})"},
        {R"(<r><a>1</a><b/><a>2</a></r>)", R"({"r":{"a":[{"#text":"1"},{"#text":"2"}],"b":{}}})"},
        {R"(<a>1</a><a>2</a>)", R"({"a":[{"#text":"1"},{"#text":"2"}]})"},
    };
    for (const hlp::Options& options : {hlp::Options {}, hlp::Options {"windows"}})
    {
        for (const auto& row : rows)
        {
            expectParsed(row, options);
        }
    }
}

TEST(XmlParserSiblings, ElementsWithChildren)
{
    const std::vector<SiblingsCase> rows {
        // nested
        {R"(<r><a><x>1</x></a><a><x>2</x></a></r>)", R"({"r":{"a":[{"x":{"#text":"1"}},{"x":{"#text":"2"}}]}})"},
        // top level
        {R"(<a><x>1</x></a><a><x>2</x></a>)", R"({"a":[{"x":{"#text":"1"}},{"x":{"#text":"2"}}]})"},
        // three siblings, with text and attributes next to the children
        {R"(<r><a k="1">t<x>1</x></a><a><x>2</x><y/></a><a k="3"><x>3</x></a></r>)",
         R"({"r":{"a":[{"#text":"t","@k":"1","x":{"#text":"1"}},{"x":{"#text":"2"},"y":{}},{"@k":"3","x":{"#text":"3"}}]}})"},
        // only some of the siblings have children
        {R"(<r><a>1</a><a><x>2</x></a><a>3</a></r>)",
         R"({"r":{"a":[{"#text":"1"},{"x":{"#text":"2"}},{"#text":"3"}]}})"},
        // the children repeat as well
        {R"(<r><a><b>1</b><b>2</b></a><a><b>3</b><b>4</b></a></r>)",
         R"({"r":{"a":[{"b":[{"#text":"1"},{"#text":"2"}]},{"b":[{"#text":"3"},{"#text":"4"}]}]}})"},
        // a sibling without content after one with attributes and repeated children
        {R"(<r><a k="1"><b>1</b><b>2</b></a><a/></r>)",
         R"({"r":{"a":[{"@k":"1","b":[{"#text":"1"},{"#text":"2"}]},{}]}})"},
        // repeated elements with children inside a repeated element
        {R"(<r><a><b><c>1</c></b><b><c>2</c></b></a><a><b><c>3</c></b></a></r>)",
         R"({"r":{"a":[{"b":[{"c":{"#text":"1"}},{"c":{"#text":"2"}}]},{"b":{"c":{"#text":"3"}}}]}})"},
    };
    for (const hlp::Options& options : {hlp::Options {}, hlp::Options {"windows"}})
    {
        for (const auto& row : rows)
        {
            expectParsed(row, options);
        }
    }
}

TEST(XmlParserSiblings, WindowsElementsWithChildren)
{
    const std::vector<SiblingsCase> rows {
        // each repeated container keeps its own named Data
        {R"(<Event><EventData><Data Name="a">v</Data></EventData><EventData><Data Name="b">w</Data></EventData></Event>)",
         R"({"EventData":[{"a":"v"},{"b":"w"}]})"},
        {R"(<Event><UserData><Item><Name>a</Name></Item><Item><Name>b</Name></Item></UserData></Event>)",
         R"({"UserData":{"Item":[{"Name":{"#text":"a"}},{"Name":{"#text":"b"}}]}})"},
        {R"(<Event><UserData><Item><Data Name="n">1</Data><Sub>x</Sub></Item><Item><Data Name="n">2</Data></Item></UserData></Event>)",
         R"({"UserData":{"Item":[{"n":"1","Sub":{"#text":"x"}},{"n":"2"}]}})"},
    };
    for (const auto& row : rows)
    {
        expectParsed(row, {"windows"});
    }
}

// A Data without Name turns its parent into an array of strings, which a later sibling of that parent takes for the
// array of the repeated siblings: the strings of the first sibling stay flat in the array and each later sibling is one
// element of it, a nested array of strings or an object.
TEST(XmlParserSiblings, WindowsUnnamedDataInRepeatedElements)
{
    const std::vector<SiblingsCase> rows {
        {R"(<Event><EventData><Data>a</Data><Data>b</Data></EventData><EventData><Data>c</Data></EventData></Event>)",
         R"({"EventData":["a","b",["c"]]})"},
        {R"(<X><Data>1</Data></X><X><Data>2</Data></X>)", R"({"X":["1",["2"]]})"},
        // named Data first, unnamed second
        {R"(<Event><EventData><Data Name="k">v</Data></EventData><EventData><Data>a</Data></EventData></Event>)",
         R"({"EventData":[{"k":"v"},["a"]]})"},
        // unnamed Data first, named second
        {R"(<Event><EventData><Data>a</Data></EventData><EventData><Data Name="k">v</Data></EventData></Event>)",
         R"({"EventData":["a",{"k":"v"}]})"},
    };
    for (const auto& row : rows)
    {
        expectParsed(row, {"windows"});
    }
}
