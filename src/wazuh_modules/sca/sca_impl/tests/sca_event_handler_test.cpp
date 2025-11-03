#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sca_event_handler.hpp>

#include "mocks/sca_event_handler_mock.hpp"
#include "logging_helper.hpp"

using namespace sca_event_handler;

class SCAEventHandlerTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            // Set up the logging callback to avoid "Log callback not set" errors
            LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */)
            {
                // Mock logging callback that does nothing
            });

            mockDBSync = std::make_shared<MockDBSync>();
            handler = std::make_unique<sca_event_handler::SCAEventHandlerMock>(mockDBSync);
        }

        std::shared_ptr<MockDBSync> mockDBSync;
        std::unique_ptr<sca_event_handler::SCAEventHandlerMock> handler;
};

TEST_F(SCAEventHandlerTest, ProcessEvents_ModifiedPolicyOnly)
{
    EXPECT_CALL(*handler, GetChecksForPolicy("cis_win11_enterprise_21H2"))
    .WillOnce(testing::Return(nlohmann::json::array(
    {
        {{"id", "26000"}, {"name", "Check 26000"}, {"policy_id", "cis_win11_enterprise_21H2"}},
        {{"id", "26001"}, {"name", "Check 26001"}, {"policy_id", "cis_win11_enterprise_21H2"}}})));

    const std::unordered_map<std::string, nlohmann::json> modifiedPolicies = {{"cis_win11_enterprise_21H2",
            {   {
                    "data",
                    {   {"id", "cis_win11_enterprise_21H2"},
                        {"name", "CIS Policy"},
                        {"file", "cis.yml"},
                        {"description", "desc"},
                        {"refs", "https://example.com"}
                    }
                },
                {"result", 1}
            }
        }
    };

    const std::unordered_map<std::string, nlohmann::json> modifiedChecks;

    const auto events = handler->ProcessEvents(modifiedPolicies, modifiedChecks);

    ASSERT_EQ(events.size(), 2);

    for (const auto& event : events)
    {
        EXPECT_EQ(event["collector"], "policy");
        EXPECT_EQ(event["policy"]["id"], "cis_win11_enterprise_21H2");
        EXPECT_TRUE(event.contains("check"));
    }
}

TEST_F(SCAEventHandlerTest, ProcessEvents_ModifiedCheckOnly)
{
    EXPECT_CALL(*handler, GetPolicyById("cis_policy_3"))
    .Times(2)
    .WillRepeatedly(
    testing::Return(nlohmann::json({{"id", "cis_policy_3"},
        {"name", "Custom Windows Hardening Policy"},
        {"file", "custom_windows_policy.yml"},
        {"description", "Custom internal hardening guidelines for Windows"},
        {"refs", "https://internal.docs/policies/windows"}})));

    const std::unordered_map<std::string, nlohmann::json> modifiedPolicies;

    const std::unordered_map<std::string, nlohmann::json> modifiedChecks =
    {
        {
            "3003",
            {   {"data", {{"new", {{"id", "3003"}, {"policy_id", "cis_policy_3"}, {"name", "Standalone Check"}}}}},
                {"result", MODIFIED}
            }
        },
        {
            "3004",
            {{"data", {{"id", "3004"}, {"policy_id", "cis_policy_3"}, {"name", "Another Check"}}}, {"result", DELETED}}
        }
    };

    const auto events = handler->ProcessEvents(modifiedPolicies, modifiedChecks);

    auto check3003Event = std::find_if(events.begin(),
                                       events.end(),
                                       [](const auto & evt)
    {
        return evt["check"].contains("new") && evt["check"]["new"]["id"] == "3003";
    });

    ASSERT_NE(check3003Event, events.end());
    EXPECT_EQ((*check3003Event)["collector"], "check");
    EXPECT_EQ((*check3003Event)["policy"]["id"], "cis_policy_3");
    EXPECT_EQ((*check3003Event)["result"], MODIFIED);

    auto check3004Event =
        std::find_if(events.begin(),
                     events.end(),
                     [](const auto & evt)
    {
        return evt["check"].contains("id") && evt["check"]["id"] == "3004";
    });

    ASSERT_NE(check3004Event, events.end());
    EXPECT_EQ((*check3004Event)["collector"], "check");
    EXPECT_EQ((*check3004Event)["policy"]["id"], "cis_policy_3");
    EXPECT_EQ((*check3004Event)["result"], DELETED);
}

TEST_F(SCAEventHandlerTest, ProcessEvents_ModifiedCheckAndPolicy)
{
    EXPECT_CALL(*handler, GetChecksForPolicy("cis_win11_enterprise_21H2"))
    .WillOnce(testing::Return(nlohmann::json::array(
    {
        {{"id", "26000"}, {"name", "Check 26000"}, {"policy_id", "cis_win11_enterprise_21H2"}},
        {{"id", "26001"}, {"name", "Check 26001"}, {"policy_id", "cis_win11_enterprise_21H2"}}})));

    const std::unordered_map<std::string, nlohmann::json> modifiedPolicies =
    {
        {
            "cis_win11_enterprise_21H2",
            {   {
                    "data",
                    {   {"id", "cis_win11_enterprise_21H2"},
                        {"name", "CIS Microsoft Windows 11 Enterprise Benchmark v1.0.0"},
                        {"file", "cis_win11_enterprise.yml"},
                        {"description", "This document provides prescriptive guidance for Windows 11 Enterprise"},
                        {"refs", "https://www.cisecurity.org/cis-benchmarks/"}
                    }
                },
                {"result", 1}
            }
        }
    };

    const std::unordered_map<std::string, nlohmann::json> modifiedChecks =
    {
        {
            "26001",
            {{"data", {{"new", {{"policy_id", "cis_win11_enterprise_21H2"}}}, {"id", "26001"}}}, {"result", MODIFIED}}
        }
    };

    const auto events = handler->ProcessEvents(modifiedPolicies, modifiedChecks);

    ASSERT_EQ(events.size(), 2);

    int policyCount = 0, checkCount = 0;

    for (const auto& event : events)
    {
        if (event["collector"] == "policy")
        {
            policyCount++;
        }

        if (event["collector"] == "check")
        {
            checkCount++;
        }
    }

    EXPECT_EQ(policyCount, 1);
    EXPECT_EQ(checkCount, 1);
}

TEST_F(SCAEventHandlerTest, ProcessEvents_NoThrowException)
{
    EXPECT_CALL(*handler, GetChecksForPolicy("cis_win11_enterprise_21H2"))
    .WillOnce(testing::Return(nlohmann::json::array(
    {
        {{"num", "26000"}, {"name", "Check 26000"}, {"policy_id", "cis_win11_enterprise_21H2"}},
        {{"num", "26001"}, {"name", "Check 26001"}, {"policy_id", "cis_win11_enterprise_21H2"}}})));

    const std::unordered_map<std::string, nlohmann::json> modifiedPolicies =
    {
        {"cis_win11_enterprise_21H2", {{"data", {/* policy fields */}}, {"result", 0}}}
    };

    const std::unordered_map<std::string, nlohmann::json> modifiedChecks;

    nlohmann::json result;
    EXPECT_NO_THROW({ result = handler->ProcessEvents(modifiedPolicies, modifiedChecks); });
    EXPECT_TRUE(result.empty());
}

TEST_F(SCAEventHandlerTest, GetPolicyById)
{
    const std::string expectedId = "pol1";
    const nlohmann::json expectedQuery =
    {
        {"table", "sca_policy"},
        {
            "query",
            {{"column_list", {"id", "name", "description", "file", "refs"}}, {"row_filter", "WHERE id = 'pol1'"}}
        }
    };
    const nlohmann::json mockResult = {{"id", "pol1"},
        {"name", "Policy Name"},
        {"description", "Some Description"},
        {"file", "policy.yml"},
        {"refs", "ref-123"}
    };

    EXPECT_CALL(*mockDBSync, selectRows(expectedQuery, testing::_))
    .WillOnce([&](const nlohmann::json&, const std::function<void(ReturnTypeCallback, const nlohmann::json&)>& cb)
    {
        cb(SELECTED, mockResult);
    });

    const auto result = handler->GetPolicyById(expectedId);

    EXPECT_EQ(result, mockResult);
}

TEST_F(SCAEventHandlerTest, GetChecksForPolicy)
{
    const std::string policyId = "polX";

    const nlohmann::json expectedQuery = {{"table", "sca_check"},
        {
            "query",
            {   {
                    "column_list",
                    {
                        "checksum",
                        "id",
                        "policy_id",
                        "name",
                        "description",
                        "rationale",
                        "remediation",
                        "refs",
                        "result",
                        "reason",
                        "condition",
                        "compliance",
                        "rules",
                        "version"
                    }
                },
                {"row_filter", "WHERE policy_id = 'polX'"}
            }
        }
    };

    const nlohmann::json check1 = {{"id", "chk1"}, {"policy_id", "polX"}, {"name", "Check 1"}};
    const nlohmann::json check2 = {{"id", "chk2"}, {"policy_id", "polX"}, {"name", "Check 2"}};

    EXPECT_CALL(*mockDBSync, selectRows(expectedQuery, testing::_))
    .WillOnce(
        [&](const nlohmann::json&, const std::function<void(ReturnTypeCallback, const nlohmann::json&)>& cb)
    {
        cb(SELECTED, check1);
        cb(SELECTED, check2);
    });

    const auto result = handler->GetChecksForPolicy(policyId);

    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], check1);
    EXPECT_EQ(result[1], check2);
}

TEST_F(SCAEventHandlerTest, ProcessStateful_ValidInput1)
{
    const nlohmann::json input = {{"check",
            {   {
                    "new",
                    {   {"checksum", "abc123"},
                        {"id", "chk1"},
                        {"name", "Ensure firewall is active"},
                        {"description", "Verifies that the firewall is running"},
                        {"rationale", "Security best practices"},
                        {"status", "passed"},
                        {"condition", "all"},
                        {"compliance", {"cis:1.1", "pci_dss:2.2"}},
                        {"remediation", "Enable the firewall service"},
                        {"refs", "Ref1, Ref2"},
                        {"rules", {"Rule1", "Rule2"}}
                    }
                }
            }
        },
        {
            "policy",
            {   {
                    "new",
                    {   {"id", "pol1"},
                        {"name", "CIS Ubuntu Benchmark"},
                        {"rationale", "SMBv1 is outdated and insecure."},
                        {"description", "Disable SMBv1"},
                        {"refs", "RefA, RefB"},
                        {"file", "policy_file.yml"}
                    }
                }
            }
        },
        {"result", 0}
    };

    const auto result = handler->ProcessStateful(input);
    const auto& output = std::get<0>(result);
    const auto& operation = std::get<1>(result);

    // Validate the operation type
    EXPECT_EQ(operation, MODIFIED);

    EXPECT_EQ(output["checksum"]["hash"]["sha1"], "abc123");
    EXPECT_EQ(output["check"]["id"], "chk1");
    EXPECT_EQ(output["check"]["name"], "Ensure firewall is active");
    EXPECT_EQ(output["check"]["description"], "Verifies that the firewall is running");
    EXPECT_EQ(output["check"]["rationale"], "Security best practices");
    EXPECT_EQ(output["check"]["status"], "passed");
    EXPECT_EQ(output["check"]["condition"], "all");
    EXPECT_TRUE(output["check"].contains("compliance"));
    EXPECT_TRUE(output["check"].contains("remediation"));
    EXPECT_TRUE(output["check"].contains("references"));
    EXPECT_TRUE(output["check"].contains("rules"));

    EXPECT_EQ(output["policy"]["id"], "pol1");
    EXPECT_EQ(output["policy"]["name"], "CIS Ubuntu Benchmark");
    EXPECT_EQ(output["policy"]["rationale"], "SMBv1 is outdated and insecure.");
    EXPECT_TRUE(output["policy"].contains("description"));
    EXPECT_TRUE(output["policy"].contains("references"));
    EXPECT_TRUE(output["policy"].contains("file"));
}

TEST_F(SCAEventHandlerTest, ProcessStateful_ValidInput2)
{
    const nlohmann::json input = {{"check",
            {   {"checksum", "abc123"},
                {"id", "chk1"},
                {"name", "Ensure firewall is active"},
                {"description", "Verifies that the firewall is running"},
                {"rationale", "Security best practices"},
                {"status", "passed"},
                {"condition", "all"},
                {"compliance", {"cis:1.1", "pci_dss:2.2"}},
                {"remediation", "Enable the firewall service"},
                {"refs", "Ref1, Ref2"},
                {"rules", {"Rule1", "Rule2"}}
            }
        },
        {
            "policy",
            {   {"id", "pol1"},
                {"name", "CIS Ubuntu Benchmark"},
                {"rationale", "SMBv1 is outdated and insecure."},
                {"description", "Disable SMBv1"},
                {"refs", "RefA, RefB"},
                {"file", "policy_file.yml"}
            }
        },
        {"result", 2}
    };

    const auto result = handler->ProcessStateful(input);
    const auto& output = std::get<0>(result);
    const auto& operation = std::get<1>(result);

    // Validate the operation type
    EXPECT_EQ(operation, INSERTED);

    EXPECT_EQ(output["checksum"]["hash"]["sha1"], "abc123");
    EXPECT_EQ(output["check"]["id"], "chk1");
    EXPECT_EQ(output["check"]["name"], "Ensure firewall is active");
    EXPECT_EQ(output["check"]["description"], "Verifies that the firewall is running");
    EXPECT_EQ(output["check"]["rationale"], "Security best practices");
    EXPECT_EQ(output["check"]["status"], "passed");
    EXPECT_TRUE(output["check"].contains("condition"));
    EXPECT_TRUE(output["check"].contains("compliance"));
    EXPECT_TRUE(output["check"].contains("remediation"));
    EXPECT_TRUE(output["check"].contains("references"));
    EXPECT_TRUE(output["check"].contains("rules"));
    EXPECT_EQ(output["policy"]["id"], "pol1");
    EXPECT_EQ(output["policy"]["name"], "CIS Ubuntu Benchmark");
    EXPECT_EQ(output["policy"]["rationale"], "SMBv1 is outdated and insecure.");
    EXPECT_TRUE(output["policy"].contains("description"));
    EXPECT_TRUE(output["policy"].contains("references"));
    EXPECT_TRUE(output["policy"].contains("file"));
}

TEST_F(SCAEventHandlerTest, ProcessStateful_WithVersion)
{
    const nlohmann::json input = {{"check",
            {   {"checksum", "version_test_123"},
                {"id", "chk_version"},
                {"name", "Version tracking test check"},
                {"description", "This check validates version tracking"},
                {"rationale", "Ensures version is properly tracked"},
                {"status", "passed"},
                {"condition", "all"},
                {"compliance", {"cis:1.1"}},
                {"remediation", "No remediation needed"},
                {"refs", "Ref1, Ref2"},
                {"rules", {"Rule1"}},
                {"version", 5}
            }
        },
        {
            "policy",
            {   {"id", "pol_version"},
                {"name", "Version Policy Test"},
                {"rationale", "Testing version field"},
                {"description", "Policy for version test"},
                {"refs", "RefA"},
                {"file", "version_policy.yml"}
            }
        },
        {"result", 0}
    };

    const auto result = handler->ProcessStateful(input);
    const auto& output = std::get<0>(result);
    const auto& operation = std::get<1>(result);

    // Validate the operation type
    EXPECT_EQ(operation, MODIFIED);

    // Verify checksum structure
    EXPECT_EQ(output["checksum"]["hash"]["sha1"], "version_test_123");

    // Verify check fields
    EXPECT_EQ(output["check"]["id"], "chk_version");
    EXPECT_EQ(output["check"]["name"], "Version tracking test check");
    EXPECT_EQ(output["check"]["description"], "This check validates version tracking");
    EXPECT_EQ(output["check"]["rationale"], "Ensures version is properly tracked");
    EXPECT_EQ(output["check"]["status"], "passed");
    EXPECT_EQ(output["check"]["condition"], "all");
    EXPECT_TRUE(output["check"].contains("compliance"));
    EXPECT_TRUE(output["check"].contains("remediation"));
    EXPECT_TRUE(output["check"].contains("references"));
    EXPECT_TRUE(output["check"].contains("rules"));

    // Verify policy fields
    EXPECT_EQ(output["policy"]["id"], "pol_version");
    EXPECT_EQ(output["policy"]["name"], "Version Policy Test");
    EXPECT_EQ(output["policy"]["rationale"], "Testing version field");
    EXPECT_TRUE(output["policy"].contains("description"));
    EXPECT_TRUE(output["policy"].contains("references"));
    EXPECT_TRUE(output["policy"].contains("file"));

    // Verify state contains modified_at
    EXPECT_TRUE(output["state"].contains("modified_at"));

    // Verify version is in state, not in check
    EXPECT_TRUE(output["state"].contains("document_version"));
    EXPECT_EQ(output["state"]["document_version"], 5);
    EXPECT_FALSE(output["check"].contains("version"));
}

TEST_F(SCAEventHandlerTest, ProcessStateful_InvalidInput1)
{
    const nlohmann::json input = {{"result", "invalid_result"}};

    const auto result = handler->ProcessStateful(input);
    const auto& output = std::get<0>(result);
    const auto& operation = std::get<1>(result);

    // Validate the operation type for error cases
    EXPECT_EQ(operation, SELECTED);

    EXPECT_TRUE(output.empty());
}

TEST_F(SCAEventHandlerTest, ProcessStateful_InvalidInput2)
{
    const nlohmann::json input = {{"check",
            {   {"checksum", "abc123"},
                {"id", "chk1"},
                {"name", "Ensure firewall is active"},
                {"description", "Verifies that the firewall is running"},
                {"rationale", "Security best practices"},
                {"status", "passed"}
            }
        }
    };

    const auto result = handler->ProcessStateful(input);
    const auto& output = std::get<0>(result);
    const auto& operation = std::get<1>(result);

    // Validate the operation type for error cases
    EXPECT_EQ(operation, SELECTED);

    EXPECT_TRUE(output.empty());
}

TEST_F(SCAEventHandlerTest, ProcessStateless_ValidInput1)
{
    // Input data with shorter, placeholder values
    const nlohmann::json input = {{"check",
            {   {
                    "new",
                    {   {"checksum", "abc123"},
                        {"id", "chk1"},
                        {"result", "passed"},
                        {"compliance", {"cis:1.1", "cis_csc:13", "pci_dss:2.2", "tsc:CC6"}},
                        {"condition", "all"},
                        {"description", "Description of cramfs filesystem."},
                        {"rationale", "Disable unneeded filesystem types to reduce attack surface."},
                        {"refs", "Ref1, Ref2, https://example.com/reference"},
                        {"remediation", "Create CIS.conf and add: install cramfs /bin/true."},
                        {"rules", {"Rule1", "Rule2"}},
                        {"name", "Disable cramfs filesystems."}
                    }
                },
                {"old", {{"id", "chk1"}, {"result", "failed"}}}
            }
        },
        {
            "policy",
            {   {
                    "new",
                    {   {"id", "pol1"},
                        {"description", "Ensure firewall is active"},
                        {"refs", "Ref1, Ref2, https://example.com/reference"},
                        {"name", "CIS Ubuntu Benchmark"},
                        {"file", "CIS_Ubuntu_Benchmark.yml"}
                    }
                },
                {"old", {{"id", "pol1"}, {"description", "Ensure firewall is running"}}}
            }
        },
        {"collector", "check"},
        {"result", 0}
    };

    // Call to your function
    const nlohmann::json output = handler->ProcessStateless(input);

    EXPECT_EQ(output["collector"], "check");
    EXPECT_EQ(output["module"], "sca");

    const auto data = output["data"];
    ASSERT_TRUE(data["check"].contains("checksum"));
    ASSERT_TRUE(data["check"].contains("id"));
    ASSERT_TRUE(data["check"].contains("result"));
    ASSERT_TRUE(data["check"].contains("previous"));
    ASSERT_TRUE(data["check"]["previous"].contains("result"));
    ASSERT_TRUE(data["check"].contains("compliance"));
    ASSERT_TRUE(data["check"].contains("condition"));
    ASSERT_TRUE(data["check"].contains("description"));
    ASSERT_TRUE(data["check"].contains("rationale"));
    ASSERT_TRUE(data["check"].contains("references"));
    ASSERT_TRUE(data["check"].contains("remediation"));
    ASSERT_TRUE(data["check"].contains("rules"));
    ASSERT_TRUE(data["check"].contains("name"));
    ASSERT_TRUE(data["policy"].contains("id"));
    ASSERT_TRUE(data["policy"].contains("description"));
    ASSERT_TRUE(data["policy"].contains("previous"));
    ASSERT_TRUE(data["policy"]["previous"].contains("description"));
    ASSERT_TRUE(data["policy"].contains("name"));
    ASSERT_TRUE(data["policy"].contains("file"));
    ASSERT_TRUE(data["event"].contains("changed_fields"));
    ASSERT_EQ(data["event"]["changed_fields"].size(), 2);
    ASSERT_TRUE(data["event"].contains("created"));
    ASSERT_TRUE(data["event"].contains("type"));
}

TEST_F(SCAEventHandlerTest, ProcessStateless_ValidInput2)
{
    const nlohmann::json input = {{"check",
            {   {"checksum", "abc123"},
                {"id", "chk1"},
                {"result", "failed"},
                {"compliance", {"cis:1.2", "pci_dss:1.1"}},
                {"condition", "any"},
                {"description", "Short check description"},
                {"rationale", "Minimize risk"},
                {"refs", "RefA, RefB"},
                {"remediation", "Do something secure"},
                {"rules", {"RuleA", "RuleB"}},
                {"name", "Check some condition"}
            }
        },
        {
            "policy",
            {   {"id", "pol1"},
                {"description", "Ensure firewall is running"},
                {"refs", "Ref1, Ref2"},
                {"name", "Basic Security Policy"},
                {"file", "basic_policy.yml"}
            }
        },
        {"collector", "check"},
        {"result", 1}
    };

    const nlohmann::json output = handler->ProcessStateless(input);

    EXPECT_EQ(output["collector"], "check");
    EXPECT_EQ(output["module"], "sca");

    const auto data = output["data"];

    ASSERT_TRUE(data["check"].contains("id"));
    EXPECT_EQ(data["check"]["id"], "chk1");
    ASSERT_TRUE(data["check"].contains("result"));
    EXPECT_EQ(data["check"]["result"], "failed");
    ASSERT_TRUE(data["check"].contains("compliance"));
    ASSERT_TRUE(data["check"].contains("condition"));
    ASSERT_TRUE(data["check"].contains("description"));
    ASSERT_TRUE(data["check"].contains("rationale"));
    ASSERT_TRUE(data["check"].contains("references"));
    ASSERT_TRUE(data["check"].contains("remediation"));
    ASSERT_TRUE(data["check"].contains("rules"));
    ASSERT_TRUE(data["check"].contains("name"));
    ASSERT_TRUE(data["policy"].contains("id"));
    EXPECT_EQ(data["policy"]["id"], "pol1");
    ASSERT_TRUE(data["policy"].contains("description"));
    EXPECT_EQ(data["policy"]["description"], "Ensure firewall is running");
    ASSERT_TRUE(data["policy"].contains("name"));
    ASSERT_TRUE(data["policy"].contains("file"));
    ASSERT_TRUE(data["policy"].contains("references"));
    ASSERT_TRUE(data["event"].contains("changed_fields"));
    ASSERT_GE(data["event"]["changed_fields"].size(), 0);
}

TEST_F(SCAEventHandlerTest, ProcessStateless_InvalidInput)
{
    const nlohmann::json input = {{"policy", {{"new", {{"id", "pol1"}}}}}};

    const nlohmann::json output = handler->ProcessStateless(input);

    EXPECT_TRUE(output.empty());
}

TEST_F(SCAEventHandlerTest, CalculateHashId_ReturnsValidHash)
{
    const nlohmann::json data = {{"check", {{"id", "chk1"}}}, {"policy", {{"id", "pol1"}}}};

    const std::string hash = handler->CalculateHashId(data);
    EXPECT_FALSE(hash.empty());
}

TEST_F(SCAEventHandlerTest, CalculateHashId_MissingFields_Throws)
{
    const nlohmann::json data = {{"check", {}}, {"policy", {}}};

    EXPECT_THROW(handler->CalculateHashId(data), nlohmann::json::type_error);
}

TEST_F(SCAEventHandlerTest, StringToJsonArray_TrimmedValues)
{
    const std::string input = " a, b ,c ";
    const nlohmann::json expected = {"a", "b", "c"};

    EXPECT_EQ(handler->StringToJsonArray(input), expected);
}

TEST_F(SCAEventHandlerTest, StringToJsonArray_NoSpaces)
{
    const std::string input = "one,two,three";
    const nlohmann::json expected = {"one", "two", "three"};

    EXPECT_EQ(handler->StringToJsonArray(input), expected);
}

TEST_F(SCAEventHandlerTest, StringToJsonArray_EmptyValuesIgnored)
{
    const std::string input = "a,,b,";
    const nlohmann::json expected = {"a", "b"};

    EXPECT_EQ(handler->StringToJsonArray(input), expected);
}

TEST_F(SCAEventHandlerTest, StringToJsonArray_EmptyString)
{
    const std::string input;
    const nlohmann::json expected = nlohmann::json::array();

    EXPECT_EQ(handler->StringToJsonArray(input), expected);
}

TEST_F(SCAEventHandlerTest, StringToJsonArray_SingleValueWithSpaces)
{
    const std::string input = "   word   ";
    const nlohmann::json expected = {"word"};

    EXPECT_EQ(handler->StringToJsonArray(input), expected);
}

TEST_F(SCAEventHandlerTest, StringToJsonArray_ValuesWithTabs)
{
    const std::string input = "\tone\t,\ttwo\t";
    const nlohmann::json expected = {"one", "two"};

    EXPECT_EQ(handler->StringToJsonArray(input), expected);
}

TEST_F(SCAEventHandlerTest, NormalizeCheck)
{
    nlohmann::json check = {{"id", "1234"},
        {"refs", "ref1, ref2"},
        {"compliance", "cis:1.1.1, cis:1.1.2"},
        {"rules", "rule1, rule2"},
        {"policy_id", "my_policy"}
    };

    handler->NormalizeCheck(check);

    ASSERT_FALSE(check.contains("refs"));
    ASSERT_FALSE(check.contains("policy_id"));
    ASSERT_TRUE(check.contains("references"));
    ASSERT_TRUE(check.contains("compliance"));
    ASSERT_TRUE(check.contains("rules"));

    EXPECT_EQ(check["references"], nlohmann::json::array({"ref1", "ref2"}));
    EXPECT_EQ(check["compliance"], nlohmann::json::array({"cis:1.1.1", "cis:1.1.2"}));
    EXPECT_EQ(check["rules"], nlohmann::json::array({"rule1", "rule2"}));
}

TEST_F(SCAEventHandlerTest, NormalizePolicy)
{
    nlohmann::json policy =
    {
        {"id", "cis_001"}, {"name", "CIS Policy"}, {"refs", "https://cis.org, https://example.com"}
    };

    handler->NormalizePolicy(policy);

    ASSERT_FALSE(policy.contains("refs"));
    ASSERT_TRUE(policy.contains("references"));
    EXPECT_EQ(policy["references"], nlohmann::json::array({"https://cis.org", "https://example.com"}));
}


TEST_F(SCAEventHandlerTest, ReportPoliciesDelta_EmptyInput)
{
    std::vector<std::string> statefulMessages;
    std::vector<std::string> statelessMessages;

    auto mockPushStateful = [&statefulMessages](const std::string&, Operation_t, const std::string&, const std::string & message, uint64_t) -> int
    {
        statefulMessages.push_back(message);
        return 0;
    };

    auto mockPushStateless = [&statelessMessages](const std::string & message) -> int
    {
        statelessMessages.push_back(message);
        return 0;
    };

    SCAEventHandler realHandler(mockDBSync, mockPushStateless, mockPushStateful);

    std::unordered_map<std::string, nlohmann::json> emptyPolicies;
    std::unordered_map<std::string, nlohmann::json> emptyChecks;

    EXPECT_NO_THROW(
    {
        realHandler.ReportPoliciesDelta(emptyPolicies, emptyChecks);
    });

    // No messages should be pushed for empty input
    EXPECT_EQ(statefulMessages.size(), 0);
    EXPECT_EQ(statelessMessages.size(), 0);
}

TEST_F(SCAEventHandlerTest, ReportPoliciesDelta_ValidInput)
{
    std::vector<std::string> statefulMessages;
    std::vector<std::string> statelessMessages;

    auto mockPushStateful = [&statefulMessages](const std::string&, Operation_t, const std::string&, const std::string & message, uint64_t) -> int
    {
        statefulMessages.push_back(message);
        return 0;
    };

    auto mockPushStateless = [&statelessMessages](const std::string & message) -> int
    {
        statelessMessages.push_back(message);
        return 0;
    };

    auto newHandler = std::make_unique<sca_event_handler::SCAEventHandlerMock>(mockDBSync, mockPushStateless, mockPushStateful);

    EXPECT_CALL(*newHandler, GetChecksForPolicy("policy1"))
    .WillOnce(testing::Return(nlohmann::json::array(
    {
        {{"id", "check1"}, {"name", "Check 1"}, {"policy_id", "policy1"}},
        {{"id", "check2"}, {"name", "Check 2"}, {"policy_id", "policy1"}}
    })));

    EXPECT_CALL(*newHandler, GetPolicyById("policy2"))
    .WillOnce(testing::Return(nlohmann::json(
    {
        {"id", "policy2"},
        {"name", "Policy 2"},
        {"description", "Test Policy 2"},
        {"file", "policy2.yml"},
        {"refs", "https://example.com"}
    })));

    std::unordered_map<std::string, nlohmann::json> modifiedPolicies =
    {
        {
            "policy1", {
                {
                    "data", {
                        {"id", "policy1"},
                        {"name", "Test Policy 1"},
                        {"description", "Description 1"},
                        {"file", "policy1.yml"},
                        {"refs", "https://test.com"}
                    }
                },
                {"result", MODIFIED}
            }
        }
    };

    std::unordered_map<std::string, nlohmann::json> modifiedChecks =
    {
        {
            "check3", {
                {
                    "data", {
                        {
                            "new", {
                                {"id", "check3"},
                                {"policy_id", "policy2"},
                                {"name", "Check 3"},
                                {"result", "passed"}
                            }
                        }
                    }
                },
                {"result", MODIFIED}
            }
        }
    };

    EXPECT_NO_THROW(
    {
        newHandler->ReportPoliciesDelta(modifiedPolicies, modifiedChecks);
    });

    EXPECT_GT(statefulMessages.size(), 0);
    EXPECT_GT(statelessMessages.size(), 0);

    for (const auto& message : statefulMessages)
    {
        nlohmann::json parsedMessage = nlohmann::json::parse(message);
        EXPECT_TRUE(parsedMessage.contains("check"));
        EXPECT_TRUE(parsedMessage.contains("policy"));
        EXPECT_TRUE(parsedMessage.contains("checksum"));
    }

    for (const auto& message : statelessMessages)
    {
        nlohmann::json parsedMessage = nlohmann::json::parse(message);
        EXPECT_TRUE(parsedMessage.contains("data"));
        EXPECT_EQ(parsedMessage["module"], "sca");
        EXPECT_TRUE(parsedMessage["data"].contains("check"));
        EXPECT_TRUE(parsedMessage["data"].contains("policy"));
        EXPECT_TRUE(parsedMessage["data"].contains("event"));
    }
}

TEST_F(SCAEventHandlerTest, ReportCheckResult_ValidInput)
{
    const std::string policyId = "test_policy";
    const std::string checkId = "test_check";
    const std::string checkResult = "passed";

    EXPECT_CALL(*mockDBSync, syncRow(testing::_, testing::_))
    .WillOnce([checkResult](const nlohmann::json&, const std::function<void(ReturnTypeCallback, const nlohmann::json&)>& callback)
    {
        nlohmann::json returnData =
        {
            {
                "old", {
                    {"id", "test_check"},
                    {"result", "failed"},
                    {"name", "Test Check"}
                }
            },
            {
                "new", {
                    {"id", "test_check"},
                    {"result", checkResult},
                    {"name", "Test Check"}
                }
            }
        };
        callback(MODIFIED, returnData);
    });

    std::vector<std::string> statefulMessages;
    std::vector<std::string> statelessMessages;

    auto mockPushStateful = [&statefulMessages](const std::string&, Operation_t, const std::string&, const std::string & message, uint64_t) -> int
    {
        statefulMessages.push_back(message);
        return 0;
    };

    auto mockPushStateless = [&statelessMessages](const std::string & message) -> int
    {
        statelessMessages.push_back(message);
        return 0;
    };

    auto newHandler = std::make_unique<sca_event_handler::SCAEventHandlerMock>(mockDBSync, mockPushStateless, mockPushStateful);

    const nlohmann::json mockPolicy =
    {
        {"id", policyId},
        {"name", "Test Policy"},
        {"description", "Test Description"},
        {"file", "test.yml"},
        {"refs", "https://example.com"}
    };

    EXPECT_CALL(*newHandler, GetPolicyById(policyId))
    .WillOnce(testing::Return(mockPolicy));

    const nlohmann::json mockCheck =
    {
        {"id", checkId},
        {"policy_id", policyId},
        {"name", "Test Check"},
        {"description", "Test Check Description"},
        {"result", "failed"}
    };

    EXPECT_CALL(*newHandler, GetPolicyCheckById(checkId))
    .WillOnce(testing::Return(mockCheck));

    EXPECT_NO_THROW(
    {
        newHandler->ReportCheckResult(policyId, checkId, checkResult);
    });

    EXPECT_EQ(statefulMessages.size(), 1);
    EXPECT_EQ(statelessMessages.size(), 1);

    if (statefulMessages.size() > 0)
    {
        nlohmann::json statefulMessage = nlohmann::json::parse(statefulMessages[0]);
        EXPECT_TRUE(statefulMessage.contains("check"));
        EXPECT_TRUE(statefulMessage.contains("policy"));
        EXPECT_TRUE(statefulMessage.contains("checksum"));
        EXPECT_EQ(statefulMessage["check"]["result"], checkResult);
        EXPECT_EQ(statefulMessage["policy"]["id"], policyId);
    }

    if (statelessMessages.size() > 0)
    {
        nlohmann::json statelessMessage = nlohmann::json::parse(statelessMessages[0]);
        EXPECT_EQ(statelessMessage["module"], "sca");
        EXPECT_TRUE(statelessMessage["data"].contains("check"));
        EXPECT_TRUE(statelessMessage["data"].contains("policy"));
        EXPECT_TRUE(statelessMessage["data"].contains("event"));
        EXPECT_EQ(statelessMessage["data"]["check"]["result"], checkResult);
    }
}

TEST_F(SCAEventHandlerTest, GetPolicyCheckById_ValidId)
{
    const std::string checkId = "check123";
    auto mockResult = std::make_shared<nlohmann::json>(nlohmann::json::object(
    {
        {"id", checkId},
        {"name", "Test Check"},
        {"result", "passed"}
    }));

    EXPECT_CALL(*mockDBSync, selectRows(testing::_, testing::_))
    .WillOnce([mockResult](const nlohmann::json&,
                           const std::function<void(ReturnTypeCallback, const nlohmann::json&)>& cb)
    {
        cb(SELECTED, *mockResult);
    });

    const auto result = handler->GetPolicyCheckByIdTester(checkId);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result["id"], checkId);
}

TEST_F(SCAEventHandlerTest, GetPolicyCheckById_NonexistentId)
{
    const std::string checkId = "nonexistent";

    EXPECT_CALL(*mockDBSync, selectRows(testing::_, testing::_))
    .WillOnce([](const nlohmann::json&,
                 const std::function<void(ReturnTypeCallback, const nlohmann::json&)>& cb)
    {
        // Return empty result
        cb(SELECTED, nlohmann::json::object());
    });

    const auto result = handler->GetPolicyCheckByIdTester(checkId);
    EXPECT_TRUE(result.empty());
}


TEST_F(SCAEventHandlerTest, GetPolicyCheckById_NullDBSync)
{
    SCAEventHandlerMock nullHandler(nullptr);

    const auto result = nullHandler.GetPolicyCheckByIdTester("any-id");
    EXPECT_TRUE(result.empty());
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
