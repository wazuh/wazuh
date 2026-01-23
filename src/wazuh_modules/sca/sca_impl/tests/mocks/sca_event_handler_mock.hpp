#pragma once

#include <gmock/gmock.h>

#include <sca_event_handler.hpp>
#include <commonDefs.h>
#include <dbsync.hpp>

#include <mock_dbsync.hpp>
#include <utility>

namespace sca_event_handler
{

    class SCAEventHandlerMock : public SCAEventHandler
    {
        public:
            SCAEventHandlerMock(const std::shared_ptr<MockDBSync>& mockDB,
                                std::function<int(const std::string&)> pushStatelessMessage = nullptr,
                                std::function<int(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> pushStatefulMessage = nullptr)
                : SCAEventHandler(mockDB, pushStatelessMessage, pushStatefulMessage)
                , mockDBSync(mockDB)
            {
            }

            std::string CalculateHashId(const nlohmann::json& data)
            {
                return SCAEventHandler::CalculateHashId(data);
            }

            nlohmann::json ProcessStateless(const nlohmann::json& event)
            {
                return SCAEventHandler::ProcessStateless(event);
            }

            std::tuple<nlohmann::json, ReturnTypeCallback, uint64_t> ProcessStateful(const nlohmann::json& event)
            {
                return SCAEventHandler::ProcessStateful(event);
            }

            nlohmann::json StringToJsonArray(const std::string& input)
            {
                return SCAEventHandler::StringToJsonArray(input);
            }

            nlohmann::json ProcessEvents(const std::unordered_map<std::string, nlohmann::json>& modifiedPoliciesMap,
                                         const std::unordered_map<std::string, nlohmann::json>& modifiedChecksMap)
            {
                return SCAEventHandler::ProcessEvents(modifiedPoliciesMap, modifiedChecksMap);
            }

            void NormalizeCheck(nlohmann::json& check)
            {
                return SCAEventHandler::NormalizeCheck(check);
            }

            std::vector<nlohmann::json> GetChecksForPolicy(const std::string& policyId)
            {
                return SCAEventHandler::GetChecksForPolicy(policyId);
            }

            nlohmann::json GetPolicyById(const std::string& policyId)
            {
                return SCAEventHandler::GetPolicyById(policyId);
            }

            void NormalizePolicy(nlohmann::json& policy)
            {
                return SCAEventHandler::NormalizePolicy(policy);
            }

            virtual nlohmann::json GetPolicyCheckByIdTester(const std::string& policyCheckId)
            {
                return SCAEventHandler::GetPolicyCheckById(policyCheckId);
            }

            // Public wrapper to expose protected ValidateAndHandleStatefulMessage for testing
            bool ValidateAndHandleStatefulMessage(const nlohmann::json& statefulEvent,
                                                  const std::string& context,
                                                  const nlohmann::json& checkData = nlohmann::json(),
                                                  std::vector<nlohmann::json>* failedChecks = nullptr) const
            {
                return SCAEventHandler::ValidateAndHandleStatefulMessage(statefulEvent, context, checkData, failedChecks);
            }

            // Helper method for testing: allows forcing validation to return specific checks as failed
            // This helps test the batch deletion with transaction logic for ReportPoliciesDelta
            void ReportPoliciesDeltaWithForcedFailures(
                const std::unordered_map<std::string, nlohmann::json>& modifiedPoliciesMap,
                const std::unordered_map<std::string, nlohmann::json>& modifiedChecksMap,
                const std::vector<nlohmann::json>& forcedFailedChecks)
            {
                const nlohmann::json events = ProcessEvents(modifiedPoliciesMap, modifiedChecksMap);

                // Use the forced failed checks directly
                std::vector<nlohmann::json> failedChecks = forcedFailedChecks;

                for (const auto& event : events)
                {
                    const auto [processedStatefulEvent, operation, version] = ProcessStateful(event);
                    // Skip validation, just push stateful
                    PushStateful(processedStatefulEvent, operation, version);

                    const auto processedStatelessEvent = ProcessStateless(event);

                    if (!processedStatelessEvent.empty())
                    {
                        PushStateless(processedStatelessEvent);
                    }
                }

                // Simulate batch delete with transaction (simplified for testing)
                if (!failedChecks.empty() && mockDBSync)
                {
                    // Call handle() to simulate getting transaction handle
                    mockDBSync->handle();

                    // Call deleteRows for each failed check
                    for (const auto& failedCheck : failedChecks)
                    {
                        auto deleteQuery = DeleteQuery::builder()
                                           .table("sca_check")
                                           .data(failedCheck)
                                           .build();

                        mockDBSync->deleteRows(deleteQuery.query());
                    }
                }
            }

            // Helper method for testing: simulates ReportCheckResult with forced validation failures
            // This helps test the batch deletion with transaction logic for ReportCheckResult
            void ReportCheckResultWithForcedFailures(
                const std::string& /* policyId */,
                const std::string& /* checkId */,
                const std::string& /* checkResult */,
                const nlohmann::json& mockCheckData,
                bool simulateValidationFailure)
            {
                if (!mockDBSync)
                {
                    return;
                }

                // List to accumulate checks that fail validation
                std::vector<nlohmann::json> failedChecks;

                if (simulateValidationFailure && !mockCheckData.empty())
                {
                    // Simulate validation failure
                    failedChecks.push_back(mockCheckData);
                }

                // Simulate batch delete with transaction (simplified for testing)
                if (!failedChecks.empty())
                {
                    // Call handle() to simulate getting transaction handle
                    mockDBSync->handle();

                    // Call deleteRows for each failed check
                    for (const auto& failedCheck : failedChecks)
                    {
                        auto deleteQuery = DeleteQuery::builder()
                                           .table("sca_check")
                                           .data(failedCheck)
                                           .build();

                        mockDBSync->deleteRows(deleteQuery.query());
                    }
                }
            }

            std::shared_ptr<MockDBSync> mockDBSync;

            MOCK_METHOD(std::vector<nlohmann::json>, GetChecksForPolicy, (const std::string& policyId), (const, override));
            MOCK_METHOD(nlohmann::json, GetPolicyById, (const std::string& policyId), (const, override));
            MOCK_METHOD(nlohmann::json, GetPolicyCheckById, (const std::string& policyId), (const, override));
    };

} // namespace sca_event_handler
