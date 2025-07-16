#pragma once

#include <gmock/gmock.h>

#include <sca_event_handler.hpp>

#include "mockdbsync.hpp"

namespace sca_event_handler
{

    class SCAEventHandlerMock : public SCAEventHandler
    {
    public:
        SCAEventHandlerMock(const std::shared_ptr<MockDBSync>& mockDB)
            : SCAEventHandler("agent-uuid", mockDB)
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

        nlohmann::json ProcessStateful(const nlohmann::json& event)
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

        std::shared_ptr<MockDBSync> mockDBSync;

        MOCK_METHOD(std::vector<nlohmann::json>, GetChecksForPolicy, (const std::string& policyId), (const, override));
        MOCK_METHOD(nlohmann::json, GetPolicyById, (const std::string& policyId), (const, override));
    };

} // namespace sca_event_handler
