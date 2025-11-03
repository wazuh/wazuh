#pragma once

#include <idbsync.hpp>
#include "iagent_sync_protocol.hpp"
#include "commonDefs.h"

#include <json.hpp>

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

/// @brief Handles Security Configuration Assessment (SCA) events.
///
/// This class is responsible for processing and generating SCA events related to policy and check updates. It receives
/// maps of modified policies and checks, processes them to generate either stateful or stateless events, and dispatches
/// these events via a messaging callback.
///
/// Event types:
/// - Stateful: Full snapshot of the current state of a policy and check.
/// - Stateless: Delta event showing the fields that have changed.
// LCOV_EXCL_START
class SCAEventHandler
{
    public:
        /// @brief Constructor
        /// @param dBSync A shared pointer to a DBSync interface used for retrieving state info.
        /// @param pushStatelessMessage Callback function used to push stateless messages to the message queue.
        /// @param pushStatefulMessage Callback function used to push stateful messages to the message queue.
        SCAEventHandler(std::shared_ptr<IDBSync> dBSync = nullptr,
                        std::function<int(const std::string&)> pushStatelessMessage = nullptr,
                        std::function<int(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> pushStatefulMessage = nullptr);

        /// @brief Destructor
        virtual ~SCAEventHandler() = default;

        /// @brief Processes maps of modified policies and checks, and generates appropriate events.
        /// @param modifiedPoliciesMap Map of modified policies: { policy_id : policy_json }.
        /// @param modifiedChecksMap Map of modified checks: { check_id : check_json }.
        void ReportPoliciesDelta(const std::unordered_map<std::string, nlohmann::json>& modifiedPoliciesMap,
                                 const std::unordered_map<std::string, nlohmann::json>& modifiedChecksMap) const;

        /// @brief Reports the result of a check execution.
        /// @param policyId The ID of the policy associated with the check.
        /// @param checkId The ID of the check.
        /// @param checkResult Indicates the result of the check execution.
        /// @param reason Optional reason for invalid checks.
        void
        ReportCheckResult(const std::string& policyId, const std::string& checkId, const std::string& checkResult, const std::string& reason = "") const;

    protected:
        /// @brief Processes modified items and returns a list of events.
        ///
        /// Combines check and policy information to form complete event objects.
        ///
        /// @param modifiedPoliciesMap Map of modified policies.
        /// @param modifiedChecksMap Map of modified checks.
        /// @return List of event objects.
        nlohmann::json ProcessEvents(const std::unordered_map<std::string, nlohmann::json>& modifiedPoliciesMap,
                                     const std::unordered_map<std::string, nlohmann::json>& modifiedChecksMap) const;

        /// @brief Creates a stateful event from a full check and policy snapshot.
        ///
        /// The resulting event contains the entire check and policy structure and represents
        /// the current state.
        ///
        /// @param event JSON containing check and policy data.
        /// @return A tuple containing the stateful event object, the operation type, and the document version.
        std::tuple<nlohmann::json, ReturnTypeCallback, uint64_t> ProcessStateful(const nlohmann::json& event) const;

        /// @brief Creates a stateless event containing changed fields.
        ///
        /// Compares the "old" and "new" values in a check or policy to construct
        /// a event representing the delta.
        ///
        /// @param event JSON with previous and updated data.
        /// @return A new stateless event object.
        nlohmann::json ProcessStateless(const nlohmann::json& event) const;

        /// @brief Sends a stateful event using the push message callback.
        ///
        /// @param event The complete event data.
        /// @param operation The operation type for the stateful message.
        void PushStateful(const nlohmann::json& event, ReturnTypeCallback operation, uint64_t version) const;

        /// @brief Sends a stateless (delta) event using the push message callback.
        ///
        /// @param event The delta event data.
        void PushStateless(const nlohmann::json& event) const;

        /// @brief Calculates a unique hash ID for an event.
        ///
        /// The hash is based on the policy ID and check ID.
        ///
        /// @param data JSON containing the check and policy identifiers.
        /// @return SHA1 hash string.
        std::string CalculateHashId(const nlohmann::json& data) const;

        /// @brief Retrieves a list of checks associated with a specific policy from the database.
        ///
        /// @param policyId The ID of the policy.
        /// @return A vector of check JSON objects.
        virtual std::vector<nlohmann::json> GetChecksForPolicy(const std::string& policyId) const;

        /// @brief Retrieves a policy object from the database based on its ID.
        /// @param policyId The ID of the policy to retrieve.
        /// @return A JSON object representing the policy.
        virtual nlohmann::json GetPolicyById(const std::string& policyId) const;

        /// @brief Retrieves a policy check object from the database based on its ID.
        /// @param policyCheckId The ID of the policy check to retrieve.
        /// @return A JSON object representing the policy check.
        virtual nlohmann::json GetPolicyCheckById(const std::string& policyCheckId) const;

        /// @brief Splits a comma-separated string into a JSON array.
        /// @param input A string with elements separated by commas.
        /// @return A JSON array of elements.
        nlohmann::json StringToJsonArray(const std::string& input) const;

        /// @brief Normalizes the structure of a check JSON object.
        ///
        /// Converts fields like "refs", "rules", and "compliance" into arrays,
        /// and removes redundant fields like "policy_id".
        ///
        /// @param check The check JSON object to normalize.
        void NormalizeCheck(nlohmann::json& check) const;

        /// @brief Normalizes the structure of a policy JSON object.
        ///
        /// Ensures "refs" field is converted to an array.
        ///
        /// @param policy The policy JSON object to normalize.
        void NormalizePolicy(nlohmann::json& policy) const;

        /// @brief Callback function used to push stateless messages to the message queue.
        std::function<int(const std::string&)> m_pushStatelessMessage;

        /// @brief Callback function used to push stateful messages to the message queue.
        std::function<int(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> m_pushStatefulMessage;

    private:
        /// @brief Pointer to the IDBSync object for database synchronization.
        std::shared_ptr<IDBSync> m_dBSync;
};
// LCOV_EXCL_STOP
