#ifndef _OP_BUILDER_SCA_DECODER_H
#define _OP_BUILDER_SCA_DECODER_H

#include <sockiface/isockFactory.hpp>
#include <wdb/iwdbManager.hpp>

#include "builders/types.hpp"

namespace builder::builders::optransform
{

namespace sca
{

namespace field
{

/**
 * @brief Represents the field that contains the SCA event.
 */
enum class Name
{
    A_BEGIN,               ///< Not a field, only for iterate purposes
    ROOT = A_BEGIN,        ///< Root field
    CHECK_COMMAND,         ///< checkEvent
    CHECK_COMPLIANCE,      ///< checkEvent
    CHECK_CONDITION,       ///< checkEvent
    CHECK_DESCRIPTION,     ///< checkEvent
    CHECK_DIRECTORY,       ///< checkEvent
    CHECK_FILE,            ///< checkEvent
    CHECK_ID,              ///< checkEvent
    CHECK_PREVIOUS_RESULT, ///< checkEvent
    CHECK_PROCESS,         ///< checkEvent
    CHECK_RATIONALE,       ///< checkEvent
    CHECK_REASON,          ///< checkEvent
    CHECK_REFERENCES,      ///< checkEvent
    CHECK_REGISTRY,        ///< checkEvent
    CHECK_REMEDIATION,     ///< checkEvent
    CHECK_RESULT,          ///< checkEvent
    CHECK_RULES,           ///< checkEvent
    CHECK_TITLE,           ///< checkEvent
    CHECK,                 ///< checkEvent
    DESCRIPTION,           ///< scaninfo
    END_TIME,              ///< scaninfo
    ELEMENTS_SENT,         ///< DumpEvent
    FAILED,                ///< scaninfo
    FILE,                  ///< scaninfo
    FIRST_SCAN,            ///< scaninfo
    FORCE_ALERT,           ///< scaninfo
    HASH_FILE,             ///< scaninfo
    HASH,                  ///< scaninfo
    ID,                    ///< checkEvent
    INVALID,               ///< scaninfo
    NAME,                  ///< scaninfo
    PASSED,                ///< scaninfo
    POLICY_ID,             ///< scaninfo, checkEvent
    POLICY,                ///< checkEvent
    POLICIES,              ///< Policies
    REFERENCES,            ///< scaninfo
    SCAN_ID,               ///< scaninfo
    SCORE,                 ///< scaninfo
    START_TIME,            ///< scaninfo
    TOTAL_CHECKS,          ///< scaninfo
    TYPE,                  ///< checkEvent
    A_END                  ///< Not a field, only for iterate purposes
};

/**
 * @brief Iterates over the fields of the SCA event.
 */
Name& operator++(Name& field);

/**
 * @brief Get the Raw Path of the field.
 *
 * @param field Field to get the Raw Path.
 * @return relative path of the field.
 */
std::string getRealtivePath(Name field);

} // namespace field

/**
 * @brief Value for a SCA Find Query Operation.
 */
enum class SearchResult
{
    ERROR = -1, ///< Error on wdb or unexpected result.
    NOT_FOUND,  ///< Not found.
    FOUND       ///< Found.
};

/**
 * @brief Store all decoder information and context for processing the SCA Event.
 */
struct DecodeCxt
{
    base::Event& event;                        ///< Event to be processed.
    const std::string& agentID;                ///< Agent ID of the agent that generated the event.
    std::shared_ptr<wazuhdb::IWDBHandler> wdb; ///< WazuhDB instance.
    /** @brief Socket to forward dump request. */
    std::shared_ptr<sockiface::ISockHandler> forwarderSocket;
    /** @brief Mapping the field Name to path of the field in the Original Event. */
    const std::unordered_map<sca::field::Name, std::string>& sourcePath;
    /** @brief Mapping the field Name to path of the field in the /sca Event. */
    const std::unordered_map<sca::field::Name, std::string>& destinationPath;

    /**
     * @brief Get int value of a field.
     * @param field Field to get the value.
     * @return empty if the field is not found or the value is not an int
     */
    std::optional<int> getSrcInt(sca::field::Name field) const { return event->getInt64(sourcePath.at(field)); };

    /**
     * @brief Get number as a double value from a field.
     * @param field Field to get the value.
     * @return empty if the field is not found or the value is not a number
     */
    std::optional<double> getSrcNumberAsDouble(sca::field::Name field) const
    {
        return event->getNumberAsDouble(sourcePath.at(field));
    };

    /**
     * @brief Get string value of a field.
     * @param field Field to get the value.
     * @return empty if the field is not found or the value is
     * not a string.
     */
    std::optional<std::string> getSrcStr(sca::field::Name field) const
    {
        return event->getString(sourcePath.at(field));
    };

    /**
     * @brief Get int value of a field.
     * @param field Field to get the value.
     * @return Empty if the field is not found or the value is not an object.
     */
    std::optional<std::vector<std::tuple<std::string, json::Json>>> getSrcObject(sca::field::Name field) const
    {
        return event->getObject(sourcePath.at(field));
    };

    /**
     * @brief Get int value of a field.
     * @param field Field to get the value.
     * @return Empty if the field is not found or the value is not an array.
     */
    std::optional<std::vector<json::Json>> getSrcArray(sca::field::Name field) const
    {
        return event->getArray(sourcePath.at(field));
    };

    /**
     * @brief Check if a field is present in the original event.
     *
     * @param field Field to check.
     * @return true if the field is present.
     * @return false if the field is not present.
     */
    bool existsSrc(sca::field::Name field) const { return event->exists(sourcePath.at(field)); }
};

/****************************************************************************************
                                 Check Event
*****************************************************************************************/

/**
 * @brief Check if the event is a valid check event type.
 *
 * @param ctx The decoder context, decode info status.
 * @return true If the event is a valid check event type.
 * @return false If the event is not a valid check event type.
 */
bool isValidCheckEvent(const DecodeCxt& ctx);

/**
 * @brief Fill the /sca object with the check event info.
 *
 * @param ctx The decoder context, decode info status.
 * @param previousResult The previous result of scan.
 */
void fillCheckEvent(const DecodeCxt& ctx, const std::string& previousResult);

/**
 * @brief Insert compliance to wdb.
 *
 * @param ctx The decoder context, decode info status.
 * @param checkID The check ID to insert.
 */
void insertCompliance(const DecodeCxt& ctx, const int checkID);

/**
 * @brief Insert rules  to wdb
 *
 * @param ctx The decoder context, decode info status.
 * @param checkID The check ID to insert
 */
void insertRules(const DecodeCxt& ctx, const int checkID);

/****************************************************************************************
                                  Scan Info Event
*****************************************************************************************/
/**
 * @brief Check if the event is a valid scan event type.
 *
 * @param ctx The decoder context, decode info status.
 * @return true If the event is a valid scan event type
 * @return false If the event is not a valid scan event type
 */
bool isValidScanInfoEvent(const DecodeCxt& ctx);

/**
 * @brief Requesting dump for policy (db dump) through the cfg ar socket.
 *
 * @param ctx The decoder context, decode info status.
 * @param policyId The policy ID to request the dump.
 * @param firstScan If true, request the first scan dump, otherwise request the other scan
 * dump.
 */
void pushDumpRequest(const DecodeCxt& ctx, const std::string& policyId, bool firstScan);

/**
 * @brief Saves or updates the scan info in wdb.
 *
 * @param ctx The decoder context, decode info status.
 * @param update If true, update the scan info, otherwise insert it.
 * @return true If the wdb operation was successful.
 * @return false If the wdb operation was not successful.
 */
bool SaveScanInfo(const DecodeCxt& ctx, bool update);

/**
 * @brief Insert de policy to wdb.
 *
 * @param ctx The decoder context, decode info status.
 */
void insertPolicyInfo(const DecodeCxt& ctx);

/**
 * @brief Update the policy `policyId` in wdb.
 *
 * @param ctx The decoder context, decode info status.
 * @param policyId The policy ID to update.
 */
void updatePolicyInfo(const DecodeCxt& ctx, const std::string& policyId);

/**
 * @brief Find the check result in wdb and dump the policy if is necessary.
 *
 * @param ctx The decoder context, decode info status.
 * @param policyId The policy ID to find.
 * @param isFirstScan If true, request the first scan
 * @param eventHash The event hash to compare.
 */
void checkResultsAndDump(const DecodeCxt& ctx,
                         const std::string& policyId,
                         bool isFirstScan,
                         const std::string& eventHash);

/**
 * @brief Delete Policy and check from wdb.
 *
 * @param ctx The decoder context, decode info status.
 * @param policyId The policy ID to delete.
 * @return true If the wdb operation was successful.
 * @return false If the wdb operation was not successful.
 */
bool deletePolicyAndCheck(const DecodeCxt& ctx, const std::string& policyId);

/**
 * @brief Find the check result in wdb
 *
 * @param ctx The decoder context, decode info status.
 * @param policyId The policy ID to find.
 * @return std::tuple<SearchResult, std::string> The search result and the event hash.
 */
std::tuple<SearchResult, std::string> findCheckResults(const DecodeCxt& ctx, const std::string& policyId);

/**
 * @brief Fill the /sca object with the scan info event.
 *
 * @param ctx The decoder context, decode info status.
 */
void FillScanInfo(const DecodeCxt& ctx);

/****************************************************************************************
                                  Dump Event
*****************************************************************************************/

/**
 * @brief Check if the event is a valid dump event type.
 *
 * @param ctx The decoder context, decode info status.
 * @return true If the event is a valid dump event type.
 * @return false If the event is not a valid dump event type.
 */
std::tuple<std::optional<std::string>, std::string, int> isValidDumpEvent(const DecodeCxt& ctx);

/**
 * @brief Delete check distinct policy id
 *
 * @param ctx The decoder context, decode info status.
 * @param policyId The policy ID to delete.
 * @param scanId The scan ID to delete.
 */
void deletePolicyCheckDistinct(const DecodeCxt& ctx, const std::string& policyId, const int scanId);

/****************************************************************************************
                                  Handlers
*****************************************************************************************/

/**
 * @brief Handler for the events of 'check' type.
 *
 * @param ctx The decoder context, decode info status.
 * @return returns a string with the error message if an error occurred. Otherwise,
 * returns an empty optional.
 */
std::optional<std::string> handleCheckEvent(const DecodeCxt& ctx);

/**
 * @brief Handler for the events of 'summary' type.
 *
 * @param ctx The decoder context, decode info status.
 * @return returns a string with the error message if an error occurred. Otherwise,
 * returns an empty optional.
 */
std::optional<std::string> handleScanInfo(const DecodeCxt& ctx);

/**
 * @brief Handler for the events of 'policies' type.
 *
 * @param ctx The decoder context, decode info status.
 * @return returns a string with the error message if an error occurred. Otherwise,
 * returns an empty optional.
 */
std::optional<std::string> handlePoliciesInfo(const DecodeCxt& ctx);

/**
 * @brief Handler for the events of 'dump_end' type.
 *
 * @param ctx The decoder context, decode info status.
 * @return returns a string with the error message if an error occurred. Otherwise,
 * returns an empty optional.
 */
std::optional<std::string> handleDumpEvent(const DecodeCxt& ctx);

} // namespace sca

/**
 * @brief SCA Decoder
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @return base::Expression true when executes without any problem, false otherwise.
 */
TransformBuilder getBuilderSCAdecoder(const std::shared_ptr<wazuhdb::IWDBManager>& wdbManager,
                                      const std::shared_ptr<sockiface::ISockFactory>& sockFactory);

} // namespace builder::builders::optransform

#endif // _OP_BUILDER_SCA_DECODER_H
