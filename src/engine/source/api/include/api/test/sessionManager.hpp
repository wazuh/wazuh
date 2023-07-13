#ifndef _API_TEST_SESSION_MANAGER_HPP
#define _API_TEST_SESSION_MANAGER_HPP

#include <atomic>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <error.hpp>

#include "session.hpp"

namespace api::sessionManager
{

constexpr auto FILTER_NAME_ERROR_MSG = "Filter '{}' is already assigned to a route '{}'";
constexpr auto POLICY_NAME_ERROR_MSG = "Policy '{}' is already assigned to a route '{}'";
constexpr auto ROUTE_NAME_ERROR_MSG = "Route name '{}' already exists";
constexpr auto SESSION_ID_ERROR_MSG = "Session ID '{}' already exists";
constexpr auto SESSION_NAME_ERROR_MSG = "Session name '{}' already exists";

constexpr auto SESSION_DEBUG_MSG = "Session created: ID={}, Name={}, Creation Date={}, Policy Name={}, Filter Name={}, "
                                   "Route Name={}, Life Span={}, Description='{}'\n";

/**
 * @brief Session Manager class.
 */
class SessionManager
{
private:
    std::unordered_map<std::string, Session> m_activeSessions; ///< Map of active sessions
    std::unordered_map<std::string, std::string> m_filterMap;  ///< Map of active filter
    std::unordered_map<std::string, std::string> m_policyMap;  ///< Map of active policies

    std::unordered_set<std::string> m_routeSet;                ///< Set of active routes
    std::unordered_set<uint32_t> m_idSet;                      ///< Set of active filter

    uint32_t m_sessionIDCounter;      ///< This counter is used to provide a unique ID to each session

    std::shared_mutex m_sessionMutex; ///< Mutex to protect the sessions resources usage

public:
    /**
     * @brief Construct a new Session Manager object
     *
     */
    SessionManager()
        : m_sessionIDCounter {0}
    {
    }

    /**
     * @brief Create a session.
     *
     * @param sessionName Session name
     * @param policyName Policy name
     * @param filterName Filter name
     * @param routeName Route name
     * @param sessionID Session ID
     * @param lifespan Session lifespan
     * @param description Session description
     * @param creationDate Session creation date
     * @return std::optional<base::Error> If the session was not created, the error message will be returned
     */
    std::optional<base::Error> createSession(const std::string& sessionName,
                                             const std::string& policyName,
                                             const std::string& filterName,
                                             const std::string& routeName,
                                             const uint32_t sessionID,
                                             const uint32_t lifespan = 0,
                                             const std::string& description = "",
                                             const std::time_t creationDate = std::time(nullptr));

    /**
     * @brief Get a new available session ID.
     *
     * @return uint32_t Available session ID
     */
    uint32_t getNewSessionID();

    /**
     * @brief Get the sessions List
     *
     * @return std::vector<std::string>
     */
    std::vector<std::string> getSessionsList();

    /**
     * @brief Get a session's data.
     *
     * @param sessionName Session name
     * @return std::optional<Session>
     */
    std::optional<Session> getSession(const std::string& sessionName);

    /**
     * @brief Check if a session exists.
     *
     * @param sessionName Session name
     * @return true If the session exists
     * @return false If the session does not exist
     */
    bool doesSessionExist(const std::string& sessionName);

    /**
     * @brief Delete all sessions.
     *
     * @param removeAll If true, all sessions will be deleted. If false, only the specified session will be deleted.
     * @param sessionName If not empty and removeAll is false, the session with this name will be deleted.
     * @return true If the sessions were deleted
     * @return false If the sessions were not deleted
     */
    bool deleteSessions(const bool removeAll, const std::string& sessionName = "");

    /**
     * @brief Delete a session.
     *
     * @param sessionName Session name to be deleted
     * @return true If the session was deleted
     * @return false If the session was not deleted
     */
    bool deleteSession(const std::string& sessionName);
};

} // namespace api::sessionManager

#endif // _API_TEST_SESSION_MANAGER_HPP
