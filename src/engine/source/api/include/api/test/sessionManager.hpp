#ifndef _SESSIONS_MANAGER_HPP
#define _SESSIONS_MANAGER_HPP

#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <error.hpp>

#include "session.hpp"

namespace api::sessionManager
{

/**
 * @brief Session Manager class. Implements the ISessionManager interface.
 *
 */
class SessionManager
{
private:
    std::unordered_map<std::string, Session> m_activeSessions; ///< Map of active sessions
    std::unordered_map<std::string, std::string> m_policyMap;  ///< Map of active policies
    std::unordered_map<std::string, std::string> m_routeMap;   ///< Map of active routes
    std::unordered_map<std::string, std::string> m_filterMap;  ///< Map of active filter

    std::shared_mutex m_sessionMutex;                          ///< Mutex to protect the sessions resources usage

public:
    /**
     * @brief Get a Session Manager instance.
     *
     * @return SessionManager&
     */
    static SessionManager& getInstance(void);

    /**
     * @copydoc ISessionManager::createSession
     */
    std::optional<base::Error> createSession(const std::string& sessionName,
                                             const std::string& policyName,
                                             const std::string& filterName,
                                             const std::string& routeName,
                                             uint32_t lifespan = 0,
                                             const std::string& description = "",
                                             const std::time_t creationDate = std::time(nullptr),
                                             const std::string& sessionID = "");

    /**
     * @copydoc ISessionManager::getSessionsList
     */
    std::vector<std::string> getSessionsList(void);

    /**
     * @copydoc ISessionManager::getSession
     */
    std::optional<Session> getSession(const std::string& sessionName);

    /**
     * @copydoc ISessionManager::doesSessionExist
     */
    bool doesSessionExist(const std::string& sessionName);

    /**
     * @copydoc ISessionManager::deleteSessions
     */
    bool deleteSessions(const bool removeAll, const std::string sessionName = "");

    /**
     * @copydoc ISessionManager::deleteSession
     */
    bool deleteSession(const std::string& sessionName);
};

} // namespace api::sessionManager

#endif // _SESSIONS_MANAGER_HPP
