#ifndef _SESSIONS_MANAGER_HPP
#define _SESSIONS_MANAGER_HPP

#include <ctime>
#include <iostream>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <fmt/format.h>

#include <error.hpp>

namespace api::sessionManager
{

constexpr auto FILTER_CONTENT_FORMAT =
    R"({{"name": "{}", "check":[{{"~TestSessionName":"{}"}}]}})"; ///< Filter content format, where '{}' is the session
                                                                  ///< name
constexpr auto FILTER_NAME_FORMAT = "filter/test-{}/0"; ///< Filter name format, where '{}' is the session name
constexpr auto ROUTE_NAME_FORMAT = "{}_route";          ///< Route name format, where '{}' is the session name

struct Session
{
public:
    Session(const std::string& name, const std::string& policy, const std::string& route, const uint32_t lifespan = 0)
        : m_creationDate(std::time(nullptr))
        , m_filterName(fmt::format(FILTER_NAME_FORMAT, name))
        , m_lifespan(lifespan)
        , m_policyName(policy)
        , m_routeName(route)
        , m_sessionID(generateSessionID())
        , m_sessionName(name)
    {
    }

    /**
     * @brief Get the filter name.
     *
     * @return std::string
     */
    std::string getFilterName(void) const { return m_filterName; };

    /**
     * @brief Get the policy name.
     *
     * @return std::string
     */
    std::string getPolicyName(void) const { return m_policyName; };

    /**
     * @brief Get the route name.
     *
     * @return std::string
     */
    std::string getRouteName(void) const { return m_routeName; };

    /**
     * @brief Get the session ID.
     *
     * @return std::string
     */
    std::string getSessionID(void) const { return m_sessionID; };

    /**
     * @brief Get the session name.
     *
     * @return std::string
     */
    std::string getSessionName(void) const { return m_sessionName; };

    /**
     * @brief Get the session creation date.
     *
     * @return std::time_t
     */
    std::time_t getCreationDate(void) const { return m_creationDate; };

    /**
     * @brief Get the session lifespan.
     *
     * @return uint32_t
     */
    uint32_t getLifespan(void) const { return m_lifespan; };

private:
    const std::string m_filterName;
    const std::string m_policyName;
    const std::string m_routeName;
    const std::string m_sessionID;
    const std::string m_sessionName;
    const std::time_t m_creationDate;
    const uint32_t m_lifespan; ///< Session m_lifespan in seconds. 0 means no expiration.

    /**
     * @brief Generates a session ID based on the creation date.
     *
     * @return std::string
     */
    std::string generateSessionID(void) { return std::to_string(m_creationDate); }
};

class SessionManager
{
private:
    std::unordered_map<std::string, Session> m_activeSessions;
    std::unordered_map<std::string, std::string> m_policyMap;
    std::unordered_map<std::string, std::string> m_routeMap;

    std::shared_mutex m_sessionMutex;

public:
    SessionManager() = default;
    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;

    /**
     * @brief Get a Session Manager instance.
     *
     * @return SessionManager&
     */
    static SessionManager& getInstance(void);

    /**
     * @brief Create a new session.
     *
     * @param sessionName Name of the session.
     * @param routeName Name of the route.
     * @param policyName Name of the policy.
     * @param lifespan Lifespan of the session in seconds. 0 means no expiration.
     * @return std::optional<base::Error>
     */
    std::optional<base::Error> createSession(const std::string& sessionName,
                                             const std::string& routeName,
                                             const std::string& policyName,
                                             uint32_t lifespan = 0);

    /**
     * @brief Get the list of active sessions.
     *
     * @return std::vector<std::string>
     */
    std::vector<std::string> getSessionsList(void);

    /**
     * @brief Get the session object.
     *
     * @param sessionName Name of the session.
     * @return std::optional<Session>
     */
    std::optional<Session> getSession(const std::string& sessionName);

    /**
     * @brief Check if a session exists.
     *
     * @param sessionName Name of the session.
     * @return true the session exists.
     * @return false the session does not exist.
     */
    bool doesSessionExist(const std::string& sessionName);

    bool deleteSessions(const bool removeAll, const std::string sessionName = "");
    bool deleteAllSessions(void);
    /**
     * @brief Delete a session.
     *
     * @param sessionName Name of the session.
     * @return true if the session was deleted.
     * @return false if the session could not be deleted.
     */
    bool deleteSession(const std::string& sessionName);
};

} // namespace api::sessionManager

#endif // _SESSIONS_MANAGER_HPP
