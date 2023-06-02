#ifndef _SESSIONS_MANAGER_HPP
#define _SESSIONS_MANAGER_HPP

#include <ctime>
#include <iostream>
#include <mutex>
#include <optional>
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
    const std::string m_filterName;
    const std::string m_policyName;
    const std::string m_routeName;
    const std::string m_sessionID;
    const std::string m_sessionName;
    const std::time_t m_creationDate;
    const uint32_t m_lifespan; ///< Session m_lifespan in seconds. 0 means no expiration.

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

    std::string getFilterName(void) const { return m_filterName; };
    std::string getPolicyName(void) const { return m_policyName; };
    std::string getRouteName(void) const { return m_routeName; };
    std::string getSessionID(void) const { return m_sessionID; };
    std::string getSessionName(void) const { return m_sessionName; };
    std::time_t getCreationDate(void) const { return m_creationDate; };
    uint32_t getLifespan(void) const { return m_lifespan; };

private:
    /// Generates a session ID based on the creation date.
    std::string generateSessionID(void) { return std::to_string(m_creationDate); }
};

class SessionManager
{
private:
    std::unordered_map<std::string, Session> m_activeSessions;
    std::unordered_map<std::string, std::string> m_policyMap;
    std::unordered_map<std::string, std::string> m_routeMap;

    std::mutex m_sessionMutex;

public:
    SessionManager() = default;
    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;

    static SessionManager& getInstance(void);

    std::optional<base::Error> createSession(const std::string& sessionName,
                                             const std::string& routeName,
                                             const std::string& policyName,
                                             uint32_t lifespan = 0);

    std::vector<std::string> getSessionsList(void);
    std::optional<Session> getSession(const std::string& sessionName);

    bool deleteSessions(const bool removeAll, const std::string sessionName = "");
    bool deleteAllSessions(void);
    bool deleteSession(const std::string& sessionName);
};

} // namespace api::sessionManager

#endif // _SESSIONS_MANAGER_HPP
