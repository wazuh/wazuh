#ifndef _SESSIONS_MANAGER_HPP
#define _SESSIONS_MANAGER_HPP

#include <ctime>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <error.hpp>

namespace api::sessionManager
{

using std::string;

struct Session
{
public:
    const string m_policyName;
    const string m_routeName;
    const string m_sessionID;
    const string m_sessionName;
    const std::time_t m_creationDate;
    const uint32_t m_lifespan; ///< Session m_lifespan in seconds. 0 means no expiration.

    Session(const string& name, const string& policy, const string& route, const uint32_t lifespan = 0)
        : m_sessionName(name)
        , m_policyName(policy)
        , m_routeName(route)
        , m_lifespan(lifespan)
        , m_creationDate(std::time(nullptr))
        , m_sessionID(generateSessionID())
    {
    }

    string getPolicyName(void) const { return m_policyName; };
    string getRouteName(void) const { return m_routeName; };
    string getSessionID(void) const { return m_sessionID; };
    string getSessionName(void) const { return m_sessionName; };
    std::time_t getCreationDate(void) const { return m_creationDate; };
    uint32_t getLifespan(void) const { return m_lifespan; };

private:
    /// Generates a session ID based on the creation date.
    string generateSessionID(void) { return std::to_string(m_creationDate); }
};

class SessionManager
{
private:
    std::unordered_map<string, Session> m_activeSessions;
    std::unordered_map<string, string> m_policyMap;
    std::unordered_map<string, string> m_routeMap;

    std::mutex m_sessionMutex;

public:
    SessionManager() = default;
    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;

    static SessionManager& getInstance(void);

    std::optional<base::Error>
    createSession(const string& sessionName, const string& policyName, uint32_t lifespan = 0);

    std::vector<string> getSessionsList(void);
    std::optional<Session> getSession(const string& sessionName);

    bool removeSessions(const bool removeAll, const string sessionName = "");
    bool removeAllSessions(void);
    bool removeSession(const string& sessionName);
};

} // namespace api::sessionManager

#endif // _SESSIONS_MANAGER_HPP
