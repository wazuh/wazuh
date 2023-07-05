#include "api/test/sessionManager.hpp"

#include <logging/logging.hpp>

namespace
{

using std::string;

}

namespace api::sessionManager
{

std::optional<base::Error> SessionManager::createSession(const string& sessionName,
                                                         const string& policyName,
                                                         const string& filterName,
                                                         const string& routeName,
                                                         const uint32_t sessionID,
                                                         const uint32_t lifespan,
                                                         const string& description,
                                                         const std::time_t creationDate)
{
    std::unique_lock<std::shared_mutex> lock(m_sessionMutex);

    // Check if the session name is already in use
    if (m_activeSessions.count(sessionName) > 0)
    {
        return base::Error {fmt::format(SESSION_NAME_ERROR_MSG, sessionName)};
    }

    // Check if the policy name is already in use
    if (m_policyMap.count(policyName) > 0)
    {
        return base::Error {fmt::format(POLICY_NAME_ERROR_MSG, policyName, m_policyMap[policyName])};
    }

    // Check if the filter name is already in use
    if (m_filterMap.count(filterName) > 0)
    {
        return base::Error {fmt::format(FILTER_NAME_ERROR_MSG, filterName, m_filterMap[filterName])};
    }

    // Check if the route name is already in use
    if (m_routeSet.count(routeName) > 0)
    {
        return base::Error {fmt::format(ROUTE_NAME_ERROR_MSG, routeName)};
    }

    // Check if the session ID is already in use
    if (m_idSet.count(sessionID) > 0)
    {
        return base::Error {fmt::format(SESSION_ID_ERROR_MSG, sessionID)};
    }

    Session session(sessionName, policyName, filterName, routeName, sessionID, lifespan, description, creationDate);

    m_activeSessions.emplace(sessionName, session);
    m_filterMap.emplace(filterName, routeName);
    m_policyMap.emplace(policyName, routeName);

    m_idSet.insert(sessionID);
    m_routeSet.insert(routeName);

    LOG_DEBUG(SESSION_DEBUG_MSG,
              sessionID,
              sessionName,
              creationDate,
              policyName,
              filterName,
              routeName,
              lifespan,
              description);

    return std::nullopt;
}

std::vector<string> SessionManager::getSessionsList(void)
{
    std::shared_lock<std::shared_mutex> lock(m_sessionMutex);

    std::vector<string> sessionNames;

    for (const auto& pair : m_activeSessions)
    {
        sessionNames.push_back(pair.first);
    }
    return sessionNames;
}

std::optional<Session> SessionManager::getSession(const string& sessionName)
{
    std::shared_lock<std::shared_mutex> lock(m_sessionMutex);

    auto it = m_activeSessions.find(sessionName);
    if (it != m_activeSessions.end())
    {
        return it->second;
    }
    return std::nullopt;
}

bool SessionManager::deleteSessions(const bool removeAll, const string sessionName)
{
    std::unique_lock<std::shared_mutex> lock(m_sessionMutex);

    bool sessionRemoved {false};

    if (removeAll)
    {
        m_activeSessions.clear();
        m_filterMap.clear();
        m_policyMap.clear();

        m_idSet.clear();
        m_routeSet.clear();

        sessionRemoved = true;
    }
    else
    {
        // Remove a specific session by sessionName
        auto sessionIt = m_activeSessions.find(sessionName);
        if (sessionIt != m_activeSessions.end())
        {
            const auto& filterName = sessionIt->second.getFilterName();
            const auto& policyName = sessionIt->second.getPolicyName();
            const auto& routeName = sessionIt->second.getRouteName();
            const auto& sessionID = sessionIt->second.getSessionID();

            m_activeSessions.erase(sessionIt);
            m_policyMap.erase(policyName);
            m_filterMap.erase(filterName);

            m_routeSet.erase(routeName);
            m_idSet.erase(sessionID);

            sessionRemoved = true;
        }
    }

    return sessionRemoved;
}

bool SessionManager::deleteSession(const string& sessionName)
{
    return deleteSessions(false, sessionName);
}

bool SessionManager::doesSessionExist(const std::string& sessionName)
{
    std::shared_lock<std::shared_mutex> lock(m_sessionMutex);

    bool doesExist {false};

    if (m_activeSessions.count(sessionName) > 0)
    {
        doesExist = true;
    }

    return doesExist;
}

uint32_t SessionManager::getNewSessionID(void)
{
    std::unique_lock<std::shared_mutex> lock(m_sessionMutex);

    uint32_t id = m_sessionIDCounter++;

    while (m_idSet.count(id) > 0 || 0 == id)
    {
        id = m_sessionIDCounter++;
    }

    return id;
}

} // namespace api::sessionManager
