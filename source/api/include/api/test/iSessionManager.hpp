#ifndef _API_I_SESSION_MANAGER_HPP
#define _API_I_SESSION_MANAGER_HPP

#include <optional>
#include <string>
#include <vector>

#include <error.hpp>

#include "session.hpp"

namespace api::sessionManager
{

/**
 * @brief Session Manager interface. Defines the methods that a Session Manager must implement.
 *
 */
class ISessionManager
{
public:
    ISessionManager() = default;
    virtual ~ISessionManager() = default;
    ISessionManager(const ISessionManager&) = delete;
    ISessionManager& operator=(const ISessionManager&) = delete;

    /**
     * @brief Create a new session.
     *
     * @param sessionName Name of the session.
     * @param routeName Name of the route.
     * @param policyName Name of the policy.
     * @param lifespan Lifespan of the session in seconds. 0 means no expiration.
     * @return std::optional<base::Error>
     */
    virtual std::optional<base::Error> createSession(const std::string& sessionName,
                                                     const std::string& policyName,
                                                     const std::string& filterName,
                                                     const std::string& routeName,
                                                     uint32_t lifespan = 0,
                                                     const std::string& description = "",
                                                     const std::time_t creationDate = std::time(nullptr),
                                                     const std::string& sessionID = "") = 0;

    /**
     * @brief Get the list of active sessions.
     *
     * @return std::vector<std::string>
     */
    virtual std::vector<std::string> getSessionsList(void) = 0;

    /**
     * @brief Get the session object.
     *
     * @param sessionName Name of the session.
     * @return std::optional<Session>
     */
    virtual std::optional<Session> getSession(const std::string& sessionName) = 0;

    /**
     * @brief Check if a session exists.
     *
     * @param sessionName Name of the session.
     * @return true the session exists.
     * @return false the session does not exist.
     */
    virtual bool doesSessionExist(const std::string& sessionName) = 0;

    virtual bool deleteSessions(const bool removeAll, const std::string sessionName = "") = 0;
    /**
     * @brief Delete a session.
     *
     * @param sessionName Name of the session.
     * @return true if the session was deleted.
     * @return false if the session could not be deleted.
     */
    virtual bool deleteSession(const std::string& sessionName) = 0;
};

} // namespace api::sessionManager

#endif // _API_I_SESSION_MANAGER_HPP
