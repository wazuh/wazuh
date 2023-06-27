#ifndef _API_TEST_SESSION_HPP
#define _API_TEST_SESSION_HPP

#include <ctime>
#include <string>

namespace api::sessionManager
{

/**
 * @brief Session class.
 *
 */
struct Session
{
public:
    Session(const std::string& sessionName,
            const std::string& policyName,
            const std::string& filterName,
            const std::string& routeName,
            const uint32_t sessionID,
            const uint32_t lifespan,
            const std::string& description,
            const std::time_t creationDate)
        : m_creationDate(creationDate)
        , m_description(description)
        , m_filterName(filterName)
        , m_lifespan(lifespan)
        , m_policyName(policyName)
        , m_routeName(routeName)
        , m_sessionID(sessionID)
        , m_sessionName(sessionName)
    {
    }

    /**
     * @brief Get the session description.
     *
     * @return std::string
     */
    std::string getDescription(void) const { return m_description; };

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
     * @return uint32_t
     */
    uint32_t getSessionID(void) const { return m_sessionID; };

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
    const std::string m_description;  ///< Session description.
    const std::string m_filterName;   ///< Filter name.
    const std::string m_policyName;   ///< Policy name.
    const std::string m_routeName;    ///< Route name.
    const std::string m_sessionName;  ///< Session name.
    const std::time_t m_creationDate; ///< Session creation date.
    const uint32_t m_lifespan;        ///< Session m_lifespan in minutes. 0 means no expiration.
    const uint32_t m_sessionID;       ///< Session ID.
};

} // namespace api::sessionManager

#endif // _API_TEST_SESSION_HPP
