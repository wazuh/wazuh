#ifndef _API_SESSION_HPP
#define _API_SESSION_HPP

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
            const uint32_t lifespan = 0,
            const std::string& description = "")
        : m_creationDate(std::time(nullptr))
        , m_description(description)
        , m_filterName(filterName)
        , m_lifespan(lifespan)
        , m_policyName(policyName)
        , m_routeName(routeName)
        , m_sessionID(generateSessionID())
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
    const std::string m_description;
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

} // namespace api::sessionManager

#endif // _API_SESSION_HPP
