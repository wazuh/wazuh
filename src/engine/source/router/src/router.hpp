#ifndef _ROUTER_ROUTER_HPP
#define _ROUTER_ROUTER_HPP

#include <memory>
#include <shared_mutex>

#include <builder/ibuilder.hpp>

#include "table.hpp"
#include "irouter.hpp"

namespace router
{

/**
 * @copydoc IRouter
 */
class Router : public IRouter
{
private:
    class RuntimeEntry : public prod::Entry
    {
    private:
        std::unique_ptr<Environment> m_env; ///< The environment associated with the entry.

    public:
        explicit RuntimeEntry(const prod::EntryPost& entry)
            : prod::Entry(entry) {};

        const std::unique_ptr<Environment>& environment() const { return m_env; }
        std::unique_ptr<Environment>& environment() { return m_env; }
    };

    internal::Table<RuntimeEntry> m_table; ///< Internal table for managing Production Environments.
    mutable std::shared_mutex m_mutex;     ///< Mutex for the table.

    std::shared_ptr<EnvironmentBuilder> m_envBuilder; ///< Environment builder for create new entries

public:
    /**
     * @brief Constructs a Router with the specified environment builder.
     * @param envBuilder The shared pointer to the EnvironmentBuilder.
     */
    Router(const std::shared_ptr<EnvironmentBuilder>& envBuilder)
        : m_table()
        , m_mutex()
        , m_envBuilder(envBuilder) {};

    /**
     * @brief Constructs a Router with the specified builder.
     * @param builder The shared pointer to the IBuilder interface.
     */
    Router(const std::weak_ptr<builder::IBuilder>& builder, std::shared_ptr<bk::IControllerMaker> controllerMaker)
        : m_table()
        , m_mutex()
        , m_envBuilder(std::make_shared<EnvironmentBuilder>(builder, controllerMaker)) {};

    /**
     * @copydoc IRouter::addEntry
     */
    base::OptError addEntry(const prod::EntryPost& entryPost, bool ignoreFail = false) override;

    /**
     * @copydoc IRouter::removeEntry
     */
    base::OptError removeEntry(const std::string& name) override;

    /**
     * @copydoc IRouter::rebuildEntry
     */
    base::OptError rebuildEntry(const std::string& name) override;

    /**
     * @copydoc IRouter::enableEntry
     */
    base::OptError enableEntry(const std::string& name) override;

    /**
     * @copydoc IRouter::changePriority
     */
    base::OptError changePriority(const std::string& name, size_t priority) override;

    /**
     * @copydoc IRouter::getEntries
     */
    std::list<prod::Entry> getEntries() const override;

    /**
     * @copydoc IRouter::getEntry
     */
    base::RespOrError<prod::Entry> getEntry(const std::string& name) const override;

    /**
     * @copydoc IRouter::ingest
     */
    void ingest(base::Event&& event) override;
};

} // namespace router

#endif // ROUTER_ROUTER_HPP
