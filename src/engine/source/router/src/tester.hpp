#ifndef ROUTER_TESTER_HPP
#define ROUTER_TESTER_HPP

#include <list>
#include <memory>
#include <shared_mutex>
#include <unordered_map>

#include <bk/icontroller.hpp>

#include <router/types.hpp>

#include "environmentBuilder.hpp"
#include "itester.hpp"

namespace router
{

/**
 * @copydoc ITester
 */
class Tester : public ITester
{
private:
    class RuntimeEntry : public test::Entry
    {
    private:
        std::shared_ptr<bk::IController> m_controller; ///< Controller of the policy to be tested.

    public:
        explicit RuntimeEntry(const test::EntryPost& entry)
            : test::Entry(entry) {};

        ~RuntimeEntry()
        {
            if (m_controller)
            {
                m_controller->stop();
            }
        }

        // Move constructor
        RuntimeEntry(RuntimeEntry&& other) noexcept
            : test::Entry(std::move(other))
            , m_controller(std::move(other.m_controller))
        {
            other.m_controller = nullptr;
        };

        // Move assignment
        RuntimeEntry& operator=(RuntimeEntry&& other) noexcept
        {
            if (this != &other)
            {
                test::Entry::operator=(std::move(other));
                m_controller = std::move(other.m_controller);
                other.m_controller = nullptr;
            }
            return *this;
        }

        const std::shared_ptr<bk::IController>& controller() const { return m_controller; }
        std::shared_ptr<bk::IController>& controller() { return m_controller; }
    };

    std::shared_ptr<bk::IController> createController(const base::Name& policy);

    std::shared_ptr<EnvironmentBuilder> m_envBuilder;      ///< Shared pointer to the controller builder.
    std::unordered_map<std::string, RuntimeEntry> m_table; ///< Internal table for managing Testing Environments.
    mutable std::shared_mutex m_mutex;                     ///< Mutex for the table.

public:
    Tester(const std::shared_ptr<EnvironmentBuilder>& envBuilder)
        : m_envBuilder(envBuilder) {};

    /**
     * @copydoc ITester::addEntry
     */
    base::OptError addEntry(const test::EntryPost& entryPost, bool ignoreFail = false) override;

    /**
     * @copydoc ITester::removeEntry
     */
    base::OptError removeEntry(const std::string& name) override;

    /**
     * @copydoc ITester::rebuildEntry
     */
    base::OptError rebuildEntry(const std::string& name) override;

    /**
     * @copydoc ITester::enableEntry
     */
    base::OptError enableEntry(const std::string& name) override;

    /**
     * @copydoc ITester::getEntries
     */
    std::list<test::Entry> getEntries() const override;

    /**
     * @copydoc ITester::getEntry
     */
    base::RespOrError<test::Entry> getEntry(const std::string& name) const override;

    /**
     * @copydoc ITester::ingestTest
     */
    base::RespOrError<test::Output> ingestTest(base::Event&& event, const test::Options& opt) override;

    /**
     * @copydoc ITester::getAssets
     */
    base::RespOrError<std::unordered_set<std::string>> getAssets(const std::string& name) const override;

    /**
     * @copydoc ITester::updateLastUsed
     */
    bool updateLastUsed(const std::string& name, uint64_t lastUsed = std::numeric_limits<uint64_t>::max()) override;
};
} // namespace router

#endif // ROUTER_TESTER_HPP
