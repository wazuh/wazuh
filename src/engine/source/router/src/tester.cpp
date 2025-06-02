#include "tester.hpp"

namespace
{
/**
 * @brief Return the current time in seconds since epoch
 */
inline int64_t getStartTime()
{
    auto startTime = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(startTime.time_since_epoch()).count();
}

} // namespace

namespace router
{

namespace test
{
class InternalOutput : public Output
{
private:
    std::unordered_map<std::string, std::list<DataPair>::iterator> m_dataMap;

public:
    InternalOutput()
        : Output()
        , m_dataMap()
    {
    }

    void addTrace(const std::string& asset,
                  const std::string& traceContent,
                  bool result,
                  const test::Options::TraceLevel level)
    {
        if (traceContent.empty())
        {
            return;
        }

        // Try inserting the asset into the map.
        auto [it, inserted] = m_dataMap.try_emplace(asset, m_traces.end());

        // If is new, insert it into the list.
        if (inserted)
        {
            m_traces.emplace_back(asset, Output::AssetTrace {});
            it->second = std::prev(m_traces.end());
        }

        auto& data = it->second->second;

        if (traceContent == "SUCCESS")
        {
            data.success = true;
        }
        else if (level == test::Options::TraceLevel::ALL)
        {
            data.traces.push_back(traceContent);
        }
    }
};
} // namespace test

base::OptError Tester::addEntry(const test::EntryPost& entryPost, bool ignoreFail, bool reverseOrderDecoders)
{
    auto entry = RuntimeEntry(entryPost);
    try
    {
        auto [controller, hash] = m_envBuilder->makeController(entry.policy(), true, true, reverseOrderDecoders);
        entry.controller() = controller;
        entry.hash(hash);
    }
    catch (const std::exception& e)
    {
        if (!ignoreFail)
        {
            return base::Error {fmt::format("Failed to create the testing environment: {}", e.what())};
        }
        entry.controller() = nullptr;
        entry.hash("");
    }
    entry.status(env::State::DISABLED); // It is disabled until all tester are ready
    entry.lifetime(entry.lifetime());

    // Add the entry to the table
    {
        std::unique_lock<std::shared_mutex> lock {m_mutex};
        if (m_table.find(entryPost.name()) != m_table.end())
        {
            return base::Error {"The name of the testing environment already exist"};
        }

        m_table.emplace(entryPost.name(), std::move(entry));
    }

    return std::nullopt;
}

base::OptError Tester::removeEntry(const std::string& name)
{
    std::unique_lock lock {m_mutex};
    auto it = m_table.find(name);
    if (it == m_table.end())
    {
        return base::Error {"The testing environment not exist"};
    }
    m_table.erase(it);
    return std::nullopt;
}

base::OptError Tester::rebuildEntry(const std::string& name)
{
    std::unique_lock lock {m_mutex};
    auto it = m_table.find(name);
    if (it == m_table.end())
    {
        return base::Error {"The testing environment not exist"};
    }
    auto& entry = it->second;
    try
    {
        auto [controller, hash] = m_envBuilder->makeController(entry.policy());
        entry.controller() = controller;
        entry.hash(hash);
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Failed to create the testing environment: {}", e.what())};
    }
    return std::nullopt;
}

base::OptError Tester::enableEntry(const std::string& name)
{
    std::unique_lock lock {m_mutex};
    auto it = m_table.find(name);
    if (it == m_table.end())
    {
        return base::Error {"The testing environment not exist"};
    }
    auto& entry = it->second;
    if (entry.controller() == nullptr)
    {
        return base::Error {"The testing environment is not builded"};
    }
    entry.status(env::State::ENABLED);
    return std::nullopt;
}

std::list<test::Entry> Tester::getEntries() const
{
    std::shared_lock lock {m_mutex};
    std::list<test::Entry> entries;
    for (const auto& [name, entry] : m_table)
    {
        entries.emplace_back(entry);
    }
    return entries;
}

base::RespOrError<test::Entry> Tester::getEntry(const std::string& name) const
{
    std::shared_lock lock {m_mutex};
    auto it = m_table.find(name);
    if (it == m_table.end())
    {
        return base::Error {"The testing environment not exist"};
    }
    return it->second;
}

// Testing
base::RespOrError<test::Output> Tester::ingestTest(base::Event&& event, const test::Options& opt)
{
    std::shared_lock lock {m_mutex};

    auto it = m_table.find(opt.environmentName());
    if (it == m_table.end())
    {
        return base::Error {"The testing environment not exist"};
    }
    auto& entry = it->second;

    if (entry.status() != env::State::ENABLED || entry.controller() == nullptr)
    {
        return base::Error {"The testing environment is not enabled"};
    }

    // Configure the environment
    auto result = std::make_shared<test::InternalOutput>();
    for (const auto& asset : opt.assets())
    {
        bk::Subscriber subFn = [asset, result, level = opt.traceLevel()](const std::string& trace, bool success) -> void
        {
            result->addTrace(asset, trace, success, level);
        };
        auto err = entry.controller()->subscribe(asset, subFn);
        if (base::isError(err))
        {
            entry.controller()->unsubscribeAll();
            return base::getError(err);
        }
    }

    // Run the test
    result->event() = entry.controller()->ingestGet(std::move(event));

    // Reset controller
    entry.controller()->unsubscribeAll();

    return *result;
}

base::RespOrError<std::unordered_set<std::string>> Tester::getAssets(const std::string& name) const
{
    std::shared_lock lock {m_mutex};
    auto it = m_table.find(name);
    if (it == m_table.end())
    {
        return base::Error {"The testing environment not exist"};
    }
    auto& entry = it->second;
    if (entry.status() != env::State::ENABLED || entry.controller() == nullptr)
    {
        return base::Error {"The testing environment is not builded"};
    }
    return entry.controller()->getTraceables();
}

bool Tester::updateLastUsed(const std::string& name, uint64_t lastUsed)
{
    std::unique_lock lock {m_mutex};
    auto it = m_table.find(name);
    if (it == m_table.end())
    {
        return false;
    }
    auto& entry = it->second;
    if (lastUsed == std::numeric_limits<uint64_t>::max())
    {
        entry.lastUse(getStartTime());
    }
    else
    {
        entry.lastUse(lastUsed);
    }
    return true;
}
} // namespace router
