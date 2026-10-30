// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _BASE_TEST_LOGCAPTURE_HPP
#define _BASE_TEST_LOGCAPTURE_HPP

#include <algorithm>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

#include <spdlog/sinks/base_sink.h>

#include <base/logging.hpp>

namespace base::test
{
// Inside namespace base, an unqualified logging:: finds base::logging (base/managerLogSink.hpp), so every
// reference to the logging front-end is globally qualified, as managerLogSink.hpp itself does.

/**
 * @brief Records the log messages emitted while it is alive, so a test can assert on them.
 *
 * It adds one more sink to the logger `logging::testInit()` starts and takes it off again on
 * destruction, restoring the level it found: nothing in the production path changes, and a test
 * that builds no LogCapture logs exactly as before.
 *
 * Only standalone mode reaches the spdlog logger (see `logging::backend_log()`), which is the mode
 * `logging::testInit()` primes; a test that forces manager mode captures nothing here and has to
 * read the manager sink instead.
 *
 * Build and destroy it on the thread under test, before any other thread logs: it adds and removes its
 * sink in `spdlog::logger::sinks()`, which the logger iterates without a lock. Nested captures have to
 * be destroyed in reverse order of construction, or the level the outer one found is not the one restored.
 *
 * `logging::testInit()` also leaves `WAZUH_ENGINE_STANDALONE=true` in the process environment and the
 * destructor does not undo it: the value is cached on first use, so unsetting it would change nothing.
 *
 * @code
 * base::test::LogCapture capture {logging::Level::Debug};
 * somethingThatLogs();
 * ASSERT_EQ(capture.records(logging::Level::Warn).size(), 1);
 * @endcode
 */
class LogCapture
{
public:
    /**
     * @brief One captured record: the level it was emitted at and the message, without the header.
     */
    struct Record
    {
        ::logging::Level level; ///< Level of the logging macro that emitted it.
        std::string message;    ///< Message as composed by the caller (no timestamp, no source location).
    };

    /**
     * @brief Starts capturing, holding the logger at @p level while the object lives.
     *
     * @param level Lowest level to capture; the default takes everything the LOG_* macros emit.
     */
    explicit LogCapture(::logging::Level level = ::logging::Level::Trace)
    {
        ::logging::testInit(level);
        // The standalone flag is cached on first use, so anything that logged before the first capture
        // froze it to false and the setenv above came too late: every record would go to the manager
        // sink and records() would come back empty, passing an emptiness assertion for the wrong reason.
        if (!::base::process::isStandaloneModeEnable())
        {
            throw std::runtime_error {
                "LogCapture: the process is not in standalone mode, so nothing would be captured"};
        }

        m_logger = ::logging::getDefaultLogger();
        m_previousLevel = ::logging::getLevel();
        ::logging::setLevel(level);

        m_sink = std::make_shared<Sink>();
        m_logger->sinks().push_back(m_sink);
    }

    // Holding the logger rather than looking it up again keeps this from throwing when a test
    // stopped logging while the capture was alive.
    ~LogCapture()
    {
        auto& sinks = m_logger->sinks();
        sinks.erase(std::remove(sinks.begin(), sinks.end(), m_sink), sinks.end());
        m_logger->set_level(::logging::SEVERITY_LEVEL.at(m_previousLevel));
    }

    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;

    /**
     * @brief Every record captured so far, in emission order.
     */
    std::vector<Record> records() const { return m_sink->records(); }

    /**
     * @brief The records captured so far at @p level, in emission order.
     *
     * @param level Level to select.
     */
    std::vector<Record> records(::logging::Level level) const
    {
        std::vector<Record> selected;
        for (auto& record : m_sink->records())
        {
            if (record.level == level)
            {
                selected.push_back(record);
            }
        }

        return selected;
    }

    /**
     * @brief Drops what was captured so far, to tell the records of one step of a test from the next.
     */
    void clear() { m_sink->clear(); }

private:
    class Sink : public spdlog::sinks::base_sink<std::mutex>
    {
    public:
        std::vector<Record> records()
        {
            std::lock_guard<std::mutex> lock(this->mutex_);
            return m_records;
        }

        void clear()
        {
            std::lock_guard<std::mutex> lock(this->mutex_);
            m_records.clear();
        }

    protected:
        void sink_it_(const spdlog::details::log_msg& message) override
        {
            m_records.push_back(
                Record {toLevel(message.level), std::string(message.payload.data(), message.payload.size())});
        }

        void flush_() override {}

    private:
        // The logging front-end only maps Level to spdlog level (::logging::SEVERITY_LEVEL); a record
        // carries the spdlog one, and a test asserts on the Level it wrote in the macro.
        static ::logging::Level toLevel(spdlog::level::level_enum level)
        {
            for (const auto& [mapped, spdLevel] : ::logging::SEVERITY_LEVEL)
            {
                if (spdLevel == level)
                {
                    return mapped;
                }
            }

            return ::logging::Level::Invalid;
        }

        std::vector<Record> m_records;
    };

    std::shared_ptr<spdlog::logger> m_logger;
    std::shared_ptr<Sink> m_sink;
    ::logging::Level m_previousLevel;
};

} // namespace base::test

#endif // _BASE_TEST_LOGCAPTURE_HPP
