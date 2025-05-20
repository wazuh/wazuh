#ifndef ARCHIVER_ARCHIVER_HPP
#define ARCHIVER_ARCHIVER_HPP

#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>

#include <fmt/format.h>

#include <archiver/iarchiver.hpp>

namespace archiver
{

class Archiver final : public IArchiver
{
private:
    std::filesystem::path m_filePath;
    std::ofstream m_outFile;
    std::mutex m_mutex;           // Mutex for thread-safe file operations
    std::atomic<bool> m_isActive; // Atomic flag for activation state

public:
    explicit Archiver(const std::string& filePath, bool isActive = false)
        : m_filePath(filePath)
        , m_isActive(isActive)
    {
        if (!std::filesystem::exists(m_filePath.parent_path())
            || !std::filesystem::is_directory(m_filePath.parent_path()))
        {
            throw std::runtime_error(fmt::format("Directory does not exist: {}", m_filePath.parent_path().string()));
        }

        m_outFile.open(m_filePath, std::ios::out | std::ios::app);
        if (!m_outFile.is_open())
        {
            throw std::runtime_error(fmt::format("Failed to open file: {}", m_filePath.string()));
        }
    }

    /**
     * @brief Archives the given data if the archiver is active.
     *
     * @param data The data to archive.
     * @return base::OptError An optional error if the archiving fails.
     */
    base::OptError archive(const std::string& data) override
    {
        if (!m_isActive.load()) // Check activation state without locking
        {
            return base::noError();
        }

        std::lock_guard<std::mutex> lock(m_mutex); // Ensure thread-safe file operations

        if (!m_outFile.is_open())
        {
            return base::Error {fmt::format("File is not open: {}", m_filePath.string())};
        }

        m_outFile << data << '\n';
        if (m_outFile.fail())
        {
            return base::Error {fmt::format("Failed to write to file: {}", m_filePath.string())};
        }

        m_outFile.flush();

        return base::noError();
    }

    /**
     * @brief Activates the archiver.
     */
    void activate() override { m_isActive.store(true); }

    /**
     * @brief Deactivates the archiver.
     */
    void deactivate() override { m_isActive.store(false); }

    /**
     * @brief Checks if the archiver is active.
     *
     * @return true if the archiver is active, false otherwise.
     */
    bool isActive() const override { return m_isActive.load(); }

    ~Archiver() override
    {
        if (m_outFile.is_open())
        {
            m_outFile.close();
        }
    }
};

} // namespace archiver

#endif // ARCHIVER_ARCHIVER_HPP
