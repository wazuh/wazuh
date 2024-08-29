#ifndef _BUILDER_BUILDERS_STAGE_FILEOUTPUT_HPP
#define _BUILDER_BUILDERS_STAGE_FILEOUTPUT_HPP

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include <fmt/format.h>

#include "builders/types.hpp"

namespace builder::builders
{

namespace detail
{
/**
 * @brief implements a subscriber which will save all received events
 * of type E into a file. Needed to implement Destructor to close file.
 *
 *
 */
class FileOutput
{
protected:
    std::ofstream m_os;

public:
    /**
     * @brief Construct a new File Output object
     *
     * @param path file to store the events received
     */
    explicit FileOutput(const std::string& path)
        : m_os {path, std::ios::out | std::ios::app | std::ios::binary}
    {
        if (!this->m_os)
        {
            throw std::invalid_argument(fmt::format("Could not open file {}", path));
        }
    }

    /**
     * @brief Closes file if open
     *
     */
    ~FileOutput()
    {
        if (this->m_os.is_open())
        {
            this->m_os.close();
        }
    }

    /**
     * @brief Write event string to file
     *
     * @param e
     */
    void write(base::ConstEvent e) { this->m_os << e->str() << std::endl; }
};
} // namespace detail

base::Expression fileOutputBuilder(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_STAGE_FILEOUTPUT_HPP
