#ifndef _FILE_OUTPUT_H
#define _FILE_OUTPUT_H

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include <json/json.hpp>

namespace builder::internals::outputs
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
            throw std::invalid_argument("Engine outputs: File output \"" + path
                                        + "\" could not be opened.");
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
    void write(base::Event e)
    {
        this->m_os << e->str() << std::endl;
    }
};

} // namespace builder::internals::outputs

#endif // _FILE_OUTPUT_H
