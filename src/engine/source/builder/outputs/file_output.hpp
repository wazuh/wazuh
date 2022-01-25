#ifndef _FILE_OUTPUT_H
#define _FILE_OUTPUT_H

#include "rxcpp/rx.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

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
    explicit FileOutput(const std::string & path) : m_os{path, std::ios::out | std::ios::app | std::ios::binary}
    {
        if (!this->m_os)
        {
            throw std::invalid_argument("File output cannot open file " + path);
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
    void write(const json::Document & e)
    {
        this->m_os << e.str() << std::endl;
    }
};

/**
 * @brief A buffered file output will store some events and then write them all
 * on a loop.
 *
 * @tparam E
 */
// template <class E> class BufferedFileOutput : public FileOutput<E>
// {
// private:
//     int m_buffsize;

// public:
//     /**
//      * @brief Construct a new Buffered File Output object
//      *
//      * @param filepath file to store events
//      * @param buffsize number of events to group before start writting
//      */
//     BufferedFileOutput(std::string filepath, int buffsize) : FileOutput<E>{filepath}, m_buffsize{buffsize} {};

//     auto subscriber()
//     {
//         if (!this->m_isWritting)
//         {
//             this->m_obs.buffer(this->m_buffsize)
//                 .subscribe(
//                     [&](std::vector<E> v) {
//                         std::for_each(std::begin(v), std::end(v),
//                                       [&](E item) { this->m_os << item.str() << std::endl; });
//                     },
//                     [&]() { this->m_os.close(); });
//         }
//         this->m_isWritting = true;
//         return this->m_subj.get_subscriber();
//     }
// };

// /**
//  * @brief A rotating file output. It will write all events of type E
//  * into a file until it exceeds the bytes limit. Then it will rename the current file
//  * to file.X where X is a positive number starting from 0, adn continue writting
//  * the new events on the mail filename.
//  *
//  * @tparam E
//  */
// template <class E> class RotatingFileOutput : public FileOutput<E>
// {
// private:
//     int m_fileIndex{0};
//     // 2 GB default limit
//     std::uintmax_t m_sizeLimit{2 << 30};
//     std::uintmax_t m_pos{0};

//     auto move()
//     {
//         this->m_os.close();
//         auto newName = std::filesystem::path(this->m_name + "." + std::to_string(this->m_fileIndex));
//         this->m_fileIndex += 1;
//         std::filesystem::rename(this->m_filepath, newName);
//         this->m_pos = 0;
//         this->m_open();
//     };

// public:
//     /**
//      * @brief Construct a new Rotating File Output object
//      *
//      * @param filepath file to write the events
//      * @param sizelimit limit in bytes to write to the file
//      */
//     RotatingFileOutput(std::string filepath, std::uintmax_t sizelimit)
//         : FileOutput<E>{filepath}, m_sizeLimit(sizelimit){};
//     RotatingFileOutput(std::string filepath) : FileOutput<E>{filepath}
//     {
//         this->m_pos = std::filesystem::file_size(this->m_os);
//     };

//     auto subscriber()
//     {
//         if (!this->m_isWritting)
//         {
//             this->m_obs.subscribe(
//                 [&](E v)
//                 {
//                     auto buff = v.str();
//                     this->m_os << buff << std::endl;
//                     this->m_pos = this->m_pos + buff.length();
//                     if (this->m_pos >= this->m_sizeLimit)
//                     {
//                         this->move();
//                     }
//                 },
//                 [&]() { this->m_os.close(); });
//         }
//         this->m_isWritting = true;
//         return this->m_subj.get_subscriber();
//     }
// };

} // namespace builder::internals::outputs

#endif // _FILE_OUTPUT_H
