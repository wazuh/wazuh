#include <string>
#include <filesystem>
#include <fstream>
#include <iostream>
#include "rxcpp/rx.hpp"

namespace outputs
{

    /**
     * @brief implements a subscriber which will save all received events
     * of type E into a file.
     *
     * @tparam E
     */
    template <class E>
    class FileOutput
    {
        using obs_t = rxcpp::observable<E>;
        using subj_t = rxcpp::subjects::subject<E>;

    protected:
        subj_t m_subj;
        obs_t m_obs;

        std::filesystem::path m_filepath;
        std::ofstream m_os;
        bool m_isWritting{false};

        void m_open()
        {
            this->m_os.open(this->m_filepath, std::ios::out | std::ios::app | std::ios::binary);

            if (!this->m_os)
            {
                throw std::runtime_error("fileOutput cannot open file " + this->m_name);
            }
        };

    public:
        std::string m_name;

        /**
         * @brief Construct a new File Output object
         *
         * @param filepath file to store the events received
         */
        FileOutput(std::string filepath) : m_name{filepath}, m_filepath{filepath}
        {
            this->m_open();
            this->m_obs = this->m_subj.get_observable();
        };

        ~FileOutput(){

        };

        auto observable()
        {
            throw std::runtime_error(
                "fileOutputs are not connectables, they don't have observable because they do not accept connections.");
        }

        auto subscriber()
        {
            if (!this->m_isWritting)
            {
                this->m_obs.subscribe([&](E v)
                                      { this->m_os << v.str() << std::endl; },
                                      [&]()
                                      { this->m_os.close(); });
            }
            this->m_isWritting = true;
            return this->m_subj.get_subscriber();
        }
    };

    /**
     * @brief A buffered file output will store some events and then write them all
     * on a loop.
     *
     * @tparam E
     */
    template <class E>
    class BufferedFileOutput : public FileOutput<E>
    {
    private:
        int m_buffsize;

    public:
        /**
         * @brief Construct a new Buffered File Output object
         *
         * @param filepath file to store events
         * @param buffsize number of events to group before start writting
         */
        BufferedFileOutput(std::string filepath, int buffsize) : FileOutput<E>{filepath}, m_buffsize{buffsize} {};

        auto subscriber()
        {
            if (!this->m_isWritting)
            {
                this->m_obs.buffer(this->m_buffsize)
                    .subscribe(
                        [&](std::vector<E> v)
                        {
                            std::for_each(std::begin(v), std::end(v),
                                          [&](E item)
                                          { this->m_os << item.str() << std::endl; });
                        },
                        [&]()
                        { this->m_os.close(); });
            }
            this->m_isWritting = true;
            return this->m_subj.get_subscriber();
        }
    };

    /**
     * @brief A rotating file output. It will write all events of type E
     * into a file until it exceeds the bytes limit. Then it will rename the current file
     * to file.X where X is a positive number starting from 0, adn continue writting
     * the new events on the mail filename.
     *
     * @tparam E
     */
    template <class E>
    class RotatingFileOutput : public FileOutput<E>
    {
    private:
        int m_fileIndex{0};
        // 2 GB default limit
        std::uintmax_t m_sizeLimit{2 << 30};
        std::uintmax_t m_pos{0};

        auto move()
        {
            this->m_os.close();
            auto newName = std::filesystem::path(this->m_name + "." + std::to_string(this->m_fileIndex));
            this->m_fileIndex += 1;
            std::filesystem::rename(this->m_filepath, newName);
            this->m_pos = 0;
            this->m_open();
        };

    public:
        /**
         * @brief Construct a new Rotating File Output object
         *
         * @param filepath file to write the events
         * @param sizelimit limit in bytes to write to the file
         */
        RotatingFileOutput(std::string filepath, std::uintmax_t sizelimit)
            : FileOutput<E>{filepath}, m_sizeLimit(sizelimit){};
        RotatingFileOutput(std::string filepath) : FileOutput<E>{filepath}
        {
            this->m_pos = std::filesystem::file_size(this->m_os);
        };

        auto subscriber()
        {
            if (!this->m_isWritting)
            {
                this->m_obs.subscribe(
                    [&](E v)
                    {
                        auto buff = v.str();
                        this->m_os << buff << std::endl;
                        this->m_pos = this->m_pos + buff.length();
                        if (this->m_pos >= this->m_sizeLimit)
                        {
                            this->move();
                        }
                    },
                    [&]()
                    { this->m_os.close(); });
            }
            this->m_isWritting = true;
            return this->m_subj.get_subscriber();
        }
    };

} // namespace Outputs
