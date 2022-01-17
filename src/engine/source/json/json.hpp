#include <iostream>
#include <string>
#include <algorithm>
#include <chrono>
#include <thread>

#include "rapidjson/document.h"
#include "rapidjson/pointer.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "rxcpp/rx.hpp"

using Value = rapidjson::Value;


/**
 * @brief Contains Json functionality.
 *
 */
namespace json
{

    /**
     * @brief Document is a json class based on rapidjson library.
     *
     */
    class Document {
    private:
        rapidjson::Document m_doc;

    public:
        Document() {};
        Document(const char * json) 
        {
            m_doc.Parse(json);
        };
        Document(const Document & e) 
        {
            this->m_doc.CopyFrom(e.m_doc, this->m_doc.GetAllocator());
        };
        Document(const rapidjson::Value & v) 
        {
            this->m_doc.CopyFrom(v, this->m_doc.GetAllocator());
        };

        /**
         * @brief Method to set a value in a given json path.
         *
         * @param path json path of the value that will be set.
         * @param v new value that will be set.
         */
        void set(std::string path, const rapidjson::Value & v)
        {
            std::replace(std::begin(path), std::end(path), '.', '/');
            auto ptr = rapidjson::Pointer(path.c_str());
            if (ptr.IsValid())
            {
                ptr.Set(this->m_doc, v);
            }
            else
            {
                throw std::invalid_argument("Invalid json path for this json");
            }
        }

        /**
         * @brief Method that returns a pointer to the value of a given json path.
         *
         * @param path json path of the value that will be returned.
         * 
         * @return rapidjson::Value * Pointer to the value of path.
         */
        rapidjson::Value * get(std::string path)
        {
            std::replace(std::begin(path), std::end(path), '.', '/');
            auto ptr = rapidjson::Pointer(path.c_str());
            if (ptr.IsValid())
            {
                return ptr.Get(this->m_doc);
            }
            throw std::invalid_argument("Invalid json path for this json");
        }

        /**
         * @brief Method to check if the value stored on the given path is equal to the value given as argument.
         *
         * @param path json path of the value that will be compared.
         * @param expected Expected value of the path.
         * 
         * @return boolean True if the value pointed by path is equal to expected. False if its not equal.
         */
        bool check(std::string path, const rapidjson::Value & expected)
        {
            std::replace(std::begin(path), std::end(path), '.', '/');
            auto ptr = rapidjson::Pointer(path.c_str());
            if (ptr.IsValid()) 
            {
                auto got = ptr.Get(this->m_doc);
                if (got)
                {
                    return *got == expected;
                }
            }
            return false;
        }

        /**
         * @brief Method to check if the value stored on the given path exists.
         *
         * @param path json path of the value that will be checked.
         * 
         * @return boolean True if the value pointed by path exists. False if it does not.
         */
        bool check(std::string path)
        {
            std::replace(std::begin(path), std::end(path), '.', '/');
            auto ptr = rapidjson::Pointer(path.c_str());
            return ptr.IsValid();
        }

        /**
         * @brief Method to write a Json object into a string.
         * 
         * @return string Containing the info of the Json object.
         */
        std::string str()
        {
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType,
                            rapidjson::ASCII<>> writer(buffer);
            this->m_doc.Accept(writer);
            return buffer.GetString();
        }

    };

};
