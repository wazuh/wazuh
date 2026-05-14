/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 6, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _JSON_ARRAY_PARSER_HPP
#define _JSON_ARRAY_PARSER_HPP

#include "json.hpp"
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>

namespace JsonArray
{

    /**
     * @brief SAX interface implementation to parse JSON arrays without having to load the whole file in memory.
     * @details This class implements a SAX interface (https://json.nlohmann.me/api/json_sax/) that invokes a
     * callback for each item of the target array.
     * This implementation is a modified version of the nlohmann's json_sax_dom_parser.
     * Original implementation can be found at:
     * https://github.com/nlohmann/json/blob/edffad036d5a93ab5a10f72a7d835eeb0d2948f9/single_include/nlohmann/json.hpp#L6733
     */
    class JsonSaxArrayParser
    {
    public:
        /// Alias for integer type
        using NumberIntegerT = typename nlohmann::json::number_integer_t;
        /// Alias for unsigned type
        using NumberUnsignedT = typename nlohmann::json::number_unsigned_t;
        /// Alias for float type
        using NumberFloatT = typename nlohmann::json::number_float_t;
        /// Alias for string type
        using StringT = typename nlohmann::json::string_t;
        /// Alias for binary type
        using BinaryT = typename nlohmann::json::binary_t;

        /**
         * @brief Construct a new Json Sax Array Parser object
         *
         * @param targetArrayPointer JSON Pointer to the target array.
         * @param itemCallback Callback invoked for every item found on the target array. If the callback returns false
         * the parsing stops, the second parameter is the quantity of items parsed.
         * @param bodyCallback Callback invoked at the end of the parsing with the body of the JSON object. The body of
         * the JSON object is the original JSON with the array items removed.
         */
        JsonSaxArrayParser(
            nlohmann::json::json_pointer targetArrayPointer,
            std::function<bool(nlohmann::json&&, const size_t)> itemCallback,
            std::function<void(nlohmann::json&&)> bodyCallback = [](nlohmann::json&&) {})
            : m_targetArrayPointer(std::move(targetArrayPointer))
            , m_itemCallback(std::move(itemCallback))
            , m_bodyCallback(std::move(bodyCallback))
            , m_refStackPtr(&m_bodyRefStack)
        {
        }

        /// @cond make class move-only
        JsonSaxArrayParser(const JsonSaxArrayParser&) = delete;
        JsonSaxArrayParser(JsonSaxArrayParser&&) = default;
        JsonSaxArrayParser& operator=(const JsonSaxArrayParser&) = delete;
        JsonSaxArrayParser& operator=(JsonSaxArrayParser&&) = default;
        ~JsonSaxArrayParser() = default;
        /// @endcond

        /**
         * @brief Processes a null value.
         *
         * @return true Continue parsing.
         * @return false Stop parsing.
         */
        // cppcheck-suppress unusedFunction
        bool null()
        {
            handleValue(nullptr);
            return m_continueParsing;
        }

        /**
         * @brief Processes a boolean value
         *
         * @param val boolean value
         * @return true Continue parsing.
         * @return false Stop parsing.
         */
        // cppcheck-suppress unusedFunction
        bool boolean(bool val)
        {
            handleValue(val);
            return m_continueParsing;
        }

        /**
         * @brief Processes an integer number
         *
         * @param val integer value
         * @return true Continue parsing.
         * @return false Stop parsing.
         */
        // cppcheck-suppress unusedFunction
        bool number_integer(NumberIntegerT val) // NOLINT
        {
            handleValue(val);
            return m_continueParsing;
        }

        /**
         * @brief Processes a unsigned integer number
         *
         * @param val unsigned integer value
         * @return true Continue parsing.
         * @return false Stop parsing.
         */
        // cppcheck-suppress unusedFunction
        bool number_unsigned(NumberUnsignedT val) // NOLINT
        {
            handleValue(val);
            return m_continueParsing;
        }

        /**
         * @brief Processes a floating-point number.
         *
         * @param val floating-point value
         * @param s string representation of the original input
         * @return true Continue parsing.
         * @return false Stop parsing.
         */
        // cppcheck-suppress unusedFunction
        bool number_float(NumberFloatT val, [[maybe_unused]] const StringT& s) // NOLINT
        {
            handleValue(val);
            return m_continueParsing;
        }

        /**
         * @brief Processes a string value.
         *
         * @param val String value
         * @return true Continue parsing.
         * @return false Stop parsing.
         */
        // cppcheck-suppress unusedFunction
        bool string(const StringT& val)
        {
            handleValue(val);
            return m_continueParsing;
        }

        /**
         * @brief Processes a binary value.
         *
         * @param val Binary value
         * @return true Continue parsing.
         * @return false Stop parsing.
         */
        // LCOV_EXCL_START
        // cppcheck-suppress unusedFunction
        bool binary(BinaryT& val)
        {
            handleValue(std::move(val));
            return m_continueParsing;
        }
        // LCOV_EXCL_STOP

        /**
         * @brief Processes an object key.
         *
         * @param val Object key.
         * @return true Continue parsing.
         * @return false Stop parsing.
         */
        // cppcheck-suppress unusedFunction
        bool key(const StringT& val)
        {
            auto& object = m_refStackPtr->back();

            // add null at given key and store the reference for later
            m_objectElement = &(*object)[val];
            return true;
        }

        /**
         * @brief Processes the beginning of an object.
         *
         * @param len number of object elements or -1 if unknown
         * @return true Continue parsing.
         * @return false Stop parsing.
         */
        // cppcheck-suppress unusedFunction
        bool start_object(std::size_t len) // NOLINT
        {
            m_refStackPtr->push_back(handleValue(nlohmann::json::value_t::object));
            if (len != static_cast<std::size_t>(-1) && len > m_refStackPtr->back()->max_size())
            {
                // LCOV_EXCL_START
                throw std::runtime_error("Excessive object size. Number of elements: " + std::to_string(len));
                // LCOV_EXCL_STOP
            }

            return true;
        }

        /**
         * @brief Processes a the end of an object.
         *
         * @return true Continue parsing.
         * @return false Stop parsing.
         */
        // cppcheck-suppress unusedFunction
        bool end_object() // NOLINT
        {
            m_refStackPtr->pop_back();

            if (m_refStackPtr->empty())
            {
                if (m_inTargetArray)
                {
                    // This item is complete. Invoke the item callback.
                    m_continueParsing = m_itemCallback(std::move(m_item), ++m_itemId);
                }
                else
                {
                    // This is the end of the file
                    // If the target array was not found throw exception
                    if (!m_targetArrayExists)
                    {
                        throw std::runtime_error {"The target array does not exist."};
                    }
                    // Return the body
                    m_bodyCallback(std::move(m_body));
                }
            }
            return m_continueParsing;
        }

        /**
         * @brief Processes the beginning of an array
         *
         * @param len number of object elements or -1 if unknown
         * @return true Continue parsing.
         * @return false Stop parsing.
         */
        // cppcheck-suppress unusedFunction
        bool start_array(std::size_t len) // NOLINT
        {
            m_refStackPtr->push_back(handleValue(nlohmann::json::value_t::array));

            if (len != static_cast<std::size_t>(-1) && len > m_refStackPtr->back()->max_size())
            {
                // LCOV_EXCL_START
                throw std::runtime_error("Excessive array size. Number of elements: " + std::to_string(len));
                // LCOV_EXCL_STOP
            }

            if (!m_inTargetArray && m_body.contains(m_targetArrayPointer))
            {
                if (m_refStackPtr->back() == &m_body.at(m_targetArrayPointer))
                {
                    // This is the start of the target array
                    m_inTargetArray = true;
                    m_targetArrayExists = true;

                    // Point the stack to the item stack
                    m_refStackPtr = &m_itemRefStack;
                }
            }

            return true;
        }

        /**
         * @brief Processes the end of an array
         *
         * @return true Continue parsing.
         * @return false Stop parsing.
         */
        // cppcheck-suppress unusedFunction
        bool end_array() // NOLINT
        {
            if (m_inTargetArray)
            {
                if (m_refStackPtr->empty())
                {
                    // This is the end of the target array
                    m_inTargetArray = false;

                    // Point the stack back to the body stack
                    m_refStackPtr = &m_bodyRefStack;
                }
                else if (m_refStackPtr->size() == 1)
                {
                    // This is the end of an array item of the target array
                    // This item is complete. Invoke the item callback.
                    m_continueParsing = m_itemCallback(std::move(m_item), ++m_itemId);
                }
                m_refStackPtr->pop_back();
            }
            else
            {
                m_refStackPtr->pop_back();
                if (m_refStackPtr->empty())
                {
                    // This is the end of the file
                    // If the target array was not found throw exception
                    if (!m_targetArrayExists)
                    {
                        throw std::runtime_error {"The target array does not exist."};
                    }
                    // Return the body
                    m_bodyCallback(std::move(m_body));
                }
            }

            return m_continueParsing;
        }

        /**
         * @brief Processes a parse error. Throws the received exception object.
         *
         * @tparam Exception
         */
        template<class Exception>
        bool parse_error(std::size_t /*unused*/, const std::string& /*unused*/, const Exception& ex) // NOLINT
        {
            throw ex;
        }

    private:
        /**
         * @brief Handle the received value
         *
         * @tparam Value
         * @param value Received value
         * @return nlohmann::json* Pointer to the processed element.
         */
        template<typename Value>
        nlohmann::json* handleValue(Value&& value)
        {
            if (m_refStackPtr->empty())
            {
                if (m_inTargetArray)
                {
                    // This is the start of an item of the target array
                    m_item = nlohmann::json(std::forward<Value>(value));

                    if (!m_item.is_object() && !m_item.is_array())
                    {
                        // The item is a single value (Not an object or an array)
                        m_continueParsing = m_itemCallback(std::move(m_item), ++m_itemId);
                    }
                    return &m_item;
                }
                else
                {
                    // This is the start of the JSON object body
                    m_body = nlohmann::json(std::forward<Value>(value));
                    return &m_body;
                }
            }

            if (m_refStackPtr->back()->is_array())
            {
                // We are parsing an array, so insert this value
                m_refStackPtr->back()->emplace_back(std::forward<Value>(value));

                return &(m_refStackPtr->back()->back());
            }

            // Insert this value in the previously created key
            *m_objectElement = nlohmann::json(std::forward<Value>(value));
            return m_objectElement;
        }

        /// Current array item
        nlohmann::json m_item;

        /// JSON body
        nlohmann::json m_body;

        /// Track whether we are currently parsing the target array.
        bool m_inTargetArray {false};

        /// Track whether the target array was found on the parsed object.
        bool m_targetArrayExists {false};

        /// Flag to stop parsing when the item callback orders so.
        bool m_continueParsing {true};

        /// JSON Pointer to the target array
        nlohmann::json::json_pointer m_targetArrayPointer;

        /// Callback for each parsed item on the target array
        std::function<bool(nlohmann::json&&, const size_t)> m_itemCallback;

        /// Callback for the object body at the end of the parsing
        std::function<void(nlohmann::json&&)> m_bodyCallback;

        /// Stack to model hierarchy of body values
        std::vector<nlohmann::json*> m_bodyRefStack {};

        /// Stack to model hierarchy of item values
        std::vector<nlohmann::json*> m_itemRefStack {};

        /// Pointer to the current stack: either the item values stack or the body values stack
        std::vector<nlohmann::json*>* m_refStackPtr {};

        /// Helper to hold the reference for the next object element
        nlohmann::json* m_objectElement = nullptr;

        /// Item id counter
        size_t m_itemId {0};
    };

    /**
     * @brief Parses a JSON file and invokes a callback for each item of the target array.
     *
     * @param filepath Path to the JSON file.
     * @param processItemCallback Callback invoked for every item found on the target array. If the callback returns
     * false the parsing stops.
     * @param arrayPointer JSON Pointer to the target array.
     * @param processBodyCallback Callback invoked at the end of the parsing with the body of the JSON object. The body
     * of the JSON object is the original JSON with the array items removed. If the \p processItemCallback stops the
     * parsing, the \p processBodyCallback will not be called.
     *
     * This function has [[maybe_unused]] attribute to avoid warnings when the function is not used.
     */
    [[maybe_unused]] static void parse(
        const std::filesystem::path& filepath,
        std::function<bool(nlohmann::json&&, const size_t)> processItemCallback,
        const nlohmann::json::json_pointer& arrayPointer = nlohmann::json::json_pointer(),
        std::function<void(nlohmann::json&&)> processBodyCallback = [](nlohmann::json&&) {})
    {
        // Open the input file
        std::ifstream file(filepath);
        if (!file.is_open())
        {
            throw std::runtime_error("Unable to open input file: " + filepath.string());
        }

        // Create the sax array parser
        JsonSaxArrayParser arrayParser(arrayPointer, std::move(processItemCallback), std::move(processBodyCallback));

        // Parse the file
        nlohmann::json::sax_parse(file, &arrayParser);
    }

} // namespace JsonArray
#endif // _JSON_ARRAY_PARSER_HPP
