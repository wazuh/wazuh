#include "schemaValidator.hpp"
#include "schemaResources.hpp"
#include <sstream>
#include <map>
#include <regex>
#include <ctime>
#include <iomanip>
#include <algorithm>
#include <cctype>

// Network headers for inet_pton
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

namespace SchemaValidator
{

    // Helper function to check if a string is a valid ISO8601 date
    static bool isValidISO8601Date(const std::string& dateStr)
    {
        // Basic ISO8601 format check: YYYY-MM-DDTHH:MM:SS.sssZ or similar
        // Also accepts formats like: YYYY-MM-DD, YYYY-MM-DDTHH:MM:SS, etc.
        // Use static const to compile regex only once
        static const std::regex iso8601Pattern(
            R"(^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})?)?$)");
        return std::regex_match(dateStr, iso8601Pattern);
    }

    // Helper function to check if a string is a valid IP address
    // Uses inet_pton following the same pattern as windowsHelper.h
    // This aligns with OpenSearch which uses InetAddress (native API validation)
    static bool isValidIP(const std::string& ipStr)
    {
        struct in_addr addr4;
        struct in6_addr addr6;

#ifdef _WIN32
        // Windows: Use GetProcAddress pattern (same as windowsHelper.h)
        typedef INT (WINAPI * inet_pton_t)(INT, PCSTR, PVOID);
        static inet_pton_t pfnInetPton = nullptr;
        static bool initialized = false;

        if (!initialized)
        {
            auto hWs2_32 = GetModuleHandleA("ws2_32.dll");
            if (hWs2_32)
            {
                pfnInetPton = reinterpret_cast<inet_pton_t>(GetProcAddress(hWs2_32, "inet_pton"));
            }
            initialized = true;
        }

        if (!pfnInetPton)
        {
            // inet_pton not available (e.g., wine environment)
            return false;
        }

        // Try IPv4 first
        if (pfnInetPton(AF_INET, ipStr.c_str(), &addr4) == 1)
        {
            return true;
        }

        // Try IPv6
        if (pfnInetPton(AF_INET6, ipStr.c_str(), &addr6) == 1)
        {
            return true;
        }

        return false;
#else
        // Linux/Unix: Use inet_pton directly
        if (inet_pton(AF_INET, ipStr.c_str(), &addr4) == 1)
        {
            return true;
        }

        if (inet_pton(AF_INET6, ipStr.c_str(), &addr6) == 1)
        {
            return true;
        }

        return false;
#endif
    }

    // Implementation class for SchemaValidatorEngine
    class SchemaValidatorEngine::Impl
    {
        public:
            nlohmann::json m_schema;
            nlohmann::json m_properties;
            bool m_strictMode;
            std::string m_schemaName;

            Impl()
                : m_strictMode(false)
            {
            }

            bool loadSchemaFromString(const std::string& schemaContent)
            {
                try
                {
                    m_schema = nlohmann::json::parse(schemaContent);
                    return parseAndInitializeSchema();
                }
                catch (const std::exception& e)
                {
                    return false;
                }
            }

        private:
            bool parseAndInitializeSchema()
            {
                // Extract properties from Elasticsearch mapping
                if (m_schema.contains("template") && m_schema["template"].contains("mappings") &&
                        m_schema["template"]["mappings"].contains("properties"))
                {
                    m_properties = m_schema["template"]["mappings"]["properties"];
                }
                else
                {
                    return false;
                }

                // Check for strict mode
                if (m_schema["template"]["mappings"].contains("dynamic"))
                {
                    std::string dynamicMode = m_schema["template"]["mappings"]["dynamic"].get<std::string>();
                    m_strictMode = (dynamicMode == "strict");
                }

                // Extract schema name from index_patterns
                if (m_schema.contains("index_patterns") && m_schema["index_patterns"].is_array() &&
                        !m_schema["index_patterns"].empty())
                {
                    std::string pattern = m_schema["index_patterns"][0].get<std::string>();
                    // Remove wildcard suffix if present
                    size_t starPos = pattern.find('*');

                    if (starPos != std::string::npos)
                    {
                        m_schemaName = pattern.substr(0, starPos);
                    }
                    else
                    {
                        m_schemaName = pattern;
                    }
                }

                return true;
            }

        public:

            ValidationResult validate(const nlohmann::json& message)
            {
                ValidationResult result;

                // Validate against properties
                validateObject(message, m_properties, "", result);

                result.isValid = result.errors.empty();
                return result;
            }

        private:
            void validateObject(const nlohmann::json& obj,
                                const nlohmann::json& properties,
                                const std::string& path,
                                ValidationResult& result)
            {
                if (!obj.is_object())
                {
                    result.errors.push_back(path + ": Expected object, got " + std::string(obj.type_name()) +
                                            " with value: " + obj.dump());
                    return;
                }

                // Check for extra fields in strict mode
                // OpenSearch accepts extra fields in strict mode ONLY if their value is null
                if (m_strictMode)
                {
                    for (auto it = obj.begin(); it != obj.end(); ++it)
                    {
                        if (!properties.contains(it.key()))
                        {
                            // OpenSearch allows undefined fields if their value is null
                            // (null values don't need mapping as they're not indexed)
                            if (!it.value().is_null())
                            {
                                std::string fieldPath = path.empty() ? it.key() : path + "." + it.key();
                                result.errors.push_back(fieldPath + ": Field not allowed in strict mode");
                            }
                        }
                    }
                }

                // Validate each property
                for (auto it = properties.begin(); it != properties.end(); ++it)
                {
                    std::string fieldName = it.key();
                    std::string fieldPath = path.empty() ? fieldName : path + "." + fieldName;
                    const nlohmann::json& fieldSchema = it.value();

                    // Skip validation if field is not present in message (fields are optional by default)
                    if (!obj.contains(fieldName))
                    {
                        continue;
                    }

                    const nlohmann::json& fieldValue = obj[fieldName];

                    // Handle nested objects
                    if (fieldSchema.contains("properties"))
                    {
                        // OpenSearch allows null values for any field, including nested objects
                        if (fieldValue.is_null())
                        {
                            continue;
                        }

                        if (!fieldValue.is_object())
                        {
                            result.errors.push_back(fieldPath + ": Expected object, got " +
                                                    std::string(fieldValue.type_name()) + " with value: " + fieldValue.dump());
                            continue;
                        }

                        validateObject(fieldValue, fieldSchema["properties"], fieldPath, result);
                    }
                    else if (fieldSchema.contains("type"))
                    {
                        std::string type = fieldSchema["type"].get<std::string>();
                        validateField(fieldValue, type, fieldPath, result);
                    }
                }
            }

            void validateField(const nlohmann::json& value,
                               const std::string& type,
                               const std::string& path,
                               ValidationResult& result)
            {
                // Allow null values for any field
                if (value.is_null())
                {
                    return;
                }

                // Arrays use the type of their elements
                if (value.is_array())
                {
                    // Validate each element of the array against the expected type
                    for (size_t i = 0; i < value.size(); ++i)
                    {
                        std::string elementPath = path + "[" + std::to_string(i) + "]";
                        validateField(value[i], type, elementPath, result);
                    }

                    return;
                }

                // Strict validation: only accept exact type or null
                if (type == "keyword" || type == "text" || type == "match_only_text")
                {
                    if (!value.is_string())
                    {
                        result.errors.push_back(path + ": Expected string, got " +
                                                std::string(value.type_name()) + " with value: " + value.dump());
                    }
                }
                else if (type == "integer" || type == "long" || type == "short" || type == "unsigned_long")
                {
                    if (!value.is_number_integer())
                    {
                        result.errors.push_back(path + ": Expected integer, got " +
                                                std::string(value.type_name()) + " with value: " + value.dump());
                    }
                }
                else if (type == "scaled_float")
                {
                    if (!value.is_number())
                    {
                        result.errors.push_back(path + ": Expected number, got " +
                                                std::string(value.type_name()) + " with value: " + value.dump());
                    }
                }
                else if (type == "date")
                {
                    // Date can be number (epoch) or ISO8601 string
                    if (value.is_number())
                    {
                        // Accept epoch timestamp
                    }
                    else if (value.is_string())
                    {
                        std::string dateStr = value.get<std::string>();

                        if (!isValidISO8601Date(dateStr))
                        {
                            result.errors.push_back(path + ": Invalid date format. Expected ISO8601, got: " + dateStr);
                        }
                    }
                    else
                    {
                        result.errors.push_back(path + ": Expected date (number or ISO8601 string), got " +
                                                std::string(value.type_name()) + " with value: " + value.dump());
                    }
                }
                else if (type == "ip")
                {
                    if (!value.is_string())
                    {
                        result.errors.push_back(path + ": Expected IP address string, got " +
                                                std::string(value.type_name()) + " with value: " + value.dump());
                    }
                    else
                    {
                        std::string ipStr = value.get<std::string>();

                        if (!isValidIP(ipStr))
                        {
                            result.errors.push_back(path + ": Invalid IP address format: " + ipStr);
                        }
                    }
                }
                else if (type == "boolean")
                {
                    if (!value.is_boolean())
                    {
                        result.errors.push_back(path + ": Expected boolean, got " +
                                                std::string(value.type_name()) + " with value: " + value.dump());
                    }
                }
                else if (type == "object")
                {
                    if (!value.is_object())
                    {
                        result.errors.push_back(path + ": Expected object, got " +
                                                std::string(value.type_name()) + " with value: " + value.dump());
                    }
                }
            }
    };

    // SchemaValidatorEngine implementation
    SchemaValidatorEngine::SchemaValidatorEngine()
        : m_impl(std::make_unique<Impl>())
    {
    }

    SchemaValidatorEngine::~SchemaValidatorEngine() = default;

    bool SchemaValidatorEngine::loadSchemaFromString(const std::string& schemaContent)
    {
        return m_impl->loadSchemaFromString(schemaContent);
    }

    ValidationResult SchemaValidatorEngine::validate(const std::string& message)
    {
        try
        {
            nlohmann::json jsonMessage = nlohmann::json::parse(message);
            return m_impl->validate(jsonMessage);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            ValidationResult result;
            result.isValid = false;
            result.errors.push_back("JSON parse error: " + std::string(e.what()));
            return result;
        }
    }

    ValidationResult SchemaValidatorEngine::validate(const nlohmann::json& message)
    {
        return m_impl->validate(message);
    }

    std::string SchemaValidatorEngine::getSchemaName() const
    {
        return m_impl->m_schemaName;
    }

    // SchemaValidatorFactory implementation
    class SchemaValidatorFactory::Impl
    {
        public:
            std::map<std::string, std::shared_ptr<ISchemaValidatorEngine>> m_validators;
            bool m_initialized;

            Impl()
                : m_initialized(false)
            {
            }

            bool loadSchemaFromString(const std::string& schemaContent)
            {
                try
                {
                    auto validator = std::make_shared<SchemaValidatorEngine>();

                    // Load schema from string using public method
                    if (validator->loadSchemaFromString(schemaContent))
                    {
                        std::string schemaName = validator->getSchemaName();

                        if (!schemaName.empty())
                        {
                            m_validators[schemaName] = validator;
                            return true;
                        }
                    }

                    return false;
                }
                catch (const std::exception& e)
                {
                    return false;
                }
            }

            bool initializeFromEmbeddedResources()
            {
                try
                {
                    const auto& embeddedSchemas = Resources::getEmbeddedSchemas();

                    for (const auto& [_, content] : embeddedSchemas)
                    {
                        loadSchemaFromString(content);
                    }

                    m_initialized = !m_validators.empty();
                    return m_initialized;
                }
                catch (const std::exception& e)
                {
                    return false;
                }
            }

            bool initialize(std::map<std::string, std::shared_ptr<ISchemaValidatorEngine>> customValidators)
            {
                if (!customValidators.empty())
                {
                    // Use injected custom validators (for testing or extensibility)
                    m_validators = std::move(customValidators);
                    m_initialized = true;
                    return true;
                }

                // Default behavior: load from embedded resources
                return initializeFromEmbeddedResources();
            }

            std::shared_ptr<ISchemaValidatorEngine> getValidator(const std::string& indexPattern)
            {
                auto it = m_validators.find(indexPattern);

                if (it != m_validators.end())
                {
                    return it->second;
                }

                return nullptr;
            }
    };

    SchemaValidatorFactory::SchemaValidatorFactory()
        : m_impl(std::make_unique<Impl>())
    {
    }

    SchemaValidatorFactory::~SchemaValidatorFactory() = default;

    SchemaValidatorFactory& SchemaValidatorFactory::getInstance()
    {
        static SchemaValidatorFactory instance;
        return instance;
    }

    bool SchemaValidatorFactory::initialize(std::map<std::string, std::shared_ptr<ISchemaValidatorEngine>> customValidators)
    {
        return m_impl->initialize(std::move(customValidators));
    }

    std::shared_ptr<ISchemaValidatorEngine> SchemaValidatorFactory::getValidator(const std::string& indexPattern)
    {
        return m_impl->getValidator(indexPattern);
    }

    bool SchemaValidatorFactory::isInitialized() const
    {
        return m_impl->m_initialized;
    }

    void SchemaValidatorFactory::reset()
    {
        m_impl->m_validators.clear();
        m_impl->m_initialized = false;
    }

} // namespace SchemaValidator
